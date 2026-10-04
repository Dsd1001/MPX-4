#!/usr/bin/env python3
"""Authenticated-wire endpoint conformance probes for MPX/4 Draft 11.

These probes target the real Session runtimes used by Gate 2 / Gate 4 fault
execution.  They do not call the Mandatory model.  Every case establishes a
real loopback TCP Carrier, completes CREATE/Finished, sends authenticated
Secure Records, and asserts endpoint state plus wire-visible responses.

The suite is parameterized across:
- implementation: reference / independent
- endpoint role: server / client where the Core rule is role-symmetric

It specifically guards the implementation-review regressions:
- DATA versus established Final Offset
- RESET suppressing application delivery
- component-wise credit merge
- FINAL_SIZE_ERROR Session contract
- Carrier-vs-Session error scope

It also covers closely related Group-L receiver semantics so the Gate report
can distinguish model/codec evidence from endpoint-wire evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]

IMPLEMENTATIONS = ("reference", "independent")
ROLES = ("server", "client")

ERROR_PROTOCOL_VIOLATION = 0x02
ERROR_AUTHENTICATION_FAILED = 0x03
ERROR_STREAM_LIMIT = 0x08
ERROR_FLOW_CONTROL = 0x09
ERROR_FRAME_ENCODING = 0x0A
ERROR_STREAM_STATE = 0x0E
ERROR_FINAL_SIZE = 0x0F
ERROR_TRANSMISSION_ID = 0x10


class ProbeError(RuntimeError):
    pass


def check(cond: bool, message: object) -> None:
    if not cond:
        raise ProbeError(str(message))


class MemoryTrace:
    def __init__(self, role: str) -> None:
        self.role = role
        self.seq = 0
        self.events: List[dict] = []

    def emit(self, event: str, **fields: object) -> None:
        self.seq += 1
        self.events.append(
            {
                "event_seq": self.seq,
                "role": self.role,
                "event": event,
                **fields,
            }
        )


class NullTrace:
    def emit(self, *args, **kwargs) -> None:
        return None


@dataclass
class Peer:
    core: object
    carrier: object
    backlog: List[Tuple[int, Dict[str, object]]]

    async def recv_until(self, frame_type: int, timeout: float = 2.0) -> Dict[str, object]:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            for idx, (ft, fields) in enumerate(self.backlog):
                if ft == frame_type:
                    self.backlog.pop(idx)
                    return fields
            remain = deadline - asyncio.get_running_loop().time()
            if remain <= 0:
                raise TimeoutError(f"Frame 0x{frame_type:x} not received")
            frames = await asyncio.wait_for(self.carrier.recv_record(), timeout=remain)
            self.backlog.extend(frames)

    async def expect_no(self, frame_type: int, timeout: float = 0.30) -> None:
        for ft, _ in self.backlog:
            if ft == frame_type:
                raise ProbeError(f"unexpected Frame 0x{frame_type:x} already queued")
        try:
            deadline = asyncio.get_running_loop().time() + timeout
            while True:
                remain = deadline - asyncio.get_running_loop().time()
                if remain <= 0:
                    return
                frames = await asyncio.wait_for(self.carrier.recv_record(), timeout=remain)
                for ft, fields in frames:
                    if ft == frame_type:
                        raise ProbeError(f"unexpected Frame 0x{frame_type:x}: {fields}")
                    self.backlog.append((ft, fields))
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            return

    async def send_raw_plaintext(
        self,
        plaintext: bytes,
        *,
        flags: int = 0,
        corrupt_tag: bool = False,
    ) -> None:
        core = self.core
        seq = self.carrier.send_seq
        header = bytes((flags,)) + core.vi_enc(len(plaintext))
        sealed = AESGCM(self.carrier.send_key).encrypt(
            core.xor_nonce(self.carrier.send_iv, seq),
            plaintext,
            header,
        )
        if corrupt_tag:
            sealed = sealed[:-1] + bytes((sealed[-1] ^ 1,))
        self.carrier.writer.write(header + sealed)
        await self.carrier.writer.drain()
        self.carrier.send_seq += 1


def modules(name: str):
    if name == "reference":
        return (
            importlib.import_module("reference.mpx4_core"),
            importlib.import_module("reference.gate2_runtime"),
        )
    if name == "independent":
        return (
            importlib.import_module("independent.core"),
            importlib.import_module("independent.gate_runtime"),
        )
    raise ProbeError(name)


async def wait_until(predicate, timeout: float = 2.0, label: str = "condition") -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(label)
        await asyncio.sleep(0.01)


class Fixture:
    def __init__(
        self,
        implementation: str,
        endpoint_role: str,
        *,
        max_streams: int = 32,
    ) -> None:
        self.implementation = implementation
        self.endpoint_role = endpoint_role
        self.core, self.runtime = modules(implementation)
        self.key = secrets.token_bytes(32)
        self.limits = self.core.Limits(
            max_frame_payload=32768,
            max_record_size=65536,
            max_streams=max_streams,
            max_carriers=4,
        )
        self.trace = MemoryTrace(f"{implementation}-{endpoint_role}")
        session_cls = (
            self.runtime.Gate2Session
            if implementation == "reference"
            else self.runtime.IndependentSession
        )
        self.session = session_cls(
            role=endpoint_role,
            trace=self.trace,
            scenario="endpoint-wire-conformance",
            local_limits=self.limits,
            write_chunk=0,
        )
        self.server: Optional[asyncio.AbstractServer] = None
        self.port: Optional[int] = None
        self.session_id = secrets.token_bytes(16)
        while self.session_id == b"\x00" * 16:
            self.session_id = secrets.token_bytes(16)
        self.peer_queue: asyncio.Queue[Tuple[int, object]] = asyncio.Queue()
        self.connection_tasks: set[asyncio.Task] = set()
        self.peers: Dict[int, Peer] = {}
        self.peer_next_txid: Dict[int, int] = {}

    async def __aenter__(self) -> "Fixture":
        if self.endpoint_role == "server":
            self.server = await asyncio.start_server(
                self._endpoint_server_callback,
                "127.0.0.1",
                0,
            )
        else:
            self.session.session_id = self.session_id
            self.session.set_state("CREATING")
            self.server = await asyncio.start_server(
                self._peer_server_callback,
                "127.0.0.1",
                0,
            )
        sockets = self.server.sockets or []
        check(sockets, "listener has no socket")
        self.port = int(sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.server is not None:
            self.server.close()
            await asyncio.sleep(0)
        for task in list(self.connection_tasks):
            if not task.done():
                task.cancel()
        if self.connection_tasks:
            await asyncio.gather(*self.connection_tasks, return_exceptions=True)
        try:
            await self.session.cleanup()
        except Exception:
            pass
        for peer in list(self.peers.values()):
            try:
                peer.carrier.writer.close()
            except Exception:
                pass

    def _track(self, coro) -> None:
        task = asyncio.create_task(coro)
        self.connection_tasks.add(task)
        task.add_done_callback(self.connection_tasks.discard)

    def _endpoint_server_callback(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._track(self._endpoint_server_worker(reader, writer))

    async def _endpoint_server_worker(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await self.runtime.server_handshake(
                self.session,
                reader,
                writer,
                self.key,
            )
        except self.runtime.CandidateReject:
            writer.close()
            await asyncio.sleep(0)
        except Exception as exc:
            self.trace.emit(
                "probe_server_handshake_error",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            writer.close()
            await asyncio.sleep(0)

    def _peer_server_callback(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._track(self._peer_server_worker(reader, writer))

    async def _peer_server_worker(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        core = self.core
        try:
            magic = await reader.readexactly(4)
            check(magic == core.MAGIC, "peer server magic")
            version, version_raw = await core.read_varint(reader)
            check(version == core.VERSION, "peer server version")
            preface = magic + version_raw

            msg, _, client_init = await core.read_message(reader)
            check(msg == core.MSG_CLIENT_INIT, "peer server CLIENT_INIT")
            init = core.parse_client_init(client_init)

            server_init = core.encode_server_init(secrets.token_bytes(32), self.limits)
            writer.write(server_init)
            await writer.drain()

            expected_cf, expected_sf, h0, prelim = core.derive_traffic(
                self.key,
                preface,
                client_init,
                server_init,
            )
            msg, _, client_finished = await core.read_message(reader)
            check(msg == core.MSG_CLIENT_FINISHED, "peer server CLIENT_FINISHED")
            core.validate_finished(
                client_finished,
                core.MSG_CLIENT_FINISHED,
                prelim.client_finished_key,
                h0,
            )
            check(client_finished == expected_cf, "peer server canonical CLIENT_FINISHED")
            _, server_finished, _, traffic = core.derive_traffic(
                self.key,
                preface,
                client_init,
                server_init,
                client_finished=client_finished,
            )
            check(server_finished == expected_sf, "peer server SERVER_FINISHED")
            writer.write(server_finished)
            await writer.drain()

            carrier = core.Carrier(
                role="server",
                reader=reader,
                writer=writer,
                trace=NullTrace(),
                local_limits=self.limits,
                peer_limits=init.client_limits,
                send_key=traffic.server_key,
                send_iv=traffic.server_iv,
                recv_key=traffic.client_key,
                recv_iv=traffic.client_iv,
                session_id=init.session_id,
                carrier_id=init.carrier_id,
                generation=init.generation,
                write_chunk=0,
            )
            await self.peer_queue.put((init.carrier_id, carrier))
        except Exception as exc:
            self.trace.emit(
                "probe_peer_server_error",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            writer.close()
            await asyncio.sleep(0)

    async def _peer_client_handshake(
        self,
        session_action: int,
        carrier_id: int,
        generation: int,
    ) -> object:
        core = self.core
        assert self.port is not None
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        preface = core.MAGIC + core.vi_enc(core.VERSION)
        client_init = core.encode_client_init(
            self.session_id,
            carrier_id,
            generation,
            secrets.token_bytes(32),
            self.limits,
            session_action,
        )
        writer.write(preface + client_init)
        await writer.drain()
        msg, _, server_init = await core.read_message(reader)
        check(msg == core.MSG_SERVER_INIT, "peer client SERVER_INIT")
        _, server_limits = core.parse_server_init(server_init)
        client_finished, expected_sf, h0, prelim = core.derive_traffic(
            self.key,
            preface,
            client_init,
            server_init,
        )
        writer.write(client_finished)
        await writer.drain()
        msg, _, server_finished = await core.read_message(reader)
        check(msg == core.MSG_SERVER_FINISHED, "peer client SERVER_FINISHED")
        h1 = hashlib.sha256(
            preface + client_init + server_init + client_finished
        ).digest()
        core.validate_finished(
            server_finished,
            core.MSG_SERVER_FINISHED,
            prelim.server_finished_key,
            h1,
        )
        check(server_finished == expected_sf, "peer client canonical SERVER_FINISHED")
        _, _, _, traffic = core.derive_traffic(
            self.key,
            preface,
            client_init,
            server_init,
            client_finished=client_finished,
            server_finished=server_finished,
        )
        return core.Carrier(
            role="client",
            reader=reader,
            writer=writer,
            trace=NullTrace(),
            local_limits=self.limits,
            peer_limits=server_limits,
            send_key=traffic.client_key,
            send_iv=traffic.client_iv,
            recv_key=traffic.server_key,
            recv_iv=traffic.server_iv,
            session_id=self.session_id,
            carrier_id=carrier_id,
            generation=generation,
            write_chunk=0,
        )

    async def establish(
        self,
        carrier_id: int = 1,
        generation: int = 0,
        action: Optional[int] = None,
    ) -> Peer:
        if action is None:
            action = 0 if not self.peers else 1
        if self.endpoint_role == "server":
            carrier = await self._peer_client_handshake(
                action,
                carrier_id,
                generation,
            )
            peer = Peer(self.core, carrier, [])
            await wait_until(
                lambda: carrier_id in self.session.carriers,
                label=f"endpoint server Carrier {carrier_id}",
            )
        else:
            assert self.port is not None
            endpoint_task = asyncio.create_task(
                self.runtime.client_handshake(
                    self.session,
                    "127.0.0.1",
                    self.port,
                    self.key,
                    action,
                    carrier_id,
                    generation,
                )
            )
            queued_id, carrier = await asyncio.wait_for(self.peer_queue.get(), timeout=2)
            check(queued_id == carrier_id, "peer server Carrier ID")
            await endpoint_task
            peer = Peer(self.core, carrier, [])
        self.peers[carrier_id] = peer
        self.peer_next_txid[carrier_id] = 1 if self.endpoint_role == "client" else 1
        await peer.recv_until(self.core.FRAME_SESSION_CREDIT)
        return peer

    async def expect_rejected_candidate(
        self,
        *,
        action: int,
        carrier_id: int,
        generation: int,
    ) -> None:
        check(self.endpoint_role == "server", "candidate rejection probe targets server admission")
        core = self.core
        assert self.port is not None
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        client_init = core.encode_client_init(
            self.session_id,
            carrier_id,
            generation,
            secrets.token_bytes(32),
            self.limits,
            action,
        )
        writer.write(core.MAGIC + core.vi_enc(core.VERSION) + client_init)
        await writer.drain()
        try:
            await asyncio.wait_for(core.read_message(reader), timeout=0.5)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        else:
            raise ProbeError("rejected candidate unexpectedly received SERVER_INIT")
        writer.close()
        await asyncio.sleep(0)

    def next_peer_tx(self, carrier_id: int) -> int:
        value = self.peer_next_txid[carrier_id]
        self.peer_next_txid[carrier_id] = value + 1
        return value

    async def open_stream(self, peer: Peer, stream_id: int = 1) -> object:
        core = self.core
        cid = peer.carrier.carrier_id
        if self.endpoint_role == "server":
            txid = self.next_peer_tx(cid)
            await peer.carrier.send_frame(
                core.FRAME_STREAM_OPEN,
                stream_id=stream_id,
                transmission_id=txid,
            )
            ok = await peer.recv_until(core.FRAME_STREAM_OPEN_OK)
            check(int(ok["transmission_id"]) == txid, "OPEN_OK txid")
            credit = await peer.recv_until(core.FRAME_STREAM_CREDIT)
            check(int(credit["stream_id"]) == stream_id, "initial stream credit")
        else:
            endpoint_carrier = self.session.carriers[cid]
            task = asyncio.create_task(self.session.open_stream(stream_id, endpoint_carrier))
            opened = await peer.recv_until(core.FRAME_STREAM_OPEN)
            txid = int(opened["transmission_id"])
            check(int(opened["stream_id"]) == stream_id, "endpoint client STREAM_OPEN")
            await peer.carrier.send_frame(
                core.FRAME_STREAM_OPEN_OK,
                stream_id=stream_id,
                transmission_id=txid,
            )
            await peer.carrier.send_frame(
                core.FRAME_STREAM_CREDIT,
                stream_id=stream_id,
                consumed_offset=0,
                maximum_offset=1024 * 1024,
            )
            await asyncio.wait_for(task, timeout=2)
        return self.session.streams[stream_id]

    def session_credit(self) -> Tuple[int, int]:
        if self.implementation == "reference":
            return (
                int(self.session.session_peer_consumed),
                int(self.session.session_peer_maximum),
            )
        pair = self.session.session_peer_credit
        return int(pair.consumed), int(pair.maximum)

    def stream_credit(self, stream_id: int) -> Tuple[int, int]:
        stream = self.session.streams[stream_id]
        if self.implementation == "reference":
            return int(stream.peer_consumed), int(stream.peer_maximum)
        return int(stream.peer_credit.consumed), int(stream.peer_credit.maximum)

    async def ping(self, peer: Peer, token: int = 0xC001) -> None:
        await peer.carrier.send_frame(self.core.FRAME_PING, token=token)
        pong = await peer.recv_until(self.core.FRAME_PONG)
        check(int(pong["token"]) == token, "PONG token")

    async def expect_no_pong(self, peer: Peer, token: int = 0xDEAD) -> None:
        try:
            await peer.carrier.send_frame(self.core.FRAME_PING, token=token)
        except (ConnectionError, BrokenPipeError):
            return
        await peer.expect_no(self.core.FRAME_PONG, timeout=0.30)

    async def expect_session_close(
        self,
        peer: Peer,
        error_code: int,
        trigger_frame_type: int,
    ) -> Dict[str, object]:
        close = await peer.recv_until(self.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == error_code, close)
        check(int(close["trigger_frame_type"]) == trigger_frame_type, close)
        await wait_until(
            lambda: self.session.state in {"CLOSING", "CLOSED"},
            label="Session failure state",
        )
        return close


async def case_normal_data(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    tx = f.next_peer_tx(p.carrier.carrier_id)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"A",
    )
    ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(ack["transmission_id"]) == tx, "normal DATA ACK")
    check(bytes(stream.recv_data) == b"A", "normal DATA delivery")
    check(f.session.state == "ACTIVE", "normal DATA state")
    return {"application_bytes": len(stream.recv_data)}


async def case_fin_fill_hole(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=1,
        transmission_id=tx,
        data=b"B",
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(bytes(stream.recv_data) == b"", "hole delivered early")
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=tx,
        final_offset=2,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"A",
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(bytes(stream.recv_data) == b"AB", "FIN fill-hole delivery")
    check(stream.recv_final == 2 and stream.terminal_mode == "FIN", "FIN state")
    return {"application_bytes": 2, "final_offset": 2}


async def case_reset_late_data(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_RESET_STREAM,
        stream_id=1,
        transmission_id=tx,
        final_offset=1,
        stream_error_code=9,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"X",
    )
    ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(ack["transmission_id"]) == tx, "RESET late DATA ACK")
    check(bytes(stream.recv_data) == b"", "RESET late DATA reached application")
    check(stream.terminal_mode == "RESET", "RESET authority lost")
    check(f.session.state == "ACTIVE", "valid RESET late DATA closed Session")
    return {"application_bytes": 0, "terminal_mode": stream.terminal_mode}


async def case_stale_credit(f: Fixture) -> dict:
    p = await f.establish()
    await p.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=512,
        maximum_bytes=2048,
    )
    await f.ping(p, 0xA1)
    await p.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=768,
        maximum_bytes=4096,
    )
    await f.ping(p, 0xA2)
    await p.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=512,
        maximum_bytes=2048,
    )
    await f.ping(p, 0xA3)
    check(f.session_credit() == (768, 4096), f.session_credit())

    await f.open_stream(p)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=64,
        maximum_offset=2 * 1024 * 1024,
    )
    await f.ping(p, 0xA4)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=128,
        maximum_offset=3 * 1024 * 1024,
    )
    await f.ping(p, 0xA5)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=64,
        maximum_offset=2 * 1024 * 1024,
    )
    await f.ping(p, 0xA6)
    check(f.stream_credit(1) == (128, 3 * 1024 * 1024), f.stream_credit(1))
    return {
        "session_credit": list(f.session_credit()),
        "stream_credit": list(f.stream_credit(1)),
    }


async def case_fin_data_beyond_final(f: Fixture) -> dict:
    p = await f.establish()
    await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=tx,
        final_offset=0,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"X",
    )
    close = await f.expect_session_close(
        p,
        ERROR_FINAL_SIZE,
        f.core.FRAME_STREAM_DATA,
    )
    check(bytes(f.session.streams[1].recv_data) == b"", "invalid DATA delivered")
    return {"close": close}


async def case_crossed_session_credit(f: Fixture) -> dict:
    p = await f.establish()
    await p.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=512,
        maximum_bytes=4096,
    )
    await f.ping(p, 0xB1)
    await p.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=768,
        maximum_bytes=3900,
    )
    close = await f.expect_session_close(
        p,
        ERROR_FLOW_CONTROL,
        f.core.FRAME_SESSION_CREDIT,
    )
    return {"close": close}


async def case_crossed_stream_credit(f: Fixture) -> dict:
    p = await f.establish()
    await f.open_stream(p)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=100,
        maximum_offset=2 * 1024 * 1024,
    )
    await f.ping(p, 0xB2)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=200,
        maximum_offset=1536 * 1024,
    )
    close = await f.expect_session_close(
        p,
        ERROR_FLOW_CONTROL,
        f.core.FRAME_STREAM_CREDIT,
    )
    return {"close": close}


async def case_final_below_commitment(f: Fixture) -> dict:
    p1 = await f.establish(1, 0, 0)
    stream = await f.open_stream(p1)
    cid = p1.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p1.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"X",
    )
    await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(bytes(stream.recv_data) == b"X", "baseline byte")
    p2 = await f.establish(96, 0, 1)
    tx = f.next_peer_tx(cid)
    await p1.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=tx,
        final_offset=0,
    )
    close = await f.expect_session_close(
        p1,
        ERROR_FINAL_SIZE,
        f.core.FRAME_STREAM_FIN,
    )
    await f.expect_no_pong(p2, 0xBEEF)
    return {"close": close, "second_carrier_no_pong": True}


async def case_flow_control_data(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=int(stream.local_maximum),
        transmission_id=tx,
        data=b"X",
    )
    close = await f.expect_session_close(
        p,
        ERROR_FLOW_CONTROL,
        f.core.FRAME_STREAM_DATA,
    )
    return {"close": close}


async def case_session_aggregate_credit(f: Fixture) -> dict:
    p = await f.establish()
    cid = p.carrier.carrier_id
    stream_ids = [1 + 2 * i for i in range(9)]
    streams = []
    for stream_id in stream_ids:
        streams.append(await f.open_stream(p, stream_id))
    for index, (stream_id, stream) in enumerate(zip(stream_ids, streams)):
        tx = f.next_peer_tx(cid)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=stream_id,
            offset=int(stream.local_maximum) - 1,
            transmission_id=tx,
            data=b"X",
        )
        if index < 8:
            await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        else:
            close = await f.expect_session_close(
                p,
                ERROR_FLOW_CONTROL,
                f.core.FRAME_STREAM_DATA,
            )
            check(f.session.session_recv_committed == 8 * 1024 * 1024, f.session.session_recv_committed)
            return {"close": close, "committed_before_failure": f.session.session_recv_committed}
    raise ProbeError("ninth Stream did not exceed Session commitment")


async def case_conflicting_overlap(f: Fixture) -> dict:
    p = await f.establish()
    await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"A",
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"B",
    )
    close = await f.expect_session_close(
        p,
        ERROR_PROTOCOL_VIOLATION,
        f.core.FRAME_STREAM_DATA,
    )
    return {"close": close}


async def case_never_allocated_ack(f: Fixture) -> dict:
    p = await f.establish()
    await p.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=999,
        receiver_timestamp_us=0,
    )
    close = await f.expect_session_close(
        p,
        ERROR_TRANSMISSION_ID,
        f.core.FRAME_TRANSMISSION_ACK,
    )
    return {"close": close}


async def case_unknown_stream_data(f: Fixture) -> dict:
    p = await f.establish()
    tx = f.next_peer_tx(p.carrier.carrier_id)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"X",
    )
    close = await f.expect_session_close(
        p,
        ERROR_STREAM_STATE,
        f.core.FRAME_STREAM_DATA,
    )
    return {"close": close}


async def case_shutdown_blocks_new_work(f: Fixture) -> dict:
    p = await f.establish()
    await p.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=999,
        receiver_timestamp_us=0,
    )
    close = await f.expect_session_close(
        p,
        ERROR_TRANSMISSION_ID,
        f.core.FRAME_TRANSMISSION_ACK,
    )
    if f.endpoint_role == "server":
        before = (dict(f.session.highest_accepted), sorted(f.session.carriers))
        await f.expect_rejected_candidate(action=1, carrier_id=96, generation=0)
        after = (dict(f.session.highest_accepted), sorted(f.session.carriers))
        check(before == after, "closing server admitted/mutated JOIN candidate")
    else:
        try:
            await f.session.open_stream(3, f.session.carriers[1])
        except RuntimeError:
            pass
        else:
            raise ProbeError("closing client created new Stream")
        try:
            await f.runtime.client_handshake(
                f.session,
                "127.0.0.1",
                int(f.port),
                f.key,
                1,
                96,
                0,
            )
        except RuntimeError:
            pass
        else:
            raise ProbeError("closing client originated new Carrier JOIN")
    return {"close": close, "new_work_blocked": True}


async def case_auth_carrier_scope(f: Fixture) -> dict:
    p1 = await f.establish(1, 0, 0)
    p2 = await f.establish(96, 0, 1)
    malformed_plaintext = f.core.encode_frame(
        f.core.FRAME_PING,
        f.core.frame_body(f.core.FRAME_PING, token=7),
    )
    await p1.send_raw_plaintext(malformed_plaintext, corrupt_tag=True)
    await wait_until(
        lambda: 1 not in f.session.carriers,
        label="auth-failed Carrier removal",
    )
    check(f.session.state == "ACTIVE", f.session.state)
    await f.ping(p2, 0xC101)
    failed = [
        x for x in f.trace.events
        if x.get("event") == "carrier_failed"
        and x.get("error_code") == ERROR_AUTHENTICATION_FAILED
    ]
    check(failed, "AUTHENTICATION_FAILED carrier trace")
    return {"remaining_carriers": sorted(f.session.carriers)}


async def case_frame_encoding_carrier_scope(f: Fixture) -> dict:
    p1 = await f.establish(1, 0, 0)
    p2 = await f.establish(96, 0, 1)
    malformed = f.core.vi_enc(f.core.FRAME_PING) + f.core.vi_enc(1)
    await p1.send_raw_plaintext(malformed)
    close = await p1.recv_until(f.core.FRAME_CARRIER_CLOSE)
    check(int(close["error_code"]) == ERROR_FRAME_ENCODING, close)
    await wait_until(
        lambda: 1 not in f.session.carriers,
        label="frame-encoding Carrier removal",
    )
    check(f.session.state == "ACTIVE", f.session.state)
    await f.ping(p2, 0xC102)
    return {"carrier_close": close, "remaining_carriers": sorted(f.session.carriers)}


async def case_stream_limit_server_only(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "stream limit probe is server receive-side only")
    p = await f.establish()
    await f.open_stream(p, 1)
    tx = f.next_peer_tx(p.carrier.carrier_id)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN,
        stream_id=3,
        transmission_id=tx,
    )
    reject = await p.recv_until(f.core.FRAME_STREAM_OPEN_REJECT)
    check(int(reject["error_code"]) == ERROR_STREAM_LIMIT, reject)
    check(f.session.state == "ACTIVE", f.session.state)
    check(set(f.session.streams) == {1}, f.session.streams)
    return {"reject": reject}


async def case_invalid_credit_structure(f: Fixture) -> dict:
    p = await f.establish()
    await p.carrier.send_frame(
        f.core.FRAME_SESSION_CREDIT,
        consumed_bytes=100,
        maximum_bytes=99,
    )
    close = await f.expect_session_close(
        p,
        ERROR_FLOW_CONTROL,
        f.core.FRAME_SESSION_CREDIT,
    )
    return {"close": close}


async def case_terminal_credit_violation(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    tx = f.next_peer_tx(p.carrier.carrier_id)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=tx,
        final_offset=int(stream.local_maximum) + 1,
    )
    close = await f.expect_session_close(
        p,
        ERROR_FLOW_CONTROL,
        f.core.FRAME_STREAM_FIN,
    )
    return {"close": close}


async def case_contradictory_final(f: Fixture) -> dict:
    p = await f.establish()
    await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=tx,
        final_offset=1,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_RESET_STREAM,
        stream_id=1,
        transmission_id=tx,
        final_offset=2,
        stream_error_code=1,
    )
    close = await f.expect_session_close(
        p,
        ERROR_FINAL_SIZE,
        f.core.FRAME_RESET_STREAM,
    )
    return {"close": close}


async def case_conflicting_txid_reuse(f: Fixture) -> dict:
    p = await f.establish()
    await f.open_stream(p)
    cid = p.carrier.carrier_id
    tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=tx,
        data=b"A",
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=1,
        transmission_id=tx,
        data=b"B",
    )
    close = await f.expect_session_close(
        p,
        ERROR_TRANSMISSION_ID,
        f.core.FRAME_STREAM_DATA,
    )
    return {"close": close}


async def case_nonzero_flags_carrier_scope(f: Fixture) -> dict:
    p1 = await f.establish(1, 0, 0)
    p2 = await f.establish(96, 0, 1)
    plaintext = f.core.encode_frame(
        f.core.FRAME_PING,
        f.core.frame_body(f.core.FRAME_PING, token=0x44),
    )
    await p1.send_raw_plaintext(plaintext, flags=1)
    close = await p1.recv_until(f.core.FRAME_CARRIER_CLOSE)
    check(int(close["error_code"]) == ERROR_FRAME_ENCODING, close)
    await wait_until(lambda: 1 not in f.session.carriers, label="flagged Carrier removal")
    check(f.session.state == "ACTIVE", f.session.state)
    await f.ping(p2, 0xC103)
    return {"carrier_close": close}


async def case_close_tail_carrier_scope(f: Fixture) -> dict:
    p1 = await f.establish(1, 0, 0)
    p2 = await f.establish(96, 0, 1)
    close_body = f.core.frame_body(
        f.core.FRAME_CARRIER_CLOSE,
        error_code=0,
        trigger_frame_type=0,
        reason="",
    )
    close_frame = f.core.encode_frame(f.core.FRAME_CARRIER_CLOSE, close_body)
    ping_frame = f.core.encode_frame(
        f.core.FRAME_PING,
        f.core.frame_body(f.core.FRAME_PING, token=1),
    )
    await p1.send_raw_plaintext(close_frame + ping_frame)
    response = await p1.recv_until(f.core.FRAME_CARRIER_CLOSE)
    check(int(response["error_code"]) == ERROR_FRAME_ENCODING, response)
    await wait_until(lambda: 1 not in f.session.carriers, label="close-tail Carrier removal")
    check(f.session.state == "ACTIVE", f.session.state)
    await f.ping(p2, 0xC104)
    return {"carrier_close": response}


async def case_invalid_stream_parity_server_only(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "Stream parity probe targets client-initiated Stream reception")
    p = await f.establish()
    tx = f.next_peer_tx(p.carrier.carrier_id)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN,
        stream_id=2,
        transmission_id=tx,
    )
    close = await f.expect_session_close(
        p,
        ERROR_STREAM_STATE,
        f.core.FRAME_STREAM_OPEN,
    )
    return {"close": close}


async def case_candidate_conflict_server_only(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "candidate conflict probe targets server admission")
    p = await f.establish(1, 0, 0)
    before = (
        dict(f.session.highest_accepted),
        sorted(f.session.carriers),
        f.session.state,
    )
    await f.expect_rejected_candidate(action=1, carrier_id=1, generation=0)
    after = (
        dict(f.session.highest_accepted),
        sorted(f.session.carriers),
        f.session.state,
    )
    check(before == after, (before, after))
    await f.ping(p, 0xC105)
    return {"highest_accepted": dict(f.session.highest_accepted)}


async def case_create_collision_server_only(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "CREATE collision probe targets server admission")
    p = await f.establish(1, 0, 0)
    before = (
        f.session.session_id,
        dict(f.session.highest_accepted),
        sorted(f.session.carriers),
    )
    await f.expect_rejected_candidate(action=0, carrier_id=96, generation=0)
    after = (
        f.session.session_id,
        dict(f.session.highest_accepted),
        sorted(f.session.carriers),
    )
    check(before == after, "colliding CREATE mutated retained Session")
    await f.ping(p, 0xC106)
    return {"retained": True}


CASES = {
    "normal-data": case_normal_data,
    "fin-fill-hole": case_fin_fill_hole,
    "reset-late-data-suppressed": case_reset_late_data,
    "stale-credit": case_stale_credit,
    "fin-data-beyond-final": case_fin_data_beyond_final,
    "crossed-session-credit": case_crossed_session_credit,
    "crossed-stream-credit": case_crossed_stream_credit,
    "final-below-commitment": case_final_below_commitment,
    "flow-control-data": case_flow_control_data,
    "session-aggregate-credit": case_session_aggregate_credit,
    "conflicting-overlap": case_conflicting_overlap,
    "never-allocated-ack": case_never_allocated_ack,
    "unknown-stream-data": case_unknown_stream_data,
    "shutdown-blocks-new-work": case_shutdown_blocks_new_work,
    "authentication-carrier-scope": case_auth_carrier_scope,
    "frame-encoding-carrier-scope": case_frame_encoding_carrier_scope,
    "stream-limit": case_stream_limit_server_only,
    "invalid-credit-structure": case_invalid_credit_structure,
    "terminal-credit-violation": case_terminal_credit_violation,
    "contradictory-final": case_contradictory_final,
    "conflicting-txid-reuse": case_conflicting_txid_reuse,
    "nonzero-record-flags": case_nonzero_flags_carrier_scope,
    "close-tail": case_close_tail_carrier_scope,
    "invalid-stream-parity": case_invalid_stream_parity_server_only,
    "candidate-conflict": case_candidate_conflict_server_only,
    "create-collision": case_create_collision_server_only,
}


async def run_one(
    implementation: str,
    role: str,
    case_name: str,
) -> dict:
    max_streams = 1 if case_name == "stream-limit" else 32
    async with Fixture(implementation, role, max_streams=max_streams) as fixture:
        detail = await CASES[case_name](fixture)
        return {
            "implementation": implementation,
            "endpoint_role": role,
            "case": case_name,
            "status": "PASS",
            "session_state": fixture.session.state,
            "trace_events": len(fixture.trace.events),
            "detail": detail,
        }


async def amain(args: argparse.Namespace) -> dict:
    started = time.time()
    selected_impl = args.implementation or list(IMPLEMENTATIONS)
    selected_roles = args.role or list(ROLES)
    selected_cases = args.case or list(CASES)
    results = []

    for implementation in selected_impl:
        for role in selected_roles:
            for case_name in selected_cases:
                if case_name in {
                    "stream-limit",
                    "invalid-stream-parity",
                    "candidate-conflict",
                    "create-collision",
                } and role != "server":
                    continue
                result = await run_one(implementation, role, case_name)
                results.append(result)
                print(
                    f"endpoint-wire {implementation}/{role}/{case_name}: PASS",
                    flush=True,
                )

    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "authenticated endpoint wire conformance",
        "status": "PASS",
        "execution_count": len(results),
        "implementations": selected_impl,
        "roles": selected_roles,
        "cases": results,
        "evidence_class": "endpoint-wire",
        "duration_seconds": round(time.time() - started, 3),
        "claim_boundary": (
            "real loopback TCP + full CREATE/Finished + authenticated Secure Records; "
            "the probe peer is test code and is not itself an independent production implementation"
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 authenticated endpoint-wire conformance")
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--implementation", action="append", choices=IMPLEMENTATIONS)
    p.add_argument("--role", action="append", choices=ROLES)
    p.add_argument("--case", action="append", choices=tuple(CASES))
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "endpoint-wire-report.json"
    try:
        report = asyncio.run(amain(args))
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"endpoint-wire suite: PASS ({report['execution_count']} executions)")
        print(f"report: {path}")
        return 0
    except Exception as exc:
        path.write_text(
            json.dumps(
                {
                    "protocol": "MPX/4",
                    "revision": "Draft 11",
                    "suite": "authenticated endpoint wire conformance",
                    "status": "FAIL",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"endpoint-wire suite: FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"report: {path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
