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
        max_carriers: int = 4,
    ) -> None:
        self.implementation = implementation
        self.endpoint_role = endpoint_role
        self.core, self.runtime = modules(implementation)
        self.key = secrets.token_bytes(32)
        self.limits = self.core.Limits(
            max_frame_payload=32768,
            max_record_size=65536,
            max_streams=max_streams,
            max_carriers=max_carriers,
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
        self.peer_tx_cursor = 1

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

    async def raw_candidate(
        self,
        *,
        action: int,
        carrier_id: int,
        generation: int,
        version: Optional[int] = None,
        limits: Optional[object] = None,
        session_id: Optional[bytes] = None,
        corrupt_finished: bool = False,
        complete: bool = False,
    ) -> Dict[str, object]:
        check(self.endpoint_role == "server", "raw candidate probe targets server admission")
        core = self.core
        assert self.port is not None
        requested_version = core.VERSION if version is None else version
        candidate_limits = self.limits if limits is None else limits
        candidate_sid = self.session_id if session_id is None else session_id
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        preface = core.MAGIC + core.vi_enc(requested_version)
        client_init = core.encode_client_init(
            candidate_sid,
            carrier_id,
            generation,
            secrets.token_bytes(32),
            candidate_limits,
            action,
        )
        writer.write(preface + client_init)
        await writer.drain()
        try:
            msg, body, raw = await asyncio.wait_for(core.read_message(reader), timeout=1.0)
        except asyncio.IncompleteReadError:
            writer.close()
            return {"message_type": None, "closed": True}
        result: Dict[str, object] = {"message_type": msg, "raw_hex": raw.hex()}
        if msg == core.MSG_HANDSHAKE_REJECT:
            code, end = core.vi_dec(body)
            check(end == len(body), "HANDSHAKE_REJECT trailing bytes")
            result["error_code"] = code
            try:
                await asyncio.wait_for(reader.readexactly(1), timeout=0.5)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
            writer.close()
            return result
        if msg == core.MSG_VERSION_NEGOTIATION:
            count, pos = core.vi_dec(body)
            versions = []
            for _ in range(count):
                item, pos = core.vi_dec(body, pos)
                versions.append(item)
            check(pos == len(body), "VERSION_NEGOTIATION trailing bytes")
            result["versions"] = versions
            writer.close()
            return result
        check(msg == core.MSG_SERVER_INIT, f"unexpected handshake message {msg}")
        result["server_init"] = raw
        if not complete:
            writer.close()
            return result
        _, server_limits = core.parse_server_init(raw)
        client_finished, expected_sf, h0, prelim = core.derive_traffic(
            self.key, preface, client_init, raw
        )
        if corrupt_finished:
            client_finished = client_finished[:-1] + bytes((client_finished[-1] ^ 1,))
        writer.write(client_finished)
        await writer.drain()
        try:
            msg2, body2, raw2 = await asyncio.wait_for(core.read_message(reader), timeout=1.0)
        except asyncio.IncompleteReadError:
            writer.close()
            result["finished_result"] = "closed"
            return result
        result["finished_message_type"] = msg2
        if msg2 == core.MSG_HANDSHAKE_REJECT:
            code, end = core.vi_dec(body2)
            check(end == len(body2), "post-init HANDSHAKE_REJECT trailing bytes")
            result["error_code"] = code
            writer.close()
            return result
        check(msg2 == core.MSG_SERVER_FINISHED, f"expected SERVER_FINISHED, got {msg2}")
        h1 = hashlib.sha256(preface + client_init + raw + client_finished).digest()
        core.validate_finished(raw2, core.MSG_SERVER_FINISHED, prelim.server_finished_key, h1)
        check(raw2 == expected_sf, "SERVER_FINISHED canonical mismatch")
        _, _, _, traffic = core.derive_traffic(
            self.key, preface, client_init, raw, client_finished=client_finished, server_finished=raw2
        )
        carrier = core.Carrier(
            role="client",
            reader=reader,
            writer=writer,
            trace=NullTrace(),
            local_limits=candidate_limits,
            peer_limits=server_limits,
            send_key=traffic.client_key,
            send_iv=traffic.client_iv,
            recv_key=traffic.server_key,
            recv_iv=traffic.server_iv,
            session_id=candidate_sid,
            carrier_id=carrier_id,
            generation=generation,
            write_chunk=0,
        )
        result["peer"] = Peer(core, carrier, [])
        return result

    async def expect_rejected_candidate(
        self,
        *,
        action: int,
        carrier_id: int,
        generation: int,
        expected_error_code: Optional[int] = None,
        limits: Optional[object] = None,
        version: Optional[int] = None,
    ) -> Dict[str, object]:
        result = await self.raw_candidate(
            action=action,
            carrier_id=carrier_id,
            generation=generation,
            limits=limits,
            version=version,
        )
        check(result.get("message_type") == self.core.MSG_HANDSHAKE_REJECT, result)
        if expected_error_code is not None:
            check(result.get("error_code") == expected_error_code, result)
        return result

    def next_peer_tx(self, carrier_id: int) -> int:
        check(carrier_id in self.peers, f"unknown peer Carrier {carrier_id}")
        value = self.peer_tx_cursor
        self.peer_tx_cursor += 1
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
    endpoint_carrier = f.session.carriers.get(1)
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
            check(endpoint_carrier is not None, "missing pre-close endpoint Carrier")
            await f.session.open_stream(3, endpoint_carrier)
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


async def case_stop_sending_directionality(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    stop_tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STOP_SENDING,
        stream_id=1,
        transmission_id=stop_tx,
        stream_error_code=7,
    )
    stop_ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(stop_ack["transmission_id"]) == stop_tx, stop_ack)
    reset = await p.recv_until(f.core.FRAME_RESET_STREAM)
    reset_tx = int(reset["transmission_id"])
    check(int(reset["final_offset"]) == int(stream.send_offset), reset)
    await p.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=reset_tx,
        receiver_timestamp_us=0,
    )
    data_tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_DATA,
        stream_id=1,
        offset=0,
        transmission_id=data_tx,
        data=b"X",
    )
    data_ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(data_ack["transmission_id"]) == data_tx, data_ack)
    check(bytes(stream.recv_data) == b"X", "STOP_SENDING incorrectly terminated receive direction")
    check(stream.recv_terminal_mode == "ACTIVE", stream.recv_terminal_mode)
    check(stream.send_terminal_mode == "RESET", stream.send_terminal_mode)
    check(f.session.state == "ACTIVE", f.session.state)
    return {"recv": stream.recv_terminal_mode, "send": stream.send_terminal_mode, "application": "X"}


async def case_legal_overlap_reassembly(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    for offset, data in ((1, b"BC"), (0, b"AB")):
        tx = f.next_peer_tx(cid)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=offset,
            transmission_id=tx,
            data=data,
        )
        ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(ack["transmission_id"]) == tx, ack)
    check(bytes(stream.recv_data) == b"ABC", stream.recv_data)
    check(stream.recv_next == 3, stream.recv_next)
    check(f.session.application_rx_bytes == 3, f.session.application_rx_bytes)
    check(f.session.state == "ACTIVE", f.session.state)
    return {"application": "ABC", "recv_next": 3}


async def case_same_offset_extension(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    for offset, data in ((1, b"B"), (1, b"BC"), (0, b"A")):
        tx = f.next_peer_tx(cid)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=offset,
            transmission_id=tx,
            data=data,
        )
        ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(ack["transmission_id"]) == tx, ack)
    check(bytes(stream.recv_data) == b"ABC", stream.recv_data)
    check(stream.recv_next == 3, stream.recv_next)
    check(f.session.state == "ACTIVE", f.session.state)
    return {"application": "ABC", "recv_next": 3}


async def case_terminal_credit_boundary(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    stop_tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STOP_SENDING,
        stream_id=1,
        transmission_id=stop_tx,
        stream_error_code=0,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    reset = await p.recv_until(f.core.FRAME_RESET_STREAM)
    await p.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=int(reset["transmission_id"]),
        receiver_timestamp_us=0,
    )
    old = f.stream_credit(1)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=0,
        maximum_offset=max(old[1] + 8, 8),
    )
    await f.ping(p, 0xC107)
    check(stream.send_final == 0, stream.send_final)
    check(f.session.state == "ACTIVE", f.session.state)
    return {"send_final": stream.send_final, "credit": list(f.stream_credit(1))}


async def case_terminal_credit_beyond_final(f: Fixture) -> dict:
    p = await f.establish()
    stream = await f.open_stream(p)
    cid = p.carrier.carrier_id
    stop_tx = f.next_peer_tx(cid)
    await p.carrier.send_frame(
        f.core.FRAME_STOP_SENDING,
        stream_id=1,
        transmission_id=stop_tx,
        stream_error_code=0,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    reset = await p.recv_until(f.core.FRAME_RESET_STREAM)
    await p.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=int(reset["transmission_id"]),
        receiver_timestamp_us=0,
    )
    old = f.stream_credit(1)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT,
        stream_id=1,
        consumed_offset=1,
        maximum_offset=max(old[1] + 8, 8),
    )
    close = await f.expect_session_close(
        p,
        ERROR_FINAL_SIZE,
        f.core.FRAME_STREAM_CREDIT,
    )
    check(stream.send_final == 0, stream.send_final)
    return {"send_final": stream.send_final, "close": close}


async def prepare_credit_tombstone(f: Fixture) -> Tuple[Peer, object, dict]:
    peer = await f.establish()
    stream = await f.open_stream(peer)
    core = f.core
    carrier = f.session.carriers[peer.carrier.carrier_id]
    await peer.carrier.send_frame(
        core.FRAME_SESSION_CREDIT, consumed_bytes=0, maximum_bytes=8 * 1024 * 1024,
    )
    await peer.carrier.send_frame(
        core.FRAME_STREAM_CREDIT, stream_id=1, consumed_offset=0, maximum_offset=1024 * 1024,
    )
    await f.ping(peer)

    async def acknowledge_local(frame_type: int, txid: Optional[int] = None) -> dict:
        fields = await peer.recv_until(frame_type)
        if txid is not None:
            check(int(fields["transmission_id"]) == txid, fields)
        await peer.carrier.send_frame(
            core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=int(fields["transmission_id"]),
            receiver_timestamp_us=0,
        )
        return fields

    async def peer_reliable(frame_type: int, **fields: object) -> int:
        txid = f.next_peer_tx(peer.carrier.carrier_id)
        await peer.carrier.send_frame(frame_type, stream_id=1, transmission_id=txid, **fields)
        ack = await peer.recv_until(core.FRAME_TRANSMISSION_ACK)
        check(int(ack["transmission_id"]) == txid, ack)
        return txid

    data_tx = await f.session.send_data(stream, b"ABCD", carrier)
    data = await acknowledge_local(core.FRAME_STREAM_DATA, data_tx.txid)
    check(data["data"] == b"ABCD", data)
    await peer_reliable(core.FRAME_STOP_SENDING, stream_error_code=0)
    reset = await acknowledge_local(core.FRAME_RESET_STREAM)
    check(int(reset["transmission_id"]) == stream.local_terminal_txid, reset)
    check(int(reset["final_offset"]) == 4, reset)
    peer_reset_tx = await peer_reliable(core.FRAME_RESET_STREAM, final_offset=0, stream_error_code=0)
    consumed_tx = await f.session.send_stream_consumed(stream, carrier)
    consumed = await acknowledge_local(core.FRAME_STREAM_CONSUMED, consumed_tx.txid)
    check(int(consumed["final_offset"]) == 0, consumed)
    await peer_reliable(core.FRAME_STREAM_CONSUMED, final_offset=4)
    await f.ping(peer)

    confirmations = {
        txid: response for txid, response in f.session.peer_tx_confirmation.items()
        if int(response[1].get("stream_id", 0)) == 1
    }
    peer_stream_txids = {
        txid for txid, semantic in f.session.peer_tx_semantics.items()
        if dict(semantic[1]).get("stream_id") == 1
    }
    check(peer_stream_txids <= set(confirmations), (peer_stream_txids, confirmations))
    check(peer_reset_tx in confirmations, confirmations)
    check(stream.send_final == 4 and stream.recv_final == 0, (stream.send_final, stream.recv_final))
    check(stream.send_terminal_mode == stream.recv_terminal_mode == "RESET", "both directions RESET")
    check(stream.local_terminal_settled and stream.local_consumed and stream.peer_final_consumed, "terminal confirmations")
    check(all(tx.settled for tx in f.session.local_tx.values()), "all local reliable Tx settled")
    check(stream.recv_committed == f.session.session_recv_committed == 0, "receive accounting released")
    check(f.session.application_rx_bytes == 0, "no application receive data")
    before = {
        "stream_credit": f.stream_credit(1),
        "session_credit": f.session_credit(),
        "session_send_committed": f.session.session_send_committed,
        "application_rx_bytes": f.session.application_rx_bytes,
        "send_final": stream.send_final,
        "recv_final": stream.recv_final,
        "send_terminal_mode": stream.send_terminal_mode,
        "recv_terminal_mode": stream.recv_terminal_mode,
        "local_terminal_settled": stream.local_terminal_settled,
        "local_consumed": stream.local_consumed,
        "peer_final_consumed": stream.peer_final_consumed,
        "recv_committed": stream.recv_committed,
        "all_local_tx_settled": True,
        "local_txids": sorted(f.session.local_tx),
        "peer_stream_txids": sorted(peer_stream_txids),
        "confirmation_txids": sorted(confirmations),
        "peer_reset_tx": peer_reset_tx,
    }
    tombstone = f.session.retire_stream_to_tombstone(1)
    check(tombstone["send_final"] == 4 and 1 not in f.session.streams, tombstone)
    check(all(f.session.peer_tx_confirmation.get(txid) == response for txid, response in confirmations.items()), "Session retains confirmation replay")
    before["tombstone"] = dict(tombstone)
    return peer, stream, before


def check_tombstone_credit_unchanged(f: Fixture, stream: object, before: dict, *, retired: bool = False) -> None:
    check(1 not in f.session.streams, "late credit resurrected Stream")
    if retired:
        check(1 not in f.session.tombstones and 1 in f.session.retired_stream_ids, "identity remains retired")
    else:
        check(f.session.tombstones.get(1) == before["tombstone"], "late credit changed tombstone")
    stream_credit = (
        (stream.peer_consumed, stream.peer_maximum) if f.implementation == "reference"
        else (stream.peer_credit.consumed, stream.peer_credit.maximum)
    )
    check(stream_credit == before["stream_credit"], "late credit expanded Stream authorization")
    check(f.session_credit() == before["session_credit"], "late credit changed Session authorization")
    check(f.session.session_send_committed == before["session_send_committed"], "late credit changed commitment")
    check(f.session.session_recv_committed == before["recv_committed"], "late credit changed receive commitment")
    check(f.session.application_rx_bytes == before["application_rx_bytes"], "late credit delivered application data")
    check(f.session.state == "ACTIVE", f.session.state)


async def tombstone_credit_positive(f: Fixture, *, maximum_above_final: bool) -> dict:
    peer, stream, before = await prepare_credit_tombstone(f)
    final = before["send_final"]
    maximum = final + f.runtime.STREAM_CREDIT_WINDOW_LIMIT if maximum_above_final else final
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT, stream_id=1, consumed_offset=final, maximum_offset=maximum,
    )
    await f.ping(peer)
    check_tombstone_credit_unchanged(f, stream, before)
    await peer.carrier.send_frame(
        f.core.FRAME_RESET_STREAM,
        stream_id=1,
        transmission_id=before["peer_reset_tx"],
        final_offset=0,
        stream_error_code=0,
    )
    ack = await peer.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(ack["transmission_id"]) == before["peer_reset_tx"], ack)
    await f.ping(peer)
    check_tombstone_credit_unchanged(f, stream, before)
    return {"preconditions": before, "consumed": final, "maximum": maximum, "confirmation_replayed": True}


async def case_tombstone_credit_boundary(f: Fixture) -> dict:
    return await tombstone_credit_positive(f, maximum_above_final=False)


async def case_tombstone_credit_maximum_above_final(f: Fixture) -> dict:
    return await tombstone_credit_positive(f, maximum_above_final=True)


async def tombstone_credit_negative(f: Fixture, violation: str) -> dict:
    peer, _, before = await prepare_credit_tombstone(f)
    final = before["send_final"]
    if violation == "beyond-final":
        consumed, maximum, error = final + 1, before["stream_credit"][1] + 8, ERROR_FINAL_SIZE
    elif violation == "invalid-pair":
        consumed, maximum, error = final, final - 1, ERROR_FLOW_CONTROL
    else:
        consumed, maximum, error = final, final + f.runtime.STREAM_CREDIT_WINDOW_LIMIT + 1, ERROR_FLOW_CONTROL
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT, stream_id=1, consumed_offset=consumed, maximum_offset=maximum,
    )
    try:
        close = await f.expect_session_close(peer, error, f.core.FRAME_STREAM_CREDIT)
    except asyncio.TimeoutError as exc:
        await f.ping(peer)
        raise ProbeError(
            f"retained tombstone STREAM_CREDIT {violation} did not close Session; "
            f"PING/PONG still succeeds (state={f.session.state}, send_final={final}, "
            f"all_local_tx_settled={before['all_local_tx_settled']}, "
            f"confirmation_txids={before['confirmation_txids']})"
        ) from exc
    return {"preconditions": before, "consumed": consumed, "maximum": maximum, "close": close}


async def case_tombstone_credit_beyond_final(f: Fixture) -> dict:
    return await tombstone_credit_negative(f, "beyond-final")


async def case_tombstone_credit_invalid_pair(f: Fixture) -> dict:
    return await tombstone_credit_negative(f, "invalid-pair")


async def case_tombstone_credit_window_exceeded(f: Fixture) -> dict:
    return await tombstone_credit_negative(f, "window-exceeded")


async def case_retired_credit_ignored(f: Fixture) -> dict:
    peer, stream, before = await prepare_credit_tombstone(f)
    retired_through = max(before["confirmation_txids"])
    await peer.carrier.send_frame(f.core.FRAME_TRANSMISSION_RETIRE, retired_through=retired_through)
    await f.ping(peer)
    check(f.session.peer_retired_through == retired_through, f.session.peer_retired_through)
    check(not set(before["confirmation_txids"]) & set(f.session.peer_tx_confirmation), "retired confirmations released")
    check(all(tx.settled for tx in f.session.local_tx.values()), "all local reliable Tx settled before compaction")
    f.session.compact_tombstone(1)
    for consumed, maximum in (
        (5, before["stream_credit"][1] + 8),
        (4, 3),
        (4, 4 + f.runtime.STREAM_CREDIT_WINDOW_LIMIT + 1),
    ):
        await peer.carrier.send_frame(
            f.core.FRAME_STREAM_CREDIT, stream_id=1, consumed_offset=consumed, maximum_offset=maximum,
        )
        await f.ping(peer)
        check_tombstone_credit_unchanged(f, stream, before, retired=True)
    return {"preconditions": before, "retired_through": retired_through, "ignored_credit_pairs": 3}


async def case_unknown_stream_credit(f: Fixture) -> dict:
    peer = await f.establish()
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_CREDIT, stream_id=99, consumed_offset=0, maximum_offset=1,
    )
    close = await f.expect_session_close(peer, ERROR_STREAM_STATE, f.core.FRAME_STREAM_CREDIT)
    return {"close": close}


async def terminalize_open_stream_zero(f: Fixture, peer: Peer, stream: object) -> dict:
    core = f.core
    carrier = f.session.carriers[peer.carrier.carrier_id]
    cid = peer.carrier.carrier_id

    stop_tx = f.next_peer_tx(cid)
    await peer.carrier.send_frame(
        core.FRAME_STOP_SENDING,
        stream_id=1,
        transmission_id=stop_tx,
        stream_error_code=0,
    )
    stop_ack = await peer.recv_until(core.FRAME_TRANSMISSION_ACK)
    check(int(stop_ack["transmission_id"]) == stop_tx, stop_ack)
    local_reset = await peer.recv_until(core.FRAME_RESET_STREAM)
    check(int(local_reset["final_offset"]) == 0, local_reset)
    await peer.carrier.send_frame(
        core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=int(local_reset["transmission_id"]),
        receiver_timestamp_us=0,
    )

    peer_reset_tx = f.next_peer_tx(cid)
    await peer.carrier.send_frame(
        core.FRAME_RESET_STREAM,
        stream_id=1,
        transmission_id=peer_reset_tx,
        final_offset=0,
        stream_error_code=0,
    )
    reset_ack = await peer.recv_until(core.FRAME_TRANSMISSION_ACK)
    check(int(reset_ack["transmission_id"]) == peer_reset_tx, reset_ack)

    consumed_tx = await f.session.send_stream_consumed(stream, carrier)
    consumed = await peer.recv_until(core.FRAME_STREAM_CONSUMED)
    check(int(consumed["transmission_id"]) == consumed_tx.txid, consumed)
    check(int(consumed["final_offset"]) == 0, consumed)
    await peer.carrier.send_frame(
        core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=consumed_tx.txid,
        receiver_timestamp_us=0,
    )

    peer_consumed_tx = f.next_peer_tx(cid)
    await peer.carrier.send_frame(
        core.FRAME_STREAM_CONSUMED,
        stream_id=1,
        transmission_id=peer_consumed_tx,
        final_offset=0,
    )
    consumed_ack = await peer.recv_until(core.FRAME_TRANSMISSION_ACK)
    check(int(consumed_ack["transmission_id"]) == peer_consumed_tx, consumed_ack)
    await f.ping(peer, 0xC201)

    check(stream.send_final == 0 and stream.recv_final == 0, (stream.send_final, stream.recv_final))
    check(stream.send_terminal_mode == stream.recv_terminal_mode == "RESET", "zero-terminal RESET")
    check(stream.local_terminal_settled and stream.local_consumed and stream.peer_final_consumed, "zero-terminal settlement")
    check(all(tx.settled for tx in f.session.local_tx.values()), "local reliable state settled")
    tombstone = f.session.retire_stream_to_tombstone(1)
    check(1 not in f.session.streams and 1 in f.session.tombstones, f.session.tombstones)
    return dict(tombstone)


async def open_pending_client_stream(f: Fixture, peer: Peer) -> Tuple[object, object]:
    stream = f.runtime.StreamState(stream_id=1, lifecycle="OPENING", accepted=False)
    f.session.streams[1] = stream
    tx = f.session.alloc_tx(f.core.FRAME_STREAM_OPEN, 1)
    stream.opening_txid = tx.txid
    await f.session.send_tx(tx, f.session.carriers[peer.carrier.carrier_id])
    opened = await peer.recv_until(f.core.FRAME_STREAM_OPEN)
    check(int(opened["stream_id"]) == 1 and int(opened["transmission_id"]) == tx.txid, opened)
    return stream, tx


async def case_padding_ignored(f: Fixture) -> dict:
    peer = await f.establish()
    token = 0xC210
    plaintext = (
        f.core.encode_frame(f.core.FRAME_PADDING, b"\x00\xff\x5a")
        + f.core.encode_frame(f.core.FRAME_PING, f.core.vi_enc(token))
    )
    await peer.send_raw_plaintext(plaintext)
    pong = await peer.recv_until(f.core.FRAME_PONG)
    check(int(pong["token"]) == token, pong)
    check(f.session.state == "ACTIVE", f.session.state)
    return {"padding_octets": 3, "pong": token}


async def case_unknown_extension_skipped(f: Fixture) -> dict:
    peer = await f.establish()
    token = 0xC211
    plaintext = (
        f.core.encode_frame(0x40, b"extension-body")
        + f.core.encode_frame(f.core.FRAME_PING, f.core.vi_enc(token))
    )
    await peer.send_raw_plaintext(plaintext)
    pong = await peer.recv_until(f.core.FRAME_PONG)
    check(int(pong["token"]) == token, pong)
    check(f.session.state == "ACTIVE", f.session.state)
    return {"extension_type": 0x40, "pong": token}


async def case_unknown_core_session_scope(f: Fixture) -> dict:
    first = await f.establish()
    second = await f.establish(96)
    await first.send_raw_plaintext(f.core.encode_frame(0x3F, b""))
    close = await f.expect_session_close(first, ERROR_PROTOCOL_VIOLATION, 0x3F)
    await second.expect_no(f.core.FRAME_PONG, timeout=0.10)
    check(f.session.state == "CLOSED", f.session.state)
    return {"close": close, "alternate_carrier_closed": True}


async def case_invalid_preopen_stop_id(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "invalid pre-open STOP targets server receiver")
    peer = await f.establish()
    txid = f.next_peer_tx(peer.carrier.carrier_id)
    await peer.carrier.send_frame(
        f.core.FRAME_STOP_SENDING,
        stream_id=2,
        transmission_id=txid,
        stream_error_code=0,
    )
    close = await f.expect_session_close(peer, ERROR_STREAM_STATE, f.core.FRAME_STOP_SENDING)
    check(2 not in f.session.opening_tombstones, f.session.opening_tombstones)
    return {"close": close, "invalid_stream_id": 2}


async def case_valid_preopen_stop_unseen(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "pre-open STOP positive targets server receiver")
    peer = await f.establish()
    txid = f.next_peer_tx(peer.carrier.carrier_id)
    await peer.carrier.send_frame(
        f.core.FRAME_STOP_SENDING,
        stream_id=1,
        transmission_id=txid,
        stream_error_code=7,
    )
    ack = await peer.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(ack["transmission_id"]) == txid, ack)
    reset = await peer.recv_until(f.core.FRAME_RESET_STREAM)
    check(int(reset["stream_id"]) == 1 and int(reset["final_offset"]) == 0, reset)
    await peer.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=int(reset["transmission_id"]),
        receiver_timestamp_us=0,
    )
    await f.ping(peer, 0xC212)
    check(1 in f.session.opening_tombstones and f.session.state == "ACTIVE", f.session.opening_tombstones)
    return {"acknowledged": txid, "reset_final": 0}


async def case_capacity_reject_replay(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "capacity reject replay targets server receiver")
    peer = await f.establish()
    stream = await f.open_stream(peer)
    txid = f.next_peer_tx(peer.carrier.carrier_id)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN,
        stream_id=3,
        transmission_id=txid,
    )
    first = await peer.recv_until(f.core.FRAME_STREAM_OPEN_REJECT)
    check(int(first["error_code"]) == ERROR_STREAM_LIMIT, first)
    await terminalize_open_stream_zero(f, peer, stream)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN,
        stream_id=3,
        transmission_id=txid,
    )
    second = await peer.recv_until(f.core.FRAME_STREAM_OPEN_REJECT)
    check(int(second["transmission_id"]) == txid, second)
    check(int(second["error_code"]) == int(first["error_code"]), (first, second))
    check(3 not in f.session.streams, f.session.streams)
    await f.ping(peer, 0xC213)
    return {"original_error": first["error_code"], "replayed_error": second["error_code"]}


async def case_accepted_open_replay_tombstone(f: Fixture) -> dict:
    check(f.endpoint_role == "server", "accepted STREAM_OPEN replay targets server receiver")
    peer = await f.establish()
    stream = await f.open_stream(peer)
    opening_txid = int(stream.opening_txid)
    await terminalize_open_stream_zero(f, peer, stream)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN,
        stream_id=1,
        transmission_id=opening_txid,
    )
    replay = await peer.recv_until(f.core.FRAME_STREAM_OPEN_OK)
    check(int(replay["transmission_id"]) == opening_txid, replay)
    check(1 not in f.session.streams and 1 in f.session.tombstones, f.session.tombstones)
    await f.ping(peer, 0xC214)
    return {"opening_txid": opening_txid, "decision": "OPEN_OK"}


async def case_accepted_open_ok_replay_tombstone(f: Fixture) -> dict:
    check(f.endpoint_role == "client", "late OPEN_OK replay targets client receiver")
    peer = await f.establish()
    stream = await f.open_stream(peer)
    opening_txid = int(stream.opening_txid)
    await terminalize_open_stream_zero(f, peer, stream)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN_OK,
        stream_id=1,
        transmission_id=opening_txid,
    )
    await f.ping(peer, 0xC215)
    check(f.session.state == "ACTIVE", f.session.state)
    check(1 not in f.session.streams and 1 in f.session.tombstones, f.session.tombstones)
    return {"opening_txid": opening_txid, "duplicate_confirmation": True}


async def case_duplicate_open_reject(f: Fixture) -> dict:
    check(f.endpoint_role == "client", "OPEN_REJECT duplicate targets client receiver")
    peer = await f.establish()
    _, tx = await open_pending_client_stream(f, peer)
    fields = {
        "stream_id": 1,
        "transmission_id": tx.txid,
        "error_code": ERROR_STREAM_LIMIT,
    }
    await peer.carrier.send_frame(f.core.FRAME_STREAM_OPEN_REJECT, **fields)
    await f.ping(peer, 0xC216)
    retained = dict(f.session.opening_tombstones[1])
    await peer.carrier.send_frame(f.core.FRAME_STREAM_OPEN_REJECT, **fields)
    await f.ping(peer, 0xC217)
    check(f.session.state == "ACTIVE", f.session.state)
    check(f.session.opening_tombstones[1] == retained, f.session.opening_tombstones[1])
    return {"error_code": ERROR_STREAM_LIMIT, "idempotent": True}


async def case_conflicting_open_reject(f: Fixture) -> dict:
    check(f.endpoint_role == "client", "conflicting OPEN_REJECT targets client receiver")
    peer = await f.establish()
    _, tx = await open_pending_client_stream(f, peer)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN_REJECT,
        stream_id=1,
        transmission_id=tx.txid,
        error_code=ERROR_STREAM_LIMIT,
    )
    await f.ping(peer, 0xC218)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_OPEN_REJECT,
        stream_id=1,
        transmission_id=tx.txid,
        error_code=ERROR_STREAM_STATE,
    )
    close = await f.expect_session_close(peer, ERROR_STREAM_STATE, f.core.FRAME_STREAM_OPEN_REJECT)
    return {"close": close, "original_error": ERROR_STREAM_LIMIT, "conflicting_error": ERROR_STREAM_STATE}


async def case_late_stop_tombstone(f: Fixture) -> dict:
    peer, _, before = await prepare_credit_tombstone(f)
    txid = f.next_peer_tx(peer.carrier.carrier_id)
    await peer.carrier.send_frame(
        f.core.FRAME_STOP_SENDING,
        stream_id=1,
        transmission_id=txid,
        stream_error_code=7,
    )
    ack = await peer.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(ack["transmission_id"]) == txid, ack)
    await peer.expect_no(f.core.FRAME_RESET_STREAM, timeout=0.15)
    check(f.session.tombstones[1]["send_final"] == before["send_final"] == 4, f.session.tombstones[1])
    check(1 not in f.session.opening_tombstones, f.session.opening_tombstones)
    await f.ping(peer, 0xC219)
    return {"send_final": 4, "new_reset": False}


async def case_retired_fin_confirmation_replay(f: Fixture) -> dict:
    peer, _, before = await prepare_credit_tombstone(f)
    txid = f.next_peer_tx(peer.carrier.carrier_id)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=txid,
        final_offset=0,
    )
    first = await peer.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(first["transmission_id"]) == txid, first)
    check(txid in f.session.peer_tx_confirmation and f.session.peer_retired_through == 0, f.session.peer_tx_confirmation)
    f.session.compact_tombstone(1)
    check(1 in f.session.retired_stream_ids and 1 not in f.session.tombstones, f.session.retired_stream_ids)
    await peer.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=txid,
        final_offset=0,
    )
    second = await peer.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    check(int(second["transmission_id"]) == txid, second)
    check(f.session.state == "ACTIVE" and 1 not in f.session.streams, f.session.state)
    await f.ping(peer, 0xC21A)
    return {"preconditions": before, "txid": txid, "confirmation_replayed": True}


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
    "stop-sending-directionality": case_stop_sending_directionality,
    "legal-overlap-reassembly": case_legal_overlap_reassembly,
    "same-offset-extension": case_same_offset_extension,
    "terminal-credit-boundary": case_terminal_credit_boundary,
    "terminal-credit-beyond-final": case_terminal_credit_beyond_final,
    "tombstone-credit-boundary": case_tombstone_credit_boundary,
    "tombstone-credit-maximum-above-final": case_tombstone_credit_maximum_above_final,
    "tombstone-credit-beyond-final": case_tombstone_credit_beyond_final,
    "tombstone-credit-invalid-pair": case_tombstone_credit_invalid_pair,
    "tombstone-credit-window-exceeded": case_tombstone_credit_window_exceeded,
    "retired-credit-ignored": case_retired_credit_ignored,
    "unknown-stream-credit": case_unknown_stream_credit,
    "padding-ignored": case_padding_ignored,
    "unknown-extension-skipped": case_unknown_extension_skipped,
    "unknown-core-session-scope": case_unknown_core_session_scope,
    "invalid-preopen-stop-id": case_invalid_preopen_stop_id,
    "valid-preopen-stop-unseen": case_valid_preopen_stop_unseen,
    "capacity-reject-replay": case_capacity_reject_replay,
    "accepted-open-replay-tombstone": case_accepted_open_replay_tombstone,
    "accepted-open-ok-replay-tombstone": case_accepted_open_ok_replay_tombstone,
    "duplicate-open-reject": case_duplicate_open_reject,
    "conflicting-open-reject": case_conflicting_open_reject,
    "late-stop-tombstone": case_late_stop_tombstone,
    "retired-fin-confirmation-replay": case_retired_fin_confirmation_replay,
}


async def run_one(
    implementation: str,
    role: str,
    case_name: str,
) -> dict:
    max_streams = 1 if case_name in {"stream-limit", "capacity-reject-replay"} else 32
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
                server_only = {
                    "stream-limit",
                    "invalid-stream-parity",
                    "candidate-conflict",
                    "create-collision",
                    "invalid-preopen-stop-id",
                    "valid-preopen-stop-unseen",
                    "capacity-reject-replay",
                    "accepted-open-replay-tombstone",
                }
                client_only = {
                    "accepted-open-ok-replay-tombstone",
                    "duplicate-open-reject",
                    "conflicting-open-reject",
                }
                if case_name in server_only and role != "server":
                    continue
                if case_name in client_only and role != "client":
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
