#!/usr/bin/env python3
"""Endpoint-level execution for the Draft 11 Mandatory cases formerly model-only.

This suite is intentionally separate from the state/oracle model.  Cases use
real loopback TCP, the runtime handshake, authenticated Secure Records, and
actual Session/Carrier/Stream handlers.  Local-policy transitions such as
tombstone compaction and DORMANT retention expiry are invoked on the real
runtime only after their wire-visible preconditions have been created.

The report names the Mandatory IDs proven by each execution so Gate 3 can fail
closed if any previously-model-only requirement loses endpoint evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from .endpoint_wire import (
    ERROR_FINAL_SIZE,
    ERROR_FLOW_CONTROL,
    ERROR_PROTOCOL_VIOLATION,
    ERROR_STREAM_STATE,
    ERROR_TRANSMISSION_ID,
    Fixture,
    MemoryTrace,
    NullTrace,
    Peer,
    ProbeError,
    check,
    modules,
    wait_until,
)

ERROR_RESOURCE_LIMIT = 0x05
ERROR_SESSION_NOT_FOUND = 0x06
ERROR_SESSION_CONFLICT = 0x07
ERROR_STREAM_LIMIT = 0x08
ERROR_CARRIER_CONFLICT = 0x0C


def session_cls(runtime, implementation: str):
    return runtime.Gate2Session if implementation == "reference" else runtime.IndependentSession


def snapshot(f: Fixture) -> Dict[str, object]:
    s = f.session
    return {
        "session_id": None if s.session_id is None else s.session_id.hex(),
        "protocol_version": s.protocol_version,
        "state": s.state,
        "highest_accepted": dict(s.highest_accepted),
        "active": {cid: c.generation for cid, c in s.carriers.items()},
        "streams": sorted(s.streams),
        "local_tx": sorted(s.local_tx),
        "peer_processed_through": s.peer_processed_through,
        "peer_retired_through": s.peer_retired_through,
    }


async def activate_raw_peer(f: Fixture, result: Dict[str, object], carrier_id: int) -> Peer:
    peer = result.get("peer")
    check(isinstance(peer, Peer), result)
    f.peers[carrier_id] = peer
    f.peer_next_txid[carrier_id] = f.peer_tx_cursor
    await wait_until(
        lambda: carrier_id in f.session.carriers,
        label=f"Carrier {carrier_id} activation",
    )
    await peer.recv_until(f.core.FRAME_SESSION_CREDIT)
    return peer


async def complete_candidate(
    f: Fixture,
    *,
    carrier_id: int,
    generation: int,
    action: int = 1,
    limits=None,
) -> Peer:
    result = await f.raw_candidate(
        action=action,
        carrier_id=carrier_id,
        generation=generation,
        limits=limits,
        complete=True,
    )
    check(result.get("finished_message_type") == f.core.MSG_SERVER_FINISHED, result)
    return await activate_raw_peer(f, result, carrier_id)


async def open_manual_client_stream(f: Fixture, p: Peer, stream_id: int = 1):
    runtime = f.runtime
    stream = runtime.StreamState(stream_id=stream_id, lifecycle="OPENING", accepted=False)
    f.session.streams[stream_id] = stream
    tx = f.session.alloc_tx(f.core.FRAME_STREAM_OPEN, stream_id)
    stream.opening_txid = tx.txid
    await f.session.send_tx(tx, f.session.carriers[p.carrier.carrier_id])
    opened = await p.recv_until(f.core.FRAME_STREAM_OPEN)
    check(int(opened["stream_id"]) == stream_id, opened)
    check(int(opened["transmission_id"]) == tx.txid, opened)
    return stream, tx


async def handshake_message_to_client(
    implementation: str,
    mode: str,
) -> Dict[str, object]:
    core, runtime = modules(implementation)
    key = secrets.token_bytes(32)
    limits = core.Limits(32768, 65536, 32, 4)
    trace = MemoryTrace(f"{implementation}-client-handshake-negative")
    cls = session_cls(runtime, implementation)
    session = cls("client", trace, "mandatory-endpoint", limits, 0)
    session.session_id = secrets.token_bytes(16)
    session.set_state("CREATING")
    seen = {"connections": 0, "client_init": 0}

    async def worker(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen["connections"] += 1
        try:
            magic = await reader.readexactly(4)
            check(magic == core.MAGIC, "client probe magic")
            version, version_raw = await core.read_varint(reader)
            preface = magic + version_raw
            msg, _, client_init = await core.read_message(reader)
            check(msg == core.MSG_CLIENT_INIT, "client probe CLIENT_INIT")
            seen["client_init"] += 1

            if mode == "reject":
                writer.write(core.encode_message(core.MSG_HANDSHAKE_REJECT, core.vi_enc(ERROR_SESSION_CONFLICT)))
                await writer.drain()
                writer.close()
                return

            if mode == "version-negotiation":
                body = core.vi_enc(1) + core.vi_enc(core.VERSION)
                writer.write(core.encode_message(core.MSG_VERSION_NEGOTIATION, body))
                await writer.drain()
                writer.close()
                return

            if mode == "late-version-negotiation":
                server_init = core.encode_server_init(secrets.token_bytes(32), limits)
                writer.write(server_init)
                await writer.drain()
                msg2, _, client_finished = await core.read_message(reader)
                check(msg2 == core.MSG_CLIENT_FINISHED, "late VN CLIENT_FINISHED")
                # We intentionally send VN after SERVER_INIT. The client must reject
                # this candidate rather than interpreting it as downgrade permission.
                body = core.vi_enc(1) + core.vi_enc(core.VERSION)
                writer.write(core.encode_message(core.MSG_VERSION_NEGOTIATION, body))
                await writer.drain()
                writer.close()
                return

            raise ProbeError(mode)
        finally:
            await asyncio.sleep(0)

    server = await asyncio.start_server(
        lambda r, w: asyncio.create_task(worker(r, w)),
        "127.0.0.1",
        0,
    )
    port = int((server.sockets or [])[0].getsockname()[1])
    before = {
        "state": session.state,
        "highest_accepted": dict(session.highest_accepted),
        "carriers": sorted(session.carriers),
        "protocol_version": session.protocol_version,
    }
    observed = ""
    try:
        try:
            await runtime.client_handshake(
                session,
                "127.0.0.1",
                port,
                key,
                0,
                1,
                0,
            )
        except Exception as exc:
            observed = type(exc).__name__
            if mode == "reject":
                check(isinstance(exc, runtime.HandshakeRejected), exc)
                check(exc.error_code == ERROR_SESSION_CONFLICT, exc.error_code)
            elif mode == "version-negotiation":
                check(isinstance(exc, runtime.VersionNegotiationReceived), exc)
                check(list(exc.versions) == [core.VERSION], exc.versions)
            elif mode == "late-version-negotiation":
                check(isinstance(exc, core.ProtocolError), exc)
            else:
                raise
        else:
            raise ProbeError(f"{mode} unexpectedly established")

        after = {
            "state": session.state,
            "highest_accepted": dict(session.highest_accepted),
            "carriers": sorted(session.carriers),
            "protocol_version": session.protocol_version,
        }
        check(before == after, (before, after))
        check(seen["connections"] == 1, seen)
        check(
            not any(
                x.get("event") == "carrier_established"
                for x in trace.events
            ),
            trace.events,
        )
        return {"exception": observed, "state": after, "connections": seen["connections"]}
    finally:
        server.close()
        await server.wait_closed()
        await session.cleanup()


async def case_join_limit_consistency(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        before = snapshot(f)
        changed = f.core.Limits(
            f.limits.max_frame_payload,
            32768,
            f.limits.max_streams,
            f.limits.max_carriers,
        )
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=96,
            generation=0,
            limits=changed,
            expected_error_code=ERROR_SESSION_CONFLICT,
        )
        check(snapshot(f) == before, (before, snapshot(f)))
        await f.ping(p, 0xB110)
        return {"reject": reject["error_code"], "state_unchanged": True}


async def case_session_protocol_version(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        f.session.supported_versions.add(5)
        before = snapshot(f)
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=96,
            generation=0,
            version=5,
            expected_error_code=ERROR_SESSION_CONFLICT,
        )
        check(snapshot(f) == before, (before, snapshot(f)))
        await f.ping(p, 0xB120)
        return {"reject": reject["error_code"], "session_version": f.session.protocol_version}


async def case_version_negotiation_server(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        result = await f.raw_candidate(
            action=0,
            carrier_id=1,
            generation=0,
            version=5,
        )
        check(result.get("message_type") == f.core.MSG_VERSION_NEGOTIATION, result)
        check(result.get("versions") == [f.core.VERSION], result)
        check(f.session.session_id is None, f.session.session_id)
        check(
            not any(x.get("event") == "handshake_recv" and x.get("stage") == "CLIENT_INIT" for x in f.trace.events),
            f.trace.events,
        )
        p = await f.establish(1, 0, 0)
        await f.ping(p, 0xB130)
        return {"versions": result["versions"], "pipelined_init_ignored": True}


async def case_version_negotiation_client(implementation: str) -> dict:
    pre = await handshake_message_to_client(implementation, "version-negotiation")
    late = await handshake_message_to_client(implementation, "late-version-negotiation")
    return {"pre_server_init": pre, "post_server_init": late}


async def case_create_collision(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        before = snapshot(f)
        reject = await f.expect_rejected_candidate(
            action=0,
            carrier_id=96,
            generation=0,
            expected_error_code=ERROR_SESSION_CONFLICT,
        )
        check(snapshot(f) == before, (before, snapshot(f)))
        await f.ping(p, 0xB160)
        return {"reject": reject["error_code"]}


async def case_stream_id_exhaustion(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        endpoint_carrier = f.session.carriers[1]
        f.session.next_stream_id = f.core.MAX_VARINT
        task = asyncio.create_task(f.session.open_next_stream(endpoint_carrier))
        opened = await p.recv_until(f.core.FRAME_STREAM_OPEN)
        check(int(opened["stream_id"]) == f.core.MAX_VARINT, opened)
        txid = int(opened["transmission_id"])
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN_OK,
            stream_id=f.core.MAX_VARINT,
            transmission_id=txid,
        )
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_CREDIT,
            stream_id=f.core.MAX_VARINT,
            consumed_offset=0,
            maximum_offset=1024 * 1024,
        )
        await asyncio.wait_for(task, timeout=2)
        try:
            await f.session.open_next_stream(endpoint_carrier)
        except RuntimeError:
            pass
        else:
            raise ProbeError("Stream ID wrapped after MAX_VARINT")
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == ERROR_RESOURCE_LIMIT, close)
        await wait_until(lambda: f.session.state == "CLOSED", label="Stream ID exhaustion close")
        return {"last_stream_id": f.core.MAX_VARINT, "close_error": close["error_code"]}


async def case_cross_carrier_order(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        st = await f.open_stream(p1)
        p2 = await f.establish(96, 0, 1)
        tx2 = f.next_peer_tx(96)
        await p2.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=1,
            transmission_id=tx2,
            data=b"B",
        )
        await p1.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(bytes(st.recv_data) == b"", st.recv_data)
        tx3 = f.next_peer_tx(1)
        await p1.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=0,
            transmission_id=tx3,
            data=b"A",
        )
        await p2.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(bytes(st.recv_data) == b"AB", st.recv_data)
        return {"delivered": st.recv_data.decode()}


async def case_carrier_limit(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=4) as f:
        client_limits = f.core.Limits(32768, 65536, 32, 2)
        created = await f.raw_candidate(
            action=0, carrier_id=1, generation=0, limits=client_limits, complete=True
        )
        p1 = await activate_raw_peer(f, created, 1)
        p2 = await complete_candidate(
            f, carrier_id=96, generation=0, limits=client_limits
        )
        check(f.session.effective_carrier_limit == 2, f.session.effective_carrier_limit)
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=97,
            generation=0,
            limits=client_limits,
            expected_error_code=ERROR_RESOURCE_LIMIT,
        )
        check(len(f.session.carriers) == 2, f.session.carriers)
        await f.ping(p1, 0xD601)
        await f.ping(p2, 0xD602)
        return {"effective_limit": 2, "reject": reject["error_code"]}


async def case_carrier_slot_release(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=2) as f:
        p1 = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        await p2.carrier.send_frame(
            f.core.FRAME_CARRIER_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason="slot-release",
        )
        await wait_until(lambda: 96 not in f.session.carriers, label="Carrier slot release")
        p3 = await complete_candidate(f, carrier_id=97, generation=0)
        check(sorted(f.session.carriers) == [1, 97], f.session.carriers)
        await f.ping(p1, 0xD701)
        await f.ping(p3, 0xD702)
        return {"active": sorted(f.session.carriers)}


async def case_active_replacement_limit(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=2) as f:
        old = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        new = await complete_candidate(f, carrier_id=1, generation=1)
        check(len(f.session.carriers) == 2, f.session.carriers)
        check(f.session.carriers[1].generation == 1, f.session.carriers[1].generation)
        await f.ping(new, 0xD801)
        await f.ping(p2, 0xD802)
        await old.expect_no(f.core.FRAME_PONG, timeout=0.15)
        return {"active": {k: v.generation for k, v in f.session.carriers.items()}}


async def case_inactive_replacement_limit(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=2) as f:
        p1 = await f.establish(1, 0, 0)
        await f.establish(96, 0, 1)
        p1.carrier.writer.close()
        await p1.carrier.writer.wait_closed()
        await wait_until(lambda: 1 not in f.session.carriers, label="inactive Carrier")
        await complete_candidate(f, carrier_id=97, generation=0)
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=1,
            generation=1,
            expected_error_code=ERROR_RESOURCE_LIMIT,
        )
        check(sorted(f.session.carriers) == [96, 97], f.session.carriers)
        return {"reject": reject["error_code"], "active": sorted(f.session.carriers)}


async def case_historical_carrier_capacity(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_carriers=2) as f:
        p1 = await f.establish(1, 0, 0)
        await f.establish(96, 0, 1)
        p1.carrier.writer.close()
        await p1.carrier.writer.wait_closed()
        await wait_until(lambda: 1 not in f.session.carriers, label="historical carrier loss")
        p97 = await complete_candidate(f, carrier_id=97, generation=0)
        check(sorted(f.session.carriers) == [96, 97], f.session.carriers)
        check(f.session.highest_accepted[1] == 0, f.session.highest_accepted)
        await f.ping(p97, 0xDA10)
        return {"historical_id": 1, "active": sorted(f.session.carriers)}


async def case_txid_exhaustion(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        st = await f.open_stream(p)
        f.session.next_txid = f.core.MAX_VARINT
        tx = f.session.alloc_tx(
            f.core.FRAME_STREAM_DATA,
            1,
            offset=0,
            data=b"X",
        )
        check(tx.txid == f.core.MAX_VARINT, tx.txid)
        await f.session.send_tx(tx, f.session.carriers[1])
        data = await p.recv_until(f.core.FRAME_STREAM_DATA)
        check(int(data["transmission_id"]) == f.core.MAX_VARINT, data)
        await p.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=f.core.MAX_VARINT,
            receiver_timestamp_us=0,
        )
        await wait_until(lambda: tx.settled, label="MAX Tx settlement")
        try:
            f.session.alloc_tx(f.core.FRAME_STREAM_FIN, 1, final_offset=1)
        except RuntimeError:
            pass
        else:
            raise ProbeError("Transmission ID wrapped")
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == ERROR_RESOURCE_LIMIT, close)
        return {"last_txid": tx.txid, "close_error": close["error_code"]}


async def case_retirement_watermark(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        await f.open_stream(p)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=0,
            transmission_id=tx,
            data=b"X",
        )
        await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(tx in f.session.peer_tx_confirmation, f.session.peer_tx_confirmation)
        await p.carrier.send_frame(f.core.FRAME_TRANSMISSION_RETIRE, retired_through=tx)
        await wait_until(lambda: f.session.peer_retired_through == tx, label="retire watermark")
        check(all(k > tx for k in f.session.peer_tx_confirmation), f.session.peer_tx_confirmation)
        return {"retired_through": tx}


async def case_confirmation_class(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        stream, tx = await open_manual_client_stream(f, p)
        await p.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx.txid,
            receiver_timestamp_us=0,
        )
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == ERROR_TRANSMISSION_ID, close)
        check(int(close["trigger_frame_type"]) == f.core.FRAME_TRANSMISSION_ACK, close)
        return {"close_error": close["error_code"]}


async def case_allocated_tx_survives_loss(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p1 = await f.establish()
        # Allocate an immutable reliable Transmission before any Attempt.
        tx = f.session.alloc_tx(f.core.FRAME_STREAM_DATA, 1, offset=0, data=b"Q")
        check(tx.attempts == 0 and not tx.settled, tx)
        p1.carrier.writer.close()
        await p1.carrier.writer.wait_closed()
        await wait_until(lambda: f.session.state == "DORMANT", label="client dormant")
        # Recover through a new first-use Carrier and attempt the same Tx identity.
        endpoint_task = asyncio.create_task(
            f.runtime.client_handshake(f.session, "127.0.0.1", int(f.port), f.key, 1, 96, 0)
        )
        cid, raw = await asyncio.wait_for(f.peer_queue.get(), timeout=2)
        check(cid == 96, cid)
        p2 = Peer(f.core, raw, [])
        f.peers[96] = p2
        await endpoint_task
        await p2.recv_until(f.core.FRAME_SESSION_CREDIT)
        check(f.session.local_tx[tx.txid] is tx and tx.attempts == 0, tx)
        await f.session.send_tx(tx, f.session.carriers[96])
        data = await p2.recv_until(f.core.FRAME_STREAM_DATA)
        check(int(data["transmission_id"]) == tx.txid, data)
        await p2.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=tx.txid,
            receiver_timestamp_us=0,
        )
        await wait_until(lambda: tx.settled, label="retained Tx settlement")
        return {"transmission_id": tx.txid, "attempts": tx.attempts}


async def case_stream_boundary(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        st = await f.open_stream(p)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=st.local_maximum - 1,
            transmission_id=tx,
            data=b"X",
        )
        await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(st.recv_committed == st.local_maximum, st.recv_committed)
        check(f.session.state == "ACTIVE", f.session.state)
        return {"committed": st.recv_committed}


async def case_reinjection_accounting(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        st = await f.open_stream(p1)
        p2 = await f.establish(96, 0, 1)
        tx = f.next_peer_tx(1)
        fields = dict(stream_id=1, offset=0, transmission_id=tx, data=b"R")
        await p1.carrier.send_frame(f.core.FRAME_STREAM_DATA, **fields)
        await wait_until(lambda: st.recv_committed == 1, label="first reinjection commitment")
        committed = st.recv_committed
        session_committed = f.session.session_recv_committed
        await p2.carrier.send_frame(f.core.FRAME_STREAM_DATA, **fields)
        await asyncio.sleep(0.02)
        check(st.recv_committed == committed == 1, st.recv_committed)
        check(f.session.session_recv_committed == session_committed == 1, f.session.session_recv_committed)
        check(bytes(st.recv_data) == b"R", st.recv_data)
        return {"stream_commitment": committed, "session_commitment": session_committed}


async def case_stream_consumed(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        st = await f.open_stream(p)
        fin = f.session.alloc_tx(f.core.FRAME_STREAM_FIN, 1, final_offset=0)
        st.send_final = 0
        st.local_terminal_txid = fin.txid
        await f.session.send_tx(fin, f.session.carriers[1])
        got = await p.recv_until(f.core.FRAME_STREAM_FIN)
        await p.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=int(got["transmission_id"]),
            receiver_timestamp_us=0,
        )
        await wait_until(lambda: fin.settled, label="FIN settlement")
        peer_tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_CONSUMED,
            stream_id=1,
            transmission_id=peer_tx,
            final_offset=0,
        )
        ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(ack["transmission_id"]) == peer_tx, ack)
        check(st.peer_final_consumed, st)
        return {"peer_consumed": True, "final_offset": 0}


async def case_credit_overtakes_open_ok(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        st, tx = await open_manual_client_stream(f, p)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_CREDIT,
            stream_id=1,
            consumed_offset=0,
            maximum_offset=4096,
        )
        await wait_until(lambda: st.accepted, label="credit acceptance evidence")
        check(st.lifecycle == "OPENING", st.lifecycle)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN_OK,
            stream_id=1,
            transmission_id=tx.txid,
        )
        await wait_until(lambda: st.lifecycle == "OPEN", label="OPEN_OK")
        check(f.session.state == "ACTIVE", f.session.state)
        return {"accepted_by_credit": True}


async def case_data_before_open_ok(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        await open_manual_client_stream(f, p)
        peer_tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=0,
            transmission_id=peer_tx,
            data=b"X",
        )
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == ERROR_STREAM_STATE, close)
        return {"close_error": close["error_code"]}


async def case_preopen_reset(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        tx1 = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_RESET_STREAM,
            stream_id=1,
            transmission_id=tx1,
            final_offset=0,
            stream_error_code=7,
        )
        await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(1 in f.session.opening_tombstones and 1 not in f.session.streams, f.session.opening_tombstones)
        tx2 = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN,
            stream_id=1,
            transmission_id=tx2,
        )
        reject = await p.recv_until(f.core.FRAME_STREAM_OPEN_REJECT)
        check(int(reject["error_code"]) == ERROR_STREAM_STATE, reject)
        return {"opening_tombstone": True, "reject": reject["error_code"]}


async def case_preopen_stop(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        st = await f.session.begin_preopen_cancel(1, f.session.carriers[1])
        stop = await p.recv_until(f.core.FRAME_STOP_SENDING)
        await p.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=int(stop["transmission_id"]),
            receiver_timestamp_us=0,
        )
        reset_tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_RESET_STREAM,
            stream_id=1,
            transmission_id=reset_tx,
            final_offset=0,
            stream_error_code=9,
        )
        await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(not st.accepted and st.recv_terminal_mode == "RESET", st)
        await f.session.send_pending_open(1, f.session.carriers[1])
        opened = await p.recv_until(f.core.FRAME_STREAM_OPEN)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN_REJECT,
            stream_id=1,
            transmission_id=int(opened["transmission_id"]),
            error_code=ERROR_STREAM_STATE,
        )
        await wait_until(lambda: 1 in f.session.opening_tombstones, label="opening cancellation tombstone")
        check(1 not in f.session.streams, f.session.streams)
        return {"cancelled": True}


async def case_acceptance_wins_cancel(implementation: str) -> dict:
    async with Fixture(implementation, "client") as f:
        p = await f.establish()
        st = await f.session.begin_preopen_cancel(1, f.session.carriers[1])
        stop = await p.recv_until(f.core.FRAME_STOP_SENDING)
        await p.carrier.send_frame(
            f.core.FRAME_TRANSMISSION_ACK,
            stream_id=1,
            transmission_id=int(stop["transmission_id"]),
            receiver_timestamp_us=0,
        )
        await f.session.send_pending_open(1, f.session.carriers[1])
        opened = await p.recv_until(f.core.FRAME_STREAM_OPEN)
        reset_tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_RESET_STREAM,
            stream_id=1,
            transmission_id=reset_tx,
            final_offset=0,
            stream_error_code=9,
        )
        await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN_OK,
            stream_id=1,
            transmission_id=int(opened["transmission_id"]),
        )
        await wait_until(lambda: st.accepted and st.lifecycle == "OPEN", label="acceptance wins")
        check(st.recv_terminal_mode == "RESET", st.recv_terminal_mode)
        return {"accepted": True, "receive_terminal": st.recv_terminal_mode}


async def prepare_tombstone(f: Fixture) -> Tuple[Peer, int]:
    p = await f.establish()
    await f.open_stream(p)
    tx = f.next_peer_tx(1)
    await p.carrier.send_frame(
        f.core.FRAME_STREAM_FIN,
        stream_id=1,
        transmission_id=tx,
        final_offset=0,
    )
    await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
    f.session.retire_stream_to_tombstone(1)
    return p, tx


async def case_tombstone_duplicate_terminal(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p, tx = await prepare_tombstone(f)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_FIN,
            stream_id=1,
            transmission_id=tx,
            final_offset=0,
        )
        ack = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(ack["transmission_id"]) == tx, ack)
        check(1 in f.session.tombstones and 1 not in f.session.streams, f.session.tombstones)
        return {"replayed_confirmation": True}


async def case_tombstone_conflicting_final(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p, _ = await prepare_tombstone(f)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_FIN,
            stream_id=1,
            transmission_id=tx,
            final_offset=1,
        )
        close = await p.recv_until(f.core.FRAME_SESSION_CLOSE)
        check(int(close["error_code"]) == ERROR_FINAL_SIZE, close)
        return {"close_error": close["error_code"]}


async def prepare_retired_identity(f: Fixture) -> Tuple[Peer, int]:
    p, terminal_tx = await prepare_tombstone(f)
    await p.carrier.send_frame(
        f.core.FRAME_TRANSMISSION_RETIRE,
        retired_through=terminal_tx,
    )
    await wait_until(lambda: f.session.peer_retired_through == terminal_tx, label="peer retire")
    f.session.compact_tombstone(1)
    return p, terminal_tx


async def case_retired_stale_no_recreate(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p, terminal_tx = await prepare_retired_identity(f)
        before = f.session.session_recv_committed
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=0,
            transmission_id=terminal_tx,
            data=b"X",
        )
        await asyncio.sleep(0.02)
        check(1 in f.session.retired_stream_ids and 1 not in f.session.streams, f.session.streams)
        check(f.session.session_recv_committed == before, f.session.session_recv_committed)
        return {"retired": True, "commitment": before}


async def case_stream_id_reuse(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p, _ = await prepare_retired_identity(f)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN,
            stream_id=1,
            transmission_id=tx,
        )
        reject = await p.recv_until(f.core.FRAME_STREAM_OPEN_REJECT)
        check(int(reject["error_code"]) == ERROR_STREAM_STATE, reject)
        check(1 not in f.session.streams, f.session.streams)
        return {"reject": reject["error_code"]}


async def case_tombstone_not_active_limit(implementation: str) -> dict:
    async with Fixture(implementation, "server", max_streams=1) as f:
        p, _ = await prepare_retired_identity(f)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_OPEN,
            stream_id=3,
            transmission_id=tx,
        )
        ok = await p.recv_until(f.core.FRAME_STREAM_OPEN_OK)
        check(int(ok["stream_id"]) == 3, ok)
        check(set(f.session.streams) == {3}, f.session.streams)
        return {"active_streams": sorted(f.session.streams), "retired": sorted(f.session.retired_stream_ids)}


async def case_terminal_confirmation_replay(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        await f.open_stream(p)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_FIN,
            stream_id=1,
            transmission_id=tx,
            final_offset=0,
        )
        # Do not consume the first ACK yet: from the sender's perspective it is lost.
        await asyncio.sleep(0.01)
        f.session.retire_stream_to_tombstone(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_FIN,
            stream_id=1,
            transmission_id=tx,
            final_offset=0,
        )
        first = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        second = await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(int(first["transmission_id"]) == tx == int(second["transmission_id"]), (first, second))
        check(tx in f.session.peer_tx_confirmation, f.session.peer_tx_confirmation)
        await p.carrier.send_frame(f.core.FRAME_TRANSMISSION_RETIRE, retired_through=tx)
        await wait_until(lambda: f.session.peer_retired_through == tx, label="terminal retire")
        check(tx not in f.session.peer_tx_confirmation, f.session.peer_tx_confirmation)
        f.session.compact_tombstone(1)
        return {"confirmation_replayed": True, "retired_through": tx}


async def cli_failed_candidate_preserves_established_session(implementation: str) -> dict:
    helper = Fixture(implementation, "server")
    module = "reference.gate2_runtime" if implementation == "reference" else "independent.gate_runtime"
    with tempfile.TemporaryDirectory(prefix=f"mpx4-{implementation}-candidate-") as tmp:
        tmp_path = Path(tmp)
        env = dict(os.environ)
        env["MPX4_REF_PSK_HEX"] = helper.key.hex()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-B",
            "-m",
            module,
            "server",
            "--scenario",
            "multi-carrier-reinjection",
            "--port",
            "0",
            "--timeout",
            "3",
            "--trace",
            str(tmp_path / "server.jsonl"),
            "--result",
            str(tmp_path / "result.json"),
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        peer = None
        try:
            check(proc.stdout is not None, "CLI server stdout unavailable")
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=3)
            ready = json.loads(line)
            helper.port = int(ready["port"])
            carrier = await helper._peer_client_handshake(0, 1, 0)
            peer = Peer(helper.core, carrier, [])
            await peer.recv_until(helper.core.FRAME_SESSION_CREDIT)
            await helper.ping(peer, 0x1502)
            result = await helper.raw_candidate(
                action=1,
                carrier_id=96,
                generation=0,
                corrupt_finished=True,
                complete=True,
            )
            check(result.get("finished_result") == "closed", result)
            await asyncio.sleep(0.10)
            check(proc.returncode is None, f"CLI server exited after failed candidate: {proc.returncode}")
            await helper.ping(peer, 0x1503)

            # A transport reset before authentication is candidate-local. It must
            # not poison session.fatal_error or make a later graceful Session close fail.
            _, rst_writer = await asyncio.open_connection("127.0.0.1", helper.port)
            rst_socket = rst_writer.get_extra_info("socket")
            check(rst_socket is not None, "RST candidate socket unavailable")
            rst_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            rst_writer.transport.abort()
            await asyncio.sleep(0.10)
            check(proc.returncode is None, f"CLI server exited after unauthenticated RST: {proc.returncode}")
            await helper.ping(peer, 0x1504)

            await peer.carrier.send_frame(
                helper.core.FRAME_SESSION_CLOSE,
                error_code=0,
                trigger_frame_type=0,
                reason="candidate-rst-regression",
            )
            rc = await asyncio.wait_for(proc.wait(), timeout=3)
            check(rc == 0, f"CLI server graceful exit after candidate RST returned {rc}")
            return {
                "candidate_closed": True,
                "rst_candidate_isolated": True,
                "server_still_running": True,
                "retained_carrier_ping": True,
                "graceful_exit": True,
            }
        finally:
            if peer is not None:
                peer.carrier.writer.close()
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            if proc.stderr is not None:
                await proc.stderr.read()


async def case_failed_candidate_nonmutating(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        before = snapshot(f)
        result = await f.raw_candidate(
            action=1,
            carrier_id=96,
            generation=0,
            corrupt_finished=True,
            complete=True,
        )
        check(result.get("finished_result") == "closed", result)
        await asyncio.sleep(0.02)
        check(snapshot(f) == before, (before, snapshot(f)))
        check(not f.session.pending_candidates, f.session.pending_candidates)
        await f.ping(p, 0x1501)
    cli = await cli_failed_candidate_preserves_established_session(implementation)
    return {"non_mutating": True, "cli": cli}


async def case_stale_generation(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        await f.establish(1, 0, 0)
        new = await complete_candidate(f, carrier_id=1, generation=1)
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=1,
            generation=0,
            expected_error_code=ERROR_CARRIER_CONFLICT,
        )
        check(f.session.highest_accepted[1] == 1, f.session.highest_accepted)
        await f.ping(new, 0x1601)
        return {"reject": reject["error_code"], "highest": 1}


async def case_first_generation_zero(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=96,
            generation=1,
            expected_error_code=ERROR_CARRIER_CONFLICT,
        )
        p96 = await complete_candidate(f, carrier_id=96, generation=0)
        await f.ping(p1, 0x1801)
        await f.ping(p96, 0x1802)
        return {"nonzero_first_reject": reject["error_code"], "accepted_generation": 0}


async def case_atomic_supersession(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        old = await f.establish(1, 0, 0)
        new = await complete_candidate(f, carrier_id=1, generation=1)
        check(f.session.carriers[1].generation == 1, f.session.carriers[1].generation)
        await f.ping(new, 0x1901)
        try:
            await old.carrier.send_frame(f.core.FRAME_PING, token=0x1902)
        except Exception:
            pass
        await old.expect_no(f.core.FRAME_PONG, timeout=0.15)
        return {"active_generation": 1}


async def case_replacement_preserves_session(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish(1, 0, 0)
        st = await f.open_stream(p)
        tx = f.next_peer_tx(1)
        await p.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=0,
            transmission_id=tx,
            data=b"A",
        )
        await p.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        before = {
            "stream_object": id(st),
            "peer_processed": f.session.peer_processed_through,
            "recv": bytes(st.recv_data),
        }
        new = await complete_candidate(f, carrier_id=1, generation=1)
        tx2 = f.next_peer_tx(1)
        await new.carrier.send_frame(
            f.core.FRAME_STREAM_DATA,
            stream_id=1,
            offset=1,
            transmission_id=tx2,
            data=b"B",
        )
        await new.recv_until(f.core.FRAME_TRANSMISSION_ACK)
        check(id(f.session.streams[1]) == before["stream_object"], "Stream state replaced")
        check(bytes(st.recv_data) == b"AB", st.recv_data)
        check(f.session.peer_processed_through >= before["peer_processed"], f.session.peer_processed_through)
        return {"recv": st.recv_data.decode(), "generation": f.session.carriers[1].generation}


async def case_simultaneous_candidates(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        await f.establish(1, 0, 0)
        core = f.core
        assert f.port is not None
        preface = core.MAGIC + core.vi_enc(core.VERSION)

        async def start_same_generation_candidate():
            reader, writer = await asyncio.open_connection("127.0.0.1", f.port)
            client_init = core.encode_client_init(
                f.session_id, 96, 0, secrets.token_bytes(32), f.limits, 1
            )
            writer.write(preface + client_init)
            await writer.drain()
            msg, _, server_init = await core.read_message(reader)
            check(msg == core.MSG_SERVER_INIT, msg)
            client_finished, expected_sf, _, prelim = core.derive_traffic(
                f.key, preface, client_init, server_init
            )
            return reader, writer, client_init, server_init, client_finished, expected_sf, prelim

        # Unauthenticated arrival order does not reserve Generation. Both
        # candidates are allowed to reach SERVER_INIT and remain HANDSHAKING.
        a = await start_same_generation_candidate()
        b = await start_same_generation_candidate()

        def pending_count() -> int:
            pending = f.session.pending_candidates
            if isinstance(pending, dict):
                return sum(int(x) for x in pending.values())
            return len(pending)

        await wait_until(
            lambda: pending_count() >= 2,
            label="two simultaneous handshaking candidates",
        )

        r1, w1, ci1, si1, cf1, expected_sf1, _ = a
        w1.write(cf1)
        await w1.drain()
        m1, _, sf1 = await core.read_message(r1)
        check(m1 == core.MSG_SERVER_FINISHED and sf1 == expected_sf1, (m1, sf1.hex()))
        _, server_limits = core.parse_server_init(si1)
        _, _, _, traffic = core.derive_traffic(
            f.key, preface, ci1, si1, client_finished=cf1, server_finished=sf1
        )
        p96 = Peer(
            core,
            core.Carrier(
                "client", r1, w1, NullTrace(), f.limits, server_limits,
                traffic.client_key, traffic.client_iv,
                traffic.server_key, traffic.server_iv,
                f.session_id, 96, 0, 0,
            ),
            [],
        )
        f.peers[96] = p96
        await wait_until(lambda: 96 in f.session.carriers, label="first authenticated candidate commit")
        await p96.recv_until(core.FRAME_SESSION_CREDIT)
        check(f.session.highest_accepted[96] == 0, f.session.highest_accepted)

        # The second equal-Generation candidate loses only when it reaches its
        # own authenticated commit point and observes H=0 already committed.
        r2, w2, _, _, cf2, _, _ = b
        w2.write(cf2)
        await w2.drain()
        m2, body2, _ = await core.read_message(r2)
        check(m2 == core.MSG_HANDSHAKE_REJECT, m2)
        code, pos = core.vi_dec(body2)
        check(pos == len(body2) and code == ERROR_CARRIER_CONFLICT, (code, pos, len(body2)))
        w2.close()

        check(f.session.highest_accepted[96] == 0, f.session.highest_accepted)
        check(f.session.carriers[96].generation == 0, f.session.carriers[96].generation)
        p96g1 = await complete_candidate(f, carrier_id=96, generation=1)
        await f.ping(p96g1, 0xB11)
        return {
            "loser_reject": code,
            "winner_generation": 0,
            "next_generation": 1,
            "both_reached_server_init": True,
        }


async def case_dormant_retirement(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p = await f.establish()
        p.carrier.writer.close()
        await p.carrier.writer.wait_closed()
        await wait_until(lambda: f.session.state == "DORMANT", label="DORMANT")
        f.session.retire_dormant()
        check(f.session.state == "CLOSED" and f.session.dormant_retired, f.session.state)
        reject = await f.expect_rejected_candidate(
            action=1,
            carrier_id=1,
            generation=1,
            expected_error_code=ERROR_SESSION_NOT_FOUND,
        )
        return {"reject": reject["error_code"], "retired": True}


async def case_carrier_close(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        await p1.carrier.send_frame(
            f.core.FRAME_CARRIER_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason="normal",
        )
        await wait_until(lambda: 1 not in f.session.carriers, label="CARRIER_CLOSE removal")
        check(f.session.state == "ACTIVE", f.session.state)
        await f.ping(p2, 0x2101)
        return {"remaining": sorted(f.session.carriers)}


async def case_bare_eof(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        p1.carrier.writer.close()
        await p1.carrier.writer.wait_closed()
        await wait_until(lambda: 1 not in f.session.carriers, label="bare EOF removal")
        check(f.session.state == "ACTIVE", f.session.state)
        await f.ping(p2, 0x2201)
        return {"remaining": sorted(f.session.carriers), "session_terminal": False}


async def case_session_close(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        await p1.carrier.send_frame(
            f.core.FRAME_SESSION_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason="peer-close",
        )
        await wait_until(lambda: f.session.state == "CLOSED", label="SESSION_CLOSE")
        check(not f.session.carriers, f.session.carriers)
        await f.expect_no_pong(p2, 0x301)
        return {"closed": True, "active_carriers": 0}


async def case_duplicate_session_close(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        await asyncio.gather(
            p1.carrier.send_frame(
                f.core.FRAME_SESSION_CLOSE,
                error_code=0,
                trigger_frame_type=0,
                reason="dup",
            ),
            p2.carrier.send_frame(
                f.core.FRAME_SESSION_CLOSE,
                error_code=0,
                trigger_frame_type=0,
                reason="dup",
            ),
            return_exceptions=True,
        )
        await wait_until(lambda: f.session.state == "CLOSED", label="duplicate SESSION_CLOSE")
        check(f.session.fatal_error is None, f.session.fatal_error)
        return {"closed": True, "idempotent": True}


async def case_tcp_half_close(implementation: str) -> dict:
    async with Fixture(implementation, "server") as f:
        p1 = await f.establish(1, 0, 0)
        p2 = await f.establish(96, 0, 1)
        sock = p1.carrier.writer.get_extra_info("socket")
        check(sock is not None, "missing TCP socket")
        sock.shutdown(socket.SHUT_WR)
        await wait_until(lambda: 1 not in f.session.carriers, label="half-close Carrier loss")
        check(f.session.state == "ACTIVE", f.session.state)
        check(f.session.session_close_received is None, f.session.session_close_received)
        await f.ping(p2, 0x501)
        return {"remaining": sorted(f.session.carriers), "session_terminal": False}


async def case_handshake_reject_no_mutation(implementation: str) -> dict:
    result = await handshake_message_to_client(implementation, "reject")
    return {"reject": result, "automatic_downgrade": False}


MANDATORY_CASES: Dict[str, Tuple[Tuple[str, ...], Callable[[str], Awaitable[dict]]]] = {
    "join-limit-consistency": (("B11",), case_join_limit_consistency),
    "session-protocol-version": (("B12",), case_session_protocol_version),
    "version-negotiation-server": (("B13",), case_version_negotiation_server),
    "version-negotiation-client": (("B13",), case_version_negotiation_client),
    "create-session-collision": (("B16",), case_create_collision),
    "stream-id-exhaustion": (("C7",), case_stream_id_exhaustion),
    "cross-carrier-order": (("D3",), case_cross_carrier_order),
    "carrier-limit": (("D6",), case_carrier_limit),
    "carrier-slot-release": (("D7",), case_carrier_slot_release),
    "active-replacement-limit": (("D8",), case_active_replacement_limit),
    "inactive-replacement-limit": (("D9",), case_inactive_replacement_limit),
    "historical-carrier-capacity": (("D10",), case_historical_carrier_capacity),
    "txid-exhaustion": (("E6",), case_txid_exhaustion),
    "retirement-watermark": (("E7",), case_retirement_watermark),
    "confirmation-class": (("E8",), case_confirmation_class),
    "allocated-tx-survives-loss": (("E10",), case_allocated_tx_survives_loss),
    "stream-boundary": (("F2",), case_stream_boundary),
    "reinjection-accounting": (("F4",), case_reinjection_accounting),
    "stream-consumed": (("G6",), case_stream_consumed),
    "credit-overtakes-open-ok": (("H1",), case_credit_overtakes_open_ok),
    "data-before-open-ok": (("H2",), case_data_before_open_ok),
    "preopen-reset": (("H3",), case_preopen_reset),
    "preopen-stop": (("H4",), case_preopen_stop),
    "acceptance-wins-cancel": (("H5",), case_acceptance_wins_cancel),
    "tombstone-terminal-duplicate": (("I1",), case_tombstone_duplicate_terminal),
    "tombstone-conflicting-final": (("I2",), case_tombstone_conflicting_final),
    "retired-stale-no-recreate": (("I3",), case_retired_stale_no_recreate),
    "stream-id-reuse": (("I4",), case_stream_id_reuse),
    "tombstone-not-active-limit": (("I5",), case_tombstone_not_active_limit),
    "terminal-confirmation-replay": (("I6",), case_terminal_confirmation_replay),
    "failed-candidate-nonmutating": (("J5",), case_failed_candidate_nonmutating),
    "stale-generation": (("J6",), case_stale_generation),
    "first-generation-zero": (("J8",), case_first_generation_zero),
    "atomic-supersession": (("J9",), case_atomic_supersession),
    "replacement-preserves-session": (("J10",), case_replacement_preserves_session),
    "simultaneous-candidates": (("J11",), case_simultaneous_candidates),
    "dormant-retirement": (("J15",), case_dormant_retirement),
    "carrier-close": (("K1",), case_carrier_close),
    "bare-eof": (("K2",), case_bare_eof),
    "session-close": (("K3",), case_session_close),
    "duplicate-session-close": (("K4",), case_duplicate_session_close),
    "tcp-half-close": (("K5",), case_tcp_half_close),
    "handshake-reject-no-mutation": (("L18",), case_handshake_reject_no_mutation),
}


async def amain(args: argparse.Namespace) -> dict:
    started = time.time()
    implementations = args.implementation or ["reference", "independent"]
    selected = args.case or list(MANDATORY_CASES)
    results = []
    for implementation in implementations:
        for case_name in selected:
            ids, func = MANDATORY_CASES[case_name]
            detail = await func(implementation)
            item = {
                "implementation": implementation,
                "case": case_name,
                "mandatory_ids": list(ids),
                "status": "PASS",
                "evidence_class": "endpoint-wire",
                "detail": detail,
            }
            results.append(item)
            print(
                f"mandatory-endpoint {implementation}/{case_name}: PASS "
                f"({','.join(ids)})",
                flush=True,
            )
    covered = sorted({mid for item in results for mid in item["mandatory_ids"]})
    return {
        "protocol": "MPX/4",
        "revision": "Draft 11",
        "suite": "formerly-model-only mandatory endpoint execution",
        "status": "PASS",
        "execution_count": len(results),
        "covered_mandatory_ids": covered,
        "cases": results,
        "duration_seconds": round(time.time() - started, 3),
        "claim_boundary": (
            "Each result executes the real runtime over loopback TCP/authenticated records, "
            "or a real runtime local-policy transition after wire-visible preconditions. "
            "No Mandatory oracle/state model is called."
        ),
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 endpoint execution for formerly model-only Mandatory cases")
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--implementation", action="append", choices=("reference", "independent"))
    p.add_argument("--case", action="append", choices=tuple(MANDATORY_CASES))
    return p


def main() -> int:
    args = parser().parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    path = args.out_dir / "endpoint-mandatory-report.json"
    try:
        report = asyncio.run(amain(args))
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"mandatory endpoint suite: PASS ({report['execution_count']} executions)")
        print(f"report: {path}")
        return 0
    except Exception as exc:
        path.write_text(
            json.dumps(
                {
                    "protocol": "MPX/4",
                    "revision": "Draft 11",
                    "suite": "formerly-model-only mandatory endpoint execution",
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
        print(f"mandatory endpoint suite: FAIL: {type(exc).__name__}: {exc}")
        print(f"report: {path}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
