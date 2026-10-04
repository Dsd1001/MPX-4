#!/usr/bin/env python3
"""CLI for source-isolated MPX/4 Draft 11 Implementation B."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional

from .core import (
    Carrier,
    FRAME_SESSION_CLOSE,
    Limits,
    MAGIC,
    MSG_CLIENT_FINISHED,
    MSG_CLIENT_INIT,
    MSG_SERVER_FINISHED,
    MSG_SERVER_INIT,
    PeerSession,
    Trace,
    VERSION,
    derive_traffic,
    encode_client_init,
    encode_server_init,
    parse_client_init,
    parse_server_init,
    read_message,
    read_varint,
    validate_finished,
    vi_enc,
)


def transport_key() -> bytes:
    raw = os.environ.get("MPX4_INTEROP_PSK_HEX") or os.environ.get("MPX4_REF_PSK_HEX", "")
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError("interop PSK must be hex") from exc
    if len(key) != 32:
        raise RuntimeError("interop PSK must encode 32 bytes")
    return key


async def write_raw(writer: asyncio.StreamWriter, data: bytes, chunk: int) -> None:
    if chunk > 0:
        for pos in range(0, len(data), chunk):
            writer.write(data[pos:pos+chunk])
            await writer.drain()
    else:
        writer.write(data)
        await writer.drain()


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    trace: Trace,
    key: bytes,
    limits: Limits,
    write_chunk: int,
) -> Carrier:
    sid = secrets.token_bytes(16)
    while sid == b"\x00" * 16:
        sid = secrets.token_bytes(16)
    nonce = secrets.token_bytes(32)
    preface = MAGIC + vi_enc(VERSION)
    client_init = encode_client_init(sid, 1, 0, nonce, limits, 0)
    await write_raw(writer, preface + client_init, write_chunk)
    trace.emit("handshake_send", stage="CLIENT_INIT", session_id=sid.hex(), carrier_id=1, generation=0)

    msg, _, server_init = await read_message(reader)
    if msg != MSG_SERVER_INIT:
        raise RuntimeError(f"expected SERVER_INIT, got {msg}")
    server_nonce, server_limits = parse_server_init(server_init)
    trace.emit(
        "handshake_recv",
        stage="SERVER_INIT",
        session_id=sid.hex(),
        carrier_id=1,
        generation=0,
        server_nonce_sha256=hashlib.sha256(server_nonce).hexdigest(),
    )

    client_finished, expected_server_finished, h0, prelim = derive_traffic(
        key, preface, client_init, server_init
    )
    await write_raw(writer, client_finished, write_chunk)
    trace.emit("handshake_send", stage="CLIENT_FINISHED", session_id=sid.hex(), carrier_id=1, generation=0)

    msg, _, server_finished = await read_message(reader)
    if msg != MSG_SERVER_FINISHED:
        raise RuntimeError(f"expected SERVER_FINISHED, got {msg}")
    h1 = hashlib.sha256(preface + client_init + server_init + client_finished).digest()
    validate_finished(server_finished, MSG_SERVER_FINISHED, prelim.server_finished_key, h1)
    if server_finished != expected_server_finished:
        raise RuntimeError("SERVER_FINISHED is valid but non-canonical")
    _, _, _, traffic = derive_traffic(
        key,
        preface,
        client_init,
        server_init,
        client_finished=client_finished,
        server_finished=server_finished,
    )
    trace.emit("handshake_established", session_id=sid.hex(), carrier_id=1, generation=0, protocol_version=VERSION)
    return Carrier(
        "client",
        reader,
        writer,
        trace,
        limits,
        server_limits,
        traffic.client_key,
        traffic.client_iv,
        traffic.server_key,
        traffic.server_iv,
        sid,
        1,
        0,
        write_chunk,
    )


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    trace: Trace,
    key: bytes,
    limits: Limits,
    write_chunk: int,
) -> Carrier:
    if await reader.readexactly(4) != MAGIC:
        raise RuntimeError("bad MPX magic")
    version, version_raw = await read_varint(reader)
    if version != VERSION:
        raise RuntimeError(f"unsupported Protocol Version {version}")
    preface = MAGIC + version_raw

    msg, _, client_init = await read_message(reader)
    if msg != MSG_CLIENT_INIT:
        raise RuntimeError(f"expected CLIENT_INIT, got {msg}")
    init = parse_client_init(client_init)
    if init.session_action != 0 or init.generation != 0:
        raise RuntimeError("Gate 4 basic server expects CREATE Generation 0")
    trace.emit(
        "handshake_recv",
        stage="CLIENT_INIT",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
    )

    snonce = secrets.token_bytes(32)
    server_init = encode_server_init(snonce, limits)
    await write_raw(writer, server_init, write_chunk)
    trace.emit(
        "handshake_send",
        stage="SERVER_INIT",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
        server_nonce_sha256=hashlib.sha256(snonce).hexdigest(),
    )

    expected_cf, expected_sf, h0, prelim = derive_traffic(key, preface, client_init, server_init)
    msg, _, client_finished = await read_message(reader)
    if msg != MSG_CLIENT_FINISHED:
        raise RuntimeError(f"expected CLIENT_FINISHED, got {msg}")
    validate_finished(client_finished, MSG_CLIENT_FINISHED, prelim.client_finished_key, h0)
    if client_finished != expected_cf:
        raise RuntimeError("CLIENT_FINISHED is valid but non-canonical")

    _, server_finished, _, traffic = derive_traffic(
        key, preface, client_init, server_init, client_finished=client_finished
    )
    if server_finished != expected_sf:
        raise RuntimeError("internal SERVER_FINISHED mismatch")
    await write_raw(writer, server_finished, write_chunk)
    trace.emit("handshake_send", stage="SERVER_FINISHED", session_id=init.session_id.hex(), carrier_id=init.carrier_id, generation=init.generation)
    trace.emit("handshake_established", session_id=init.session_id.hex(), carrier_id=init.carrier_id, generation=init.generation, protocol_version=VERSION)

    return Carrier(
        "server",
        reader,
        writer,
        trace,
        limits,
        init.client_limits,
        traffic.server_key,
        traffic.server_iv,
        traffic.client_key,
        traffic.client_iv,
        init.session_id,
        init.carrier_id,
        init.generation,
        write_chunk,
    )


async def cleanup(session: Optional[PeerSession]) -> None:
    if session is None:
        return
    tasks = [t for t in [session.receiver_task, *session.sender_tasks] if t is not None]
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_client(args: argparse.Namespace, trace: Trace, key: bytes) -> dict:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(args.host, args.port), timeout=args.timeout)
    session: Optional[PeerSession] = None
    try:
        carrier = await asyncio.wait_for(
            client_handshake(reader, writer, trace, key, args.limits, args.write_chunk),
            timeout=args.timeout,
        )
        session = PeerSession("client", carrier, trace, args.streams, args.bytes_per_stream)
        await session.send_session_credit()
        session.receiver_task = asyncio.create_task(session.receive_loop())
        await session.open_streams()
        await session.wait_complete()
        if session.outstanding:
            raise RuntimeError(f"independent client outstanding: {sorted(session.outstanding)}")
        await carrier.send_frame(FRAME_SESSION_CLOSE, error_code=0, trigger_frame_type=0, reason="gate4-complete")
        trace.emit("frame_send", **carrier.base_trace(), frame_type="SESSION_CLOSE", error_code=0)
        session.close_seen.set()
        writer.close()
        await writer.wait_closed()
        if session.receiver_task is not None:
            await asyncio.wait_for(session.receiver_task, timeout=args.timeout)
        result = session.result()
        result.update({"status": "PASS", "gate": "Gate 4", "implementation": "independent-b", "mode": "independent-client"})
        return result
    finally:
        await cleanup(session)
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()


async def run_server_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    trace: Trace,
    key: bytes,
) -> dict:
    session: Optional[PeerSession] = None
    try:
        carrier = await asyncio.wait_for(
            server_handshake(reader, writer, trace, key, args.limits, args.write_chunk),
            timeout=args.timeout,
        )
        session = PeerSession("server", carrier, trace, args.streams, args.bytes_per_stream)
        await session.send_session_credit()
        session.receiver_task = asyncio.create_task(session.receive_loop())
        await asyncio.wait_for(session.streams_ready.wait(), timeout=args.timeout)
        await session.wait_complete()
        if session.outstanding:
            raise RuntimeError(f"independent server outstanding: {sorted(session.outstanding)}")
        await asyncio.wait_for(session.close_seen.wait(), timeout=args.timeout)
        if session.receiver_task is not None:
            await asyncio.wait_for(session.receiver_task, timeout=args.timeout)
        result = session.result()
        result.update({"status": "PASS", "gate": "Gate 4", "implementation": "independent-b", "mode": "independent-server"})
        writer.close()
        await writer.wait_closed()
        return result
    finally:
        await cleanup(session)
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()


async def run_server(args: argparse.Namespace, trace: Trace, key: bytes) -> dict:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[dict] = loop.create_future()
    accepted = False

    async def worker(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal accepted
        if accepted:
            writer.close()
            await writer.wait_closed()
            return
        accepted = True
        try:
            result = await run_server_connection(reader, writer, args, trace, key)
        except Exception as exc:
            if not future.done():
                future.set_exception(exc)
        else:
            if not future.done():
                future.set_result(result)

    def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        asyncio.create_task(worker(reader, writer))

    server = await asyncio.start_server(callback, args.host, args.port)
    sockets = server.sockets or []
    if not sockets:
        raise RuntimeError("independent server has no socket")
    port = int(sockets[0].getsockname()[1])
    print(json.dumps({"event": "READY", "host": args.host, "port": port}), flush=True)
    trace.emit("listener_ready", host=args.host, port=port)
    try:
        return await asyncio.wait_for(future, timeout=args.timeout * 4)
    finally:
        server.close()
        await server.wait_closed()


def write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 source-isolated Implementation B endpoint")
    p.add_argument("role", choices=("client", "server"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--trace", type=Path, required=True)
    p.add_argument("--result", type=Path, required=True)
    p.add_argument("--streams", type=int, default=16)
    p.add_argument("--bytes-per-stream", type=int, default=65536)
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--write-chunk", type=int, default=0)
    p.add_argument("--max-frame-payload", type=int, default=32768)
    p.add_argument("--max-record-size", type=int, default=65536)
    p.add_argument("--max-streams", type=int, default=32)
    p.add_argument("--max-carriers", type=int, default=2)
    return p


async def amain(args: argparse.Namespace) -> int:
    if args.streams <= 0 or args.bytes_per_stream <= 0 or args.streams > args.max_streams:
        raise RuntimeError("invalid test profile")
    args.limits = Limits(args.max_frame_payload, args.max_record_size, args.max_streams, args.max_carriers)
    args.limits.validate()
    key = transport_key()
    trace = Trace(args.trace, args.role)
    try:
        result = await (run_server(args, trace, key) if args.role == "server" else run_client(args, trace, key))
        write_result(args.result, result)
        return 0
    except Exception as exc:
        trace.emit("endpoint_error", error_type=type(exc).__name__, error=str(exc))
        write_result(args.result, {"status": "FAIL", "role": args.role, "implementation": "independent-b", "error_type": type(exc).__name__, "error": str(exc)})
        print(f"independent {args.role} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        trace.close()


def main() -> int:
    return asyncio.run(amain(parser().parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
