#!/usr/bin/env python3
"""CLI entrypoint for the MPX/4 Draft 11 reference endpoint."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional, Tuple

from .mpx4_core import (
    Carrier,
    FRAME_SESSION_CLOSE,
    Limits,
    MAGIC,
    MSG_CLIENT_FINISHED,
    MSG_CLIENT_INIT,
    MSG_SERVER_FINISHED,
    MSG_SERVER_INIT,
    ReferenceSession,
    Trace,
    VERSION,
    derive_traffic,
    encode_client_init,
    encode_message,
    encode_server_init,
    parse_client_init,
    parse_server_init,
    read_message,
    read_varint,
    validate_finished,
    vi_enc,
)


def _transport_key_from_env() -> bytes:
    value = os.environ.get("MPX4_REF_PSK_HEX", "")
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError("MPX4_REF_PSK_HEX must be hex") from exc
    if len(key) != 32:
        raise RuntimeError("MPX4_REF_PSK_HEX must encode exactly 32 bytes")
    return key


async def _write_raw(writer: asyncio.StreamWriter, data: bytes, chunk: int) -> None:
    if chunk > 0:
        for i in range(0, len(data), chunk):
            writer.write(data[i : i + chunk])
            await writer.drain()
    else:
        writer.write(data)
        await writer.drain()


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    trace: Trace,
    transport_key: bytes,
    local_limits: Limits,
    write_chunk: int,
) -> Carrier:
    session_id = secrets.token_bytes(16)
    while session_id == b"\x00" * 16:
        session_id = secrets.token_bytes(16)
    client_nonce = secrets.token_bytes(32)
    carrier_id = 1
    generation = 0
    preface = MAGIC + vi_enc(VERSION)
    client_init = encode_client_init(
        session_id=session_id,
        carrier_id=carrier_id,
        generation=generation,
        client_nonce=client_nonce,
        limits=local_limits,
        session_action=0,
    )

    await _write_raw(writer, preface + client_init, write_chunk)
    trace.emit(
        "handshake_send",
        stage="CLIENT_INIT",
        session_id=session_id.hex(),
        carrier_id=carrier_id,
        generation=generation,
        bytes=len(preface + client_init),
    )

    message_type, _, server_init = await read_message(reader)
    if message_type != MSG_SERVER_INIT:
        raise RuntimeError(f"expected SERVER_INIT, got {message_type}")
    server_nonce, server_limits = parse_server_init(server_init)
    trace.emit(
        "handshake_recv",
        stage="SERVER_INIT",
        session_id=session_id.hex(),
        carrier_id=carrier_id,
        generation=generation,
        server_nonce_sha256=hashlib.sha256(server_nonce).hexdigest(),
    )

    client_finished, expected_server_finished, h0, prelim = derive_traffic(
        transport_key,
        preface,
        client_init,
        server_init,
    )
    await _write_raw(writer, client_finished, write_chunk)
    trace.emit(
        "handshake_send",
        stage="CLIENT_FINISHED",
        session_id=session_id.hex(),
        carrier_id=carrier_id,
        generation=generation,
    )

    message_type, _, server_finished = await read_message(reader)
    if message_type != MSG_SERVER_FINISHED:
        raise RuntimeError(f"expected SERVER_FINISHED, got {message_type}")
    h1 = hashlib.sha256(preface + client_init + server_init + client_finished).digest()
    validate_finished(
        server_finished,
        MSG_SERVER_FINISHED,
        prelim.server_finished_key,
        h1,
    )
    if server_finished != expected_server_finished:
        raise RuntimeError("SERVER_FINISHED is valid but not canonical for the transcript")

    _, _, _, traffic = derive_traffic(
        transport_key,
        preface,
        client_init,
        server_init,
        client_finished=client_finished,
        server_finished=server_finished,
    )
    trace.emit(
        "handshake_established",
        session_id=session_id.hex(),
        carrier_id=carrier_id,
        generation=generation,
        protocol_version=VERSION,
    )
    return Carrier(
        role="client",
        reader=reader,
        writer=writer,
        trace=trace,
        local_limits=local_limits,
        peer_limits=server_limits,
        send_key=traffic.client_key,
        send_iv=traffic.client_iv,
        recv_key=traffic.server_key,
        recv_iv=traffic.server_iv,
        session_id=session_id,
        carrier_id=carrier_id,
        generation=generation,
        write_chunk=write_chunk,
    )


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    trace: Trace,
    transport_key: bytes,
    local_limits: Limits,
    write_chunk: int,
) -> Carrier:
    magic = await reader.readexactly(4)
    if magic != MAGIC:
        raise RuntimeError("invalid MPX magic")
    version, version_raw = await read_varint(reader)
    if version != VERSION:
        raise RuntimeError(f"unsupported Protocol Version {version}")
    preface = magic + version_raw

    message_type, _, client_init = await read_message(reader)
    if message_type != MSG_CLIENT_INIT:
        raise RuntimeError(f"expected CLIENT_INIT, got {message_type}")
    init = parse_client_init(client_init)
    if init.session_action != 0:
        raise RuntimeError("Gate 1 reference server accepts CREATE only")
    if init.generation != 0:
        raise RuntimeError("first Carrier generation must be zero")
    trace.emit(
        "handshake_recv",
        stage="CLIENT_INIT",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
    )

    server_nonce = secrets.token_bytes(32)
    server_init = encode_server_init(server_nonce, local_limits)
    await _write_raw(writer, server_init, write_chunk)
    trace.emit(
        "handshake_send",
        stage="SERVER_INIT",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
        server_nonce_sha256=hashlib.sha256(server_nonce).hexdigest(),
    )

    expected_client_finished, server_finished_template, h0, prelim = derive_traffic(
        transport_key,
        preface,
        client_init,
        server_init,
    )

    message_type, _, client_finished = await read_message(reader)
    if message_type != MSG_CLIENT_FINISHED:
        raise RuntimeError(f"expected CLIENT_FINISHED, got {message_type}")
    validate_finished(
        client_finished,
        MSG_CLIENT_FINISHED,
        prelim.client_finished_key,
        h0,
    )
    if client_finished != expected_client_finished:
        raise RuntimeError("CLIENT_FINISHED is valid but not canonical for the transcript")

    _, server_finished, _, traffic = derive_traffic(
        transport_key,
        preface,
        client_init,
        server_init,
        client_finished=client_finished,
    )
    if server_finished != server_finished_template:
        raise RuntimeError("internal SERVER_FINISHED derivation mismatch")
    await _write_raw(writer, server_finished, write_chunk)
    trace.emit(
        "handshake_send",
        stage="SERVER_FINISHED",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
    )
    trace.emit(
        "handshake_established",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
        protocol_version=VERSION,
    )

    return Carrier(
        role="server",
        reader=reader,
        writer=writer,
        trace=trace,
        local_limits=local_limits,
        peer_limits=init.client_limits,
        send_key=traffic.server_key,
        send_iv=traffic.server_iv,
        recv_key=traffic.client_key,
        recv_iv=traffic.client_iv,
        session_id=init.session_id,
        carrier_id=init.carrier_id,
        generation=init.generation,
        write_chunk=write_chunk,
    )


async def _cleanup_session_tasks(session: Optional[ReferenceSession]) -> None:
    if session is None:
        return
    tasks = [task for task in [session.receive_task, *session.sender_tasks] if task is not None]
    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_client(args: argparse.Namespace, trace: Trace, key: bytes) -> dict:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(args.host, args.port),
        timeout=args.timeout,
    )
    session: Optional[ReferenceSession] = None
    try:
        carrier = await asyncio.wait_for(
            client_handshake(
                reader,
                writer,
                trace,
                key,
                args.limits,
                args.write_chunk,
            ),
            timeout=args.timeout,
        )
        session = ReferenceSession(
            role="client",
            carrier=carrier,
            trace=trace,
            stream_count=args.streams,
            bytes_per_stream=args.bytes_per_stream,
        )
        await session.send_initial_session_credit()
        session.receive_task = asyncio.create_task(session.run_receiver())
        await session.open_streams()
        await session.wait_application_complete()
        if session.outstanding:
            raise RuntimeError(f"client has outstanding reliable Transmissions: {sorted(session.outstanding)}")

        await carrier.send_frame(
            FRAME_SESSION_CLOSE,
            error_code=0,
            trigger_frame_type=0,
            reason="gate1-complete",
        )
        trace.emit(
            "frame_send",
            **carrier.base_trace(),
            frame_type="SESSION_CLOSE",
            error_code=0,
        )
        session.session_close_event.set()
        writer.close()
        await writer.wait_closed()
        if session.receive_task:
            await asyncio.wait_for(session.receive_task, timeout=args.timeout)

        result = session.result()
        result.update({"status": "PASS", "gate": "Gate 1", "mode": "reference-client"})
        return result
    finally:
        await _cleanup_session_tasks(session)
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
    session: Optional[ReferenceSession] = None
    try:
        carrier = await asyncio.wait_for(
            server_handshake(
            reader,
            writer,
            trace,
            key,
            args.limits,
            args.write_chunk,
        ),
            timeout=args.timeout,
        )
        session = ReferenceSession(
            role="server",
        carrier=carrier,
        trace=trace,
        stream_count=args.streams,
            bytes_per_stream=args.bytes_per_stream,
        )
        await session.send_initial_session_credit()
        session.receive_task = asyncio.create_task(session.run_receiver())

        await asyncio.wait_for(session.streams_ready_event.wait(), timeout=args.timeout)
        await session.wait_application_complete()
        if session.outstanding:
            raise RuntimeError(f"server has outstanding reliable Transmissions: {sorted(session.outstanding)}")

        await asyncio.wait_for(session.session_close_event.wait(), timeout=args.timeout)
        if session.receive_task:
            await asyncio.wait_for(session.receive_task, timeout=args.timeout)
        result = session.result()
        result.update({"status": "PASS", "gate": "Gate 1", "mode": "reference-server"})
        writer.close()
        await writer.wait_closed()
        return result
    finally:
        await _cleanup_session_tasks(session)
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()


async def run_server(args: argparse.Namespace, trace: Trace, key: bytes) -> dict:
    loop = asyncio.get_running_loop()
    result_future: asyncio.Future[dict] = loop.create_future()
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
            if not result_future.done():
                result_future.set_exception(exc)
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
        else:
            if not result_future.done():
                result_future.set_result(result)

    def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        asyncio.create_task(worker(reader, writer))

    server = await asyncio.start_server(callback, args.host, args.port)
    sockets = server.sockets or []
    if not sockets:
        raise RuntimeError("server has no listening socket")
    port = int(sockets[0].getsockname()[1])
    print(json.dumps({"event": "READY", "host": args.host, "port": port}), flush=True)
    trace.emit("listener_ready", host=args.host, port=port)
    try:
        return await asyncio.wait_for(result_future, timeout=args.timeout * 4)
    finally:
        server.close()
        await server.wait_closed()


def write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MPX/4 Draft 11 reference endpoint")
    parser.add_argument("role", choices=("client", "server"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--streams", type=int, default=16)
    parser.add_argument("--bytes-per-stream", type=int, default=65536)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--write-chunk", type=int, default=0)
    parser.add_argument("--max-frame-payload", type=int, default=32768)
    parser.add_argument("--max-record-size", type=int, default=65536)
    parser.add_argument("--max-streams", type=int, default=32)
    parser.add_argument("--max-carriers", type=int, default=2)
    return parser


async def _amain(args: argparse.Namespace) -> int:
    if args.streams <= 0:
        raise RuntimeError("--streams must be positive")
    if args.bytes_per_stream <= 0:
        raise RuntimeError("--bytes-per-stream must be positive")
    if args.streams > args.max_streams:
        raise RuntimeError("--streams exceeds local MAX_STREAMS")
    args.limits = Limits(
        max_frame_payload=args.max_frame_payload,
        max_record_size=args.max_record_size,
        max_streams=args.max_streams,
        max_carriers=args.max_carriers,
    )
    args.limits.validate()
    key = _transport_key_from_env()
    trace = Trace(args.trace, args.role)
    try:
        if args.role == "server":
            result = await run_server(args, trace, key)
        else:
            result = await run_client(args, trace, key)
        write_result(args.result, result)
        return 0
    except Exception as exc:
        trace.emit("endpoint_error", error_type=type(exc).__name__, error=str(exc))
        write_result(
            args.result,
            {
                "status": "FAIL",
                "role": args.role,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        print(f"{args.role} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        trace.close()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
