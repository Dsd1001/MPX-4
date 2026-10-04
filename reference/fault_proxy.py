#!/usr/bin/env python3
"""Transport-layer fault proxy for MPX/4 reference tests.

This proxy only injects faults that make sense for TCP byte streams:
fragmented forwarding, delay/backpressure, and connection abort. It does not
"drop a Secure Record and continue" because that would intentionally corrupt
the ordered byte stream and desynchronize implicit Record sequence numbers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Optional


class ProxyTrace:
    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.seq = 0
        self.file = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.file = path.open("w", encoding="utf-8")

    def emit(self, event: str, **fields: object) -> None:
        if self.file is None:
            return
        self.seq += 1
        record = {
            "event_seq": self.seq,
            "monotonic_ns": time.monotonic_ns(),
            "event": event,
            **fields,
        }
        self.file.write(json.dumps(record, sort_keys=True) + "\n")
        self.file.flush()

    def close(self) -> None:
        if self.file is not None:
            self.file.close()


async def forward(
    direction: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    trace: ProxyTrace,
    max_chunk: int,
    delay_ms: float,
    abort_after: int,
    abort_event: asyncio.Event,
) -> None:
    forwarded = 0
    while not abort_event.is_set():
        data = await reader.read(65536)
        if not data:
            trace.emit("eof", direction=direction, forwarded_bytes=forwarded)
            try:
                writer.write_eof()
                await writer.drain()
            except (AttributeError, OSError, RuntimeError):
                pass
            return

        pieces = [data]
        if max_chunk > 0:
            pieces = [data[i : i + max_chunk] for i in range(0, len(data), max_chunk)]

        for piece in pieces:
            if abort_after > 0 and forwarded + len(piece) > abort_after:
                allowed = max(0, abort_after - forwarded)
                if allowed:
                    writer.write(piece[:allowed])
                    await writer.drain()
                    forwarded += allowed
                trace.emit(
                    "fault_abort",
                    direction=direction,
                    forwarded_bytes=forwarded,
                    configured_after=abort_after,
                )
                abort_event.set()
                return
            writer.write(piece)
            await writer.drain()
            forwarded += len(piece)
            trace.emit("forward", direction=direction, bytes=len(piece), forwarded_bytes=forwarded)
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)


async def proxy_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    trace: ProxyTrace,
) -> None:
    upstream_reader, upstream_writer = await asyncio.open_connection(args.target_host, args.target_port)
    abort_event = asyncio.Event()
    trace.emit(
        "connected",
        target_host=args.target_host,
        target_port=args.target_port,
        client_peer=str(client_writer.get_extra_info("peername")),
    )

    tasks = [
        asyncio.create_task(
            forward(
                "client_to_server",
                client_reader,
                upstream_writer,
                trace,
                args.max_chunk,
                args.delay_ms,
                args.abort_after_c2s,
                abort_event,
            )
        ),
        asyncio.create_task(
            forward(
                "server_to_client",
                upstream_reader,
                client_writer,
                trace,
                args.max_chunk,
                args.delay_ms,
                args.abort_after_s2c,
                abort_event,
            )
        ),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if abort_event.is_set():
            for task in pending:
                task.cancel()
        else:
            await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        upstream_writer.close()
        client_writer.close()
        await asyncio.gather(
            upstream_writer.wait_closed(),
            client_writer.wait_closed(),
            return_exceptions=True,
        )
        trace.emit("connection_closed", aborted=abort_event.is_set())


async def amain(args: argparse.Namespace) -> int:
    trace = ProxyTrace(args.trace)
    done = asyncio.Event()
    failure: list[BaseException] = []

    async def worker(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await proxy_connection(reader, writer, args, trace)
        except BaseException as exc:
            failure.append(exc)
            trace.emit("proxy_error", error_type=type(exc).__name__, error=str(exc))
        finally:
            done.set()

    def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        asyncio.create_task(worker(reader, writer))

    server = await asyncio.start_server(callback, args.listen_host, args.listen_port)
    sockets = server.sockets or []
    if not sockets:
        raise RuntimeError("proxy has no listening socket")
    port = int(sockets[0].getsockname()[1])
    print(json.dumps({"event": "READY", "host": args.listen_host, "port": port}), flush=True)
    trace.emit("listener_ready", host=args.listen_host, port=port)

    try:
        await asyncio.wait_for(done.wait(), timeout=args.timeout)
    finally:
        server.close()
        await server.wait_closed()
        trace.close()

    if failure:
        raise failure[0]
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MPX/4 reference TCP fault proxy")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--max-chunk", type=int, default=0)
    parser.add_argument("--delay-ms", type=float, default=0.0)
    parser.add_argument("--abort-after-c2s", type=int, default=0)
    parser.add_argument("--abort-after-s2c", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--trace", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(amain(args))
    except Exception as exc:
        print(f"fault proxy failed: {type(exc).__name__}: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
