#!/usr/bin/env python3
"""Focused tests for the executable basic-runtime optimizations."""

from __future__ import annotations

import unittest
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from independent import core as independent_core
from reference import mpx4_core as reference_core


class RuntimeOptimizationTests(unittest.TestCase):
    def test_overlapping_fragments_are_checked_and_reassembled(self) -> None:
        for module in (reference_core, independent_core):
            store = module.SegmentStore()
            store.insert(4, b"ef")
            store.insert(2, b"cdef")
            store.insert(0, b"abcd")
            result = bytearray()
            offset = 0
            while True:
                chunk = store.pop_contiguous(offset)
                if chunk is None:
                    break
                result.extend(chunk)
                offset += len(chunk)
            self.assertEqual(bytes(result), b"abcdef", module.__name__)

            store = module.SegmentStore()
            store.insert(4, b"ef")
            with self.assertRaises(module.ProtocolError):
                store.insert(2, b"cdXX")

    def test_fragment_queue_handles_many_out_of_order_ranges(self) -> None:
        for module in (reference_core, independent_core):
            store = module.SegmentStore()
            expected = bytes(range(256)) * 4
            for start in range(0, len(expected), 17):
                end = min(len(expected), start + 31)
                store.insert(start, expected[start:end])
            result = bytearray()
            offset = 0
            while True:
                chunk = store.pop_contiguous(offset)
                if chunk is None:
                    break
                result.extend(chunk)
                offset += len(chunk)
            self.assertEqual(bytes(result), expected, module.__name__)

    def test_data_chunk_respects_record_and_frame_limits(self) -> None:
        for module in (reference_core, independent_core):
            carrier = object.__new__(module.Carrier)
            carrier.peer_limits = module.Limits(max_frame_payload=32768, max_record_size=1024)
            size = carrier.max_stream_data_payload(1, 1, 0)
            self.assertGreater(size, 0, module.__name__)
            body = module.frame_body(
                module.FRAME_STREAM_DATA,
                stream_id=1,
                offset=0,
                transmission_id=1,
                data=b"x" * size,
            )
            self.assertLessEqual(
                len(module.encode_frame(module.FRAME_STREAM_DATA, body)),
                carrier.peer_limits.max_record_size,
                module.__name__,
            )
            self.assertLess(size, carrier.peer_limits.max_frame_payload, module.__name__)


class NullTrace:
    def emit(self, *args, **kwargs):
        pass


class FakeCarrier:
    def __init__(self, module):
        self.module = module
        self.local_limits = module.Limits()
        self.peer_limits = module.Limits(max_record_size=1024)
        self.sent = []

    def base_trace(self):
        return {}

    def timestamp_us(self):
        return 0

    def max_stream_data_payload(self, stream_id, transmission_id, offset):
        return self.module.Carrier.max_stream_data_payload(self, stream_id, transmission_id, offset)

    async def send_frame(self, frame_type, **fields):
        self.sent.append((frame_type, fields))


class RuntimeIdempotenceTests(unittest.IsolatedAsyncioTestCase):
    def session(self, module, role="client"):
        carrier = FakeCarrier(module)
        session_class = getattr(module, "ReferenceSession", getattr(module, "PeerSession", None))
        session = session_class(role, carrier, NullTrace(), 1, 64)
        handler = getattr(session, "handle_frame", getattr(session, "handle", None))
        allocate = getattr(session, "alloc_tx", getattr(session, "allocate", None))
        return session, handler, allocate

    async def test_repeated_ack_and_open_ok_preserve_identity_checks(self):
        for module in (reference_core, independent_core):
            session, handle, allocate = self.session(module)
            session.streams[1] = module.StreamState(1)
            for frame_type, response_type in (
                (module.FRAME_STREAM_DATA, module.FRAME_TRANSMISSION_ACK),
                (module.FRAME_STREAM_FIN, module.FRAME_TRANSMISSION_ACK),
                (module.FRAME_STREAM_OPEN, module.FRAME_STREAM_OPEN_OK),
            ):
                tx = allocate(frame_type, 1)
                fields = {"stream_id": 1, "transmission_id": tx.txid}
                await handle(response_type, fields)
                await handle(response_type, fields)
                self.assertTrue(tx.event.is_set())
                self.assertNotIn(tx.txid, session.outstanding)
                with self.assertRaises(module.TransmissionError):
                    await handle(response_type, {"stream_id": 3, "transmission_id": tx.txid})
            with self.assertRaises(module.TransmissionError):
                await handle(module.FRAME_TRANSMISSION_ACK, {"stream_id": 1, "transmission_id": tx.txid})

    async def test_repeated_open_only_starts_one_sender(self):
        for module in (reference_core, independent_core):
            session, handle, _ = self.session(module, "server")
            started = []

            async def sender(stream):
                started.append(stream.stream_id)

            if module is reference_core:
                session.send_application_stream = sender
            else:
                session.send_application = sender
            fields = {"stream_id": 1, "transmission_id": 7}
            await handle(module.FRAME_STREAM_OPEN, fields)
            await handle(module.FRAME_STREAM_OPEN, fields)
            await asyncio.gather(*session.sender_tasks)
            self.assertEqual(started, [1])
            responses = [f for f, _ in session.carrier.sent if f == module.FRAME_STREAM_OPEN_OK]
            self.assertEqual(len(responses), 2)
            with self.assertRaises(module.TransmissionError):
                await handle(module.FRAME_STREAM_OPEN, {"stream_id": 3, "transmission_id": 7})
            with self.assertRaises(module.TransmissionError):
                await handle(module.FRAME_STREAM_OPEN, {"stream_id": 1, "transmission_id": 8})

    async def test_delivered_overlap_is_checked_without_redelivery(self):
        for module in (reference_core, independent_core):
            session, handle, _ = self.session(module)
            stream = module.StreamState(1, local_maximum=64)
            session.streams[1] = stream
            for txid, offset, data in ((1, 0, b"abcd"), (2, 2, b"cdef"), (3, 0, b"abcdef")):
                await handle(module.FRAME_STREAM_DATA, {"stream_id": 1, "offset": offset, "transmission_id": txid, "data": data})
            self.assertEqual(bytes(stream.recv_data), b"abcdef")
            self.assertEqual(stream.recv_next, 6)
            with self.assertRaises(module.ProtocolError):
                await handle(module.FRAME_STREAM_DATA, {"stream_id": 1, "offset": 2, "transmission_id": 4, "data": b"XX"})

    async def test_credit_failure_does_not_leak_unsent_transmission(self):
        for module in (reference_core, independent_core):
            session, _, _ = self.session(module)
            stream = module.StreamState(1)
            session.streams[1] = stream
            if module is reference_core:
                session.session_credit_event.set()
                stream.credit_event.set()
                stream.peer_maximum = 0
                session.session_peer_maximum = 64
                send = session.send_application_stream
            else:
                session.session_credit.set()
                stream.credit_event.set()
                stream.peer_maximum = 0
                session.peer_session_max = 64
                send = session.send_application
            with self.assertRaises(module.FlowControlError):
                await send(stream)
            self.assertEqual(session.outstanding, {})


if __name__ == "__main__":
    unittest.main()
