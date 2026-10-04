#!/usr/bin/env python3
"""MPX/4 Draft 11 Gate 2 multi-Carrier/fault reference runtime.

Gate 2 is intentionally scenario-driven. Client and Server run as separate
processes over real TCP, share no runtime memory, and exercise Session state
across multiple independently authenticated Carriers.

Implemented Gate 2 scenarios:
- multi-carrier-reinjection
- dormant-recovery
- ambiguous-replacement
- fin-reset-retire
- error-scope

This runtime imports only reference.mpx4_core wire/crypto primitives. It does
not import the specification validator or semantic oracles.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .mpx4_core import (
    AuthenticationError,
    Carrier,
    FlowControlError,
    FRAME_CARRIER_CLOSE,
    FRAME_CREDIT_PROBE,
    FRAME_NAMES,
    FRAME_PING,
    FRAME_PONG,
    FRAME_RESET_STREAM,
    FRAME_SESSION_CLOSE,
    FRAME_SESSION_CREDIT,
    FRAME_STOP_SENDING,
    FRAME_STREAM_CONSUMED,
    FRAME_STREAM_CREDIT,
    FRAME_STREAM_DATA,
    FRAME_STREAM_FIN,
    FRAME_STREAM_OPEN,
    FRAME_STREAM_OPEN_OK,
    FRAME_STREAM_OPEN_REJECT,
    FRAME_TRANSMISSION_ACK,
    FRAME_TRANSMISSION_RETIRE,
    FinalSizeError,
    Limits,
    MAGIC,
    MSG_CLIENT_FINISHED,
    MSG_CLIENT_INIT,
    MSG_SERVER_FINISHED,
    MSG_SERVER_INIT,
    ProtocolError,
    Trace,
    TransmissionError,
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

ERROR_NO_ERROR = 0x00
ERROR_RESOURCE_LIMIT = 0x05
ERROR_SESSION_CONFLICT = 0x07
ERROR_FLOW_CONTROL = 0x09
ERROR_CARRIER_CONFLICT = 0x0C
ERROR_TRANSMISSION_ID = 0x10

STREAM_REASON_TEST = 0x09

SCENARIOS = (
    "multi-carrier-reinjection",
    "dormant-recovery",
    "ambiguous-replacement",
    "fin-reset-retire",
    "error-scope",
)


class AmbiguousHandshake(RuntimeError):
    def __init__(self, carrier_id: int, generation: int) -> None:
        super().__init__(f"ambiguous handshake for Carrier {carrier_id} Generation {generation}")
        self.carrier_id = carrier_id
        self.generation = generation


class CandidateReject(RuntimeError):
    def __init__(self, error_code: int, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


def transport_key_from_env() -> bytes:
    raw = os.environ.get("MPX4_REF_PSK_HEX", "")
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError("MPX4_REF_PSK_HEX must be hex") from exc
    if len(key) != 32:
        raise RuntimeError("MPX4_REF_PSK_HEX must encode exactly 32 bytes")
    return key


async def write_raw(writer: asyncio.StreamWriter, data: bytes, chunk: int) -> None:
    if chunk > 0:
        for pos in range(0, len(data), chunk):
            writer.write(data[pos : pos + chunk])
            await writer.drain()
    else:
        writer.write(data)
        await writer.drain()


@dataclass
class TxState:
    txid: int
    frame_type: int
    stream_id: int
    fields: Dict[str, object]
    settled: bool = False
    attempts: int = 0
    event: asyncio.Event = field(default_factory=asyncio.Event)

    def semantic(self) -> Tuple[object, ...]:
        items: List[Tuple[str, object]] = []
        for key, value in sorted(self.fields.items()):
            if key == "receiver_timestamp_us":
                continue
            if isinstance(value, (bytes, bytearray)):
                value = bytes(value)
            items.append((key, value))
        return (self.frame_type, tuple(items))


@dataclass
class StreamState:
    stream_id: int
    local_maximum: int = 1024 * 1024
    peer_maximum: int = 0
    recv_committed: int = 0
    recv_next: int = 0
    recv_final: Optional[int] = None
    send_offset: int = 0
    send_final: Optional[int] = None
    terminal_mode: str = "ACTIVE"
    stream_error_code: Optional[int] = None
    recv_segments: Dict[int, bytes] = field(default_factory=dict)
    recv_data: bytearray = field(default_factory=bytearray)
    open_event: asyncio.Event = field(default_factory=asyncio.Event)
    credit_event: asyncio.Event = field(default_factory=asyncio.Event)
    stop_received_event: asyncio.Event = field(default_factory=asyncio.Event)
    reset_sent_event: asyncio.Event = field(default_factory=asyncio.Event)
    retire_seen_event: asyncio.Event = field(default_factory=asyncio.Event)


class Gate2Session:
    def __init__(
        self,
        role: str,
        trace: Trace,
        scenario: str,
        local_limits: Limits,
        write_chunk: int,
    ) -> None:
        self.role = role
        self.trace = trace
        self.scenario = scenario
        self.local_limits = local_limits
        self.write_chunk = write_chunk

        self.session_id: Optional[bytes] = None
        self.client_limits: Optional[Limits] = None
        self.server_limits: Optional[Limits] = None
        self.peer_limits: Optional[Limits] = None
        self.effective_carrier_limit: Optional[int] = None

        self.state = "NEW"
        self.state_history: List[str] = ["NEW"]
        self.carriers: Dict[int, Carrier] = {}
        self.carrier_tasks: Dict[Tuple[int, int], asyncio.Task[None]] = {}
        self.highest_accepted: Dict[int, int] = {}
        self.highest_attempted: Dict[int, int] = {}
        self.established_incarnations: List[Tuple[int, int]] = []
        self.lost_incarnations: List[Tuple[int, int]] = []
        self.ambiguous_attempts: List[Tuple[int, int]] = []

        self.streams: Dict[int, StreamState] = {}
        self.next_txid = 1
        self.local_tx: Dict[int, TxState] = {}
        self.settled_through = 0
        self.last_retire_advertised = 0
        self.peer_tx_semantics: Dict[int, Tuple[object, ...]] = {}
        self.peer_tx_confirmation: Dict[int, Tuple[int, Dict[str, object]]] = {}
        self.peer_processed: Set[int] = set()
        self.peer_processed_through = 0
        self.peer_retired_through = 0

        self.session_local_maximum = 8 * 1024 * 1024
        self.session_peer_maximum = 0
        self.session_recv_committed = 0
        self.session_send_committed = 0
        self.session_credit_event = asyncio.Event()
        self.session_credit_refreshes = 0
        self.stream_credit_refreshes = 0

        self.application_rx_bytes = 0
        self.application_duplicate_bytes_suppressed = 0
        self.reinjection_attempts = 0
        self.duplicate_confirmations = 0
        self.suppressed_confirmations = 0
        self.session_close_received: Optional[Dict[str, object]] = None
        self.fatal_error: Optional[str] = None

        self.done_event = asyncio.Event()
        self.carrier_change_event = asyncio.Event()
        self.pong_tokens: Set[int] = set()
        self.pong_event = asyncio.Event()
        self.suppressed_faults: Set[Tuple[object, ...]] = set()
        self.ambiguous_faults: Set[Tuple[int, int]] = set()
        self.server_stop_txid: Optional[int] = None

    def set_state(self, state: str, **extra: object) -> None:
        if self.state == state:
            return
        self.state = state
        self.state_history.append(state)
        self.trace.emit(
            "session_state",
            session_id=self.session_id.hex() if self.session_id else None,
            state=state,
            active_carriers=len(self.carriers),
            **extra,
        )

    def limits_equal(self, a: Limits, b: Limits) -> bool:
        return (
            a.max_frame_payload == b.max_frame_payload
            and a.max_record_size == b.max_record_size
            and a.max_streams == b.max_streams
            and a.max_carriers == b.max_carriers
        )

    def validate_server_candidate(self, init) -> None:
        if init.session_action == 0:
            if self.session_id is not None:
                raise CandidateReject(ERROR_SESSION_CONFLICT, "CREATE collided with retained Session")
            if init.generation != 0:
                raise CandidateReject(ERROR_CARRIER_CONFLICT, "first Carrier generation must be zero")
            return

        if init.session_action != 1:
            raise CandidateReject(ERROR_SESSION_CONFLICT, "invalid Session action")
        if self.session_id is None or init.session_id != self.session_id:
            raise CandidateReject(ERROR_SESSION_CONFLICT, "JOIN Session not found")
        if self.client_limits is None or not self.limits_equal(init.client_limits, self.client_limits):
            raise CandidateReject(ERROR_SESSION_CONFLICT, "JOIN client limits changed")

        current_highest = self.highest_accepted.get(init.carrier_id)
        current_active = init.carrier_id in self.carriers
        active_count = len(self.carriers)
        limit = self.effective_carrier_limit or 0

        if current_highest is None:
            if init.generation != 0:
                raise CandidateReject(ERROR_CARRIER_CONFLICT, "unused Carrier ID requires Generation 0")
            if active_count >= limit:
                raise CandidateReject(ERROR_RESOURCE_LIMIT, "new Carrier would exceed Effective Carrier Limit")
        else:
            if init.generation <= current_highest:
                raise CandidateReject(ERROR_CARRIER_CONFLICT, "Generation is stale or equal")
            if not current_active and active_count >= limit:
                raise CandidateReject(ERROR_RESOURCE_LIMIT, "inactive replacement requires free Carrier slot")

    def should_drop_server_finished(self, carrier_id: int, generation: int) -> bool:
        if self.role != "server" or self.scenario != "ambiguous-replacement":
            return False
        key = (carrier_id, generation)
        if key in self.ambiguous_faults:
            return False
        if key in {(1, 1), (96, 0)}:
            self.ambiguous_faults.add(key)
            return True
        return False

    def commit_server_candidate(self, init) -> None:
        if init.session_action == 0:
            self.session_id = init.session_id
            self.client_limits = init.client_limits
            self.server_limits = self.local_limits
            self.peer_limits = init.client_limits
            self.effective_carrier_limit = min(
                init.client_limits.max_carriers,
                self.local_limits.max_carriers,
            )
            self.set_state("CREATING")
        self.highest_accepted[init.carrier_id] = init.generation
        self.trace.emit(
            "candidate_committed",
            session_id=init.session_id.hex(),
            carrier_id=init.carrier_id,
            generation=init.generation,
            session_action="CREATE" if init.session_action == 0 else "JOIN",
        )

    async def add_carrier(self, carrier: Carrier, accepted_locally: bool = True) -> None:
        if self.session_id is None:
            self.session_id = carrier.session_id
        old = self.carriers.get(carrier.carrier_id)
        if old is not None and old.generation < carrier.generation:
            self.trace.emit(
                "carrier_superseded",
                session_id=self.session_id.hex(),
                carrier_id=carrier.carrier_id,
                old_generation=old.generation,
                new_generation=carrier.generation,
            )
            await self._close_writer(old)
            self.carriers.pop(carrier.carrier_id, None)

        self.carriers[carrier.carrier_id] = carrier
        if accepted_locally:
            self.highest_accepted[carrier.carrier_id] = carrier.generation
        self.established_incarnations.append((carrier.carrier_id, carrier.generation))
        self.set_state("ACTIVE")
        self.trace.emit(
            "carrier_established",
            **carrier.base_trace(),
            active_carriers=len(self.carriers),
            send_record_seq=carrier.send_seq,
            recv_record_seq=carrier.recv_seq,
        )

        task = asyncio.create_task(self.receive_loop(carrier))
        self.carrier_tasks[(carrier.carrier_id, carrier.generation)] = task
        self.carrier_change_event.set()
        self.carrier_change_event = asyncio.Event()
        await self.refresh_after_establish(carrier)

    async def refresh_after_establish(self, carrier: Carrier) -> None:
        await self.send_frame(
            carrier,
            FRAME_SESSION_CREDIT,
            consumed_bytes=0,
            maximum_bytes=self.session_local_maximum,
        )
        self.session_credit_refreshes += 1
        self.trace.emit(
            "recovery_refresh",
            **carrier.base_trace(),
            kind="SESSION_CREDIT",
            maximum=self.session_local_maximum,
        )
        if self.settled_through > 0:
            await self.send_frame(
                carrier,
                FRAME_TRANSMISSION_RETIRE,
                retired_through=self.settled_through,
            )
            self.trace.emit(
                "recovery_refresh",
                **carrier.base_trace(),
                kind="TRANSMISSION_RETIRE",
                retired_through=self.settled_through,
            )

    async def _close_writer(self, carrier: Carrier) -> None:
        try:
            carrier.writer.close()
            await asyncio.sleep(0)
        except (Exception, asyncio.CancelledError):
            pass

    async def close_carrier(self, carrier_id: int, reason: str) -> None:
        carrier = self.carriers.get(carrier_id)
        if carrier is None:
            return
        self.trace.emit("fault_close_carrier", **carrier.base_trace(), reason=reason)
        await self._close_writer(carrier)
        await self.on_carrier_lost(carrier, reason=reason)

    async def on_carrier_lost(self, carrier: Carrier, reason: str) -> None:
        current = self.carriers.get(carrier.carrier_id)
        if current is None or current.generation != carrier.generation:
            return
        self.carriers.pop(carrier.carrier_id, None)
        self.lost_incarnations.append((carrier.carrier_id, carrier.generation))
        self.trace.emit(
            "carrier_lost",
            **carrier.base_trace(),
            reason=reason,
            active_carriers=len(self.carriers),
        )
        if not self.carriers and self.state not in {"CLOSING", "CLOSED"}:
            self.set_state("DORMANT", reason=reason)
        self.carrier_change_event.set()
        self.carrier_change_event = asyncio.Event()

    def choose_carrier(self, preferred: Optional[int] = None, exclude: Optional[int] = None) -> Carrier:
        if preferred is not None and preferred in self.carriers:
            return self.carriers[preferred]
        ids = sorted(cid for cid in self.carriers if cid != exclude)
        if not ids:
            ids = sorted(self.carriers)
        if not ids:
            raise RuntimeError("no active Carrier")
        return self.carriers[ids[0]]

    def alternate_carrier(self, incoming: Carrier) -> Carrier:
        return self.choose_carrier(exclude=incoming.carrier_id)

    async def send_frame(self, carrier: Carrier, frame_type: int, **fields: object) -> None:
        await carrier.send_frame(frame_type, **fields)
        info = carrier.base_trace()
        info["frame_type"] = FRAME_NAMES.get(frame_type, f"0x{frame_type:x}")
        for key in (
            "stream_id",
            "transmission_id",
            "offset",
            "final_offset",
            "retired_through",
            "error_code",
            "trigger_frame_type",
            "token",
        ):
            if key in fields:
                info[key] = fields[key]
        if frame_type == FRAME_STREAM_DATA:
            info["data_length"] = len(fields["data"])  # type: ignore[arg-type]
        self.trace.emit("frame_send", **info)

    def alloc_tx(self, frame_type: int, stream_id: int, **fields: object) -> TxState:
        txid = self.next_txid
        self.next_txid += 1
        wire_fields = dict(fields)
        wire_fields["stream_id"] = stream_id
        wire_fields["transmission_id"] = txid
        tx = TxState(
            txid=txid,
            frame_type=frame_type,
            stream_id=stream_id,
            fields=wire_fields,
        )
        self.local_tx[txid] = tx
        self.trace.emit(
            "transmission_allocated",
            session_id=self.session_id.hex() if self.session_id else None,
            transmission_id=txid,
            frame_type=FRAME_NAMES.get(frame_type, frame_type),
            stream_id=stream_id,
        )
        return tx

    async def send_tx(self, tx: TxState, carrier: Carrier, reinjection: bool = False) -> None:
        if tx.attempts > 0 or reinjection:
            self.reinjection_attempts += 1
        tx.attempts += 1
        await self.send_frame(carrier, tx.frame_type, **tx.fields)
        self.trace.emit(
            "transmission_attempt",
            **carrier.base_trace(),
            transmission_id=tx.txid,
            frame_type=FRAME_NAMES.get(tx.frame_type, tx.frame_type),
            stream_id=tx.stream_id,
            attempt=tx.attempts,
            reinjection=tx.attempts > 1 or reinjection,
        )

    def settle_tx(self, txid: int, confirmation: str, stream_id: int) -> None:
        tx = self.local_tx.get(txid)
        if tx is None:
            raise TransmissionError(f"confirmation for never-allocated Transmission {txid}")
        if tx.stream_id != stream_id:
            raise TransmissionError("confirmation Stream identity mismatch")
        if confirmation == "ACK" and tx.frame_type == FRAME_STREAM_OPEN:
            raise TransmissionError("TRANSMISSION_ACK cannot settle STREAM_OPEN")
        if confirmation in {"OPEN_OK", "OPEN_REJECT"} and tx.frame_type != FRAME_STREAM_OPEN:
            raise TransmissionError("opening confirmation references non-open Transmission")
        if tx.settled:
            self.duplicate_confirmations += 1
            self.trace.emit(
                "duplicate_confirmation",
                session_id=self.session_id.hex() if self.session_id else None,
                transmission_id=txid,
                confirmation=confirmation,
            )
            return
        tx.settled = True
        tx.event.set()
        self.trace.emit(
            "transmission_settled",
            session_id=self.session_id.hex() if self.session_id else None,
            transmission_id=txid,
            confirmation=confirmation,
        )
        while True:
            nxt = self.local_tx.get(self.settled_through + 1)
            if nxt is None or not nxt.settled:
                break
            self.settled_through += 1

    def peer_semantic(self, frame_type: int, fields: Dict[str, object]) -> Tuple[object, ...]:
        items = []
        for key, value in sorted(fields.items()):
            if key == "receiver_timestamp_us":
                continue
            if isinstance(value, (bytes, bytearray)):
                value = bytes(value)
            items.append((key, value))
        return (frame_type, tuple(items))

    def register_peer_tx(self, frame_type: int, fields: Dict[str, object]) -> bool:
        txid = int(fields["transmission_id"])
        if txid <= 0:
            raise TransmissionError("zero Transmission ID")
        semantic = self.peer_semantic(frame_type, fields)
        old = self.peer_tx_semantics.get(txid)
        if old is not None:
            if old != semantic:
                raise TransmissionError(f"conflicting reuse of peer Transmission {txid}")
            self.trace.emit(
                "peer_transmission_duplicate",
                session_id=self.session_id.hex() if self.session_id else None,
                transmission_id=txid,
                frame_type=FRAME_NAMES.get(frame_type, frame_type),
            )
            return True
        self.peer_tx_semantics[txid] = semantic
        self.peer_processed.add(txid)
        while self.peer_processed_through + 1 in self.peer_processed:
            self.peer_processed_through += 1
        self.trace.emit(
            "peer_transmission_processed",
            session_id=self.session_id.hex() if self.session_id else None,
            transmission_id=txid,
            frame_type=FRAME_NAMES.get(frame_type, frame_type),
            processed_through=self.peer_processed_through,
        )
        return False

    def should_suppress_confirmation(
        self,
        frame_type: int,
        fields: Dict[str, object],
        incoming: Carrier,
    ) -> bool:
        txid = int(fields.get("transmission_id", 0))
        key = (frame_type, txid, incoming.carrier_id, incoming.generation)
        if key in self.suppressed_faults:
            return False

        suppress = False
        if self.role == "server" and self.scenario == "multi-carrier-reinjection":
            suppress = (
                frame_type == FRAME_STREAM_DATA
                and int(fields.get("offset", -1)) == 16384
                and incoming.carrier_id == 1
            )
        elif self.role == "server" and self.scenario == "dormant-recovery":
            suppress = (
                frame_type == FRAME_STREAM_DATA
                and incoming.carrier_id == 1
                and incoming.generation == 0
            )
        elif self.role == "server" and self.scenario == "fin-reset-retire":
            suppress = frame_type == FRAME_STREAM_FIN and incoming.carrier_id == 1

        if suppress:
            self.suppressed_faults.add(key)
            self.suppressed_confirmations += 1
            self.trace.emit(
                "fault_suppress_confirmation",
                **incoming.base_trace(),
                transmission_id=txid,
                frame_type=FRAME_NAMES.get(frame_type, frame_type),
            )
            return True
        return False

    async def acknowledge(
        self,
        incoming: Carrier,
        stream_id: int,
        txid: int,
        original_frame_type: int,
    ) -> None:
        if self.should_suppress_confirmation(
            original_frame_type,
            {"stream_id": stream_id, "transmission_id": txid},
            incoming,
        ):
            return
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        await self.send_frame(
            reply,
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=reply.timestamp_us(),
        )

    async def receive_loop(self, carrier: Carrier) -> None:
        try:
            while self.state not in {"CLOSING", "CLOSED"}:
                frames = await carrier.recv_record()
                for frame_type, fields in frames:
                    await self.handle_frame(carrier, frame_type, fields)
                    if self.state in {"CLOSING", "CLOSED"}:
                        return
        except asyncio.IncompleteReadError:
            await self.on_carrier_lost(carrier, "transport-eof")
        except (ConnectionError, BrokenPipeError):
            await self.on_carrier_lost(carrier, "transport-error")
        except TransmissionError as exc:
            await self.fail_session(
                ERROR_TRANSMISSION_ID,
                FRAME_TRANSMISSION_ACK,
                f"TRANSMISSION_ID_ERROR: {exc}",
                carrier,
            )
        except FlowControlError as exc:
            await self.fail_session(
                ERROR_FLOW_CONTROL,
                FRAME_STREAM_DATA,
                f"FLOW_CONTROL_ERROR: {exc}",
                carrier,
            )
        except (ProtocolError, FinalSizeError, AuthenticationError) as exc:
            self.fatal_error = f"{type(exc).__name__}: {exc}"
            self.trace.emit(
                "runtime_error",
                **carrier.base_trace(),
                error_type=type(exc).__name__,
                error=str(exc),
            )
            self.done_event.set()

    async def fail_session(
        self,
        error_code: int,
        trigger_frame_type: int,
        reason: str,
        preferred_carrier: Optional[Carrier] = None,
    ) -> None:
        if self.state in {"CLOSING", "CLOSED"}:
            return
        self.set_state("CLOSING", error_code=error_code)
        carrier = preferred_carrier
        if carrier is None or carrier.carrier_id not in self.carriers:
            carrier = self.choose_carrier() if self.carriers else None
        if carrier is not None:
            try:
                await self.send_frame(
                    carrier,
                    FRAME_SESSION_CLOSE,
                    error_code=error_code,
                    trigger_frame_type=trigger_frame_type,
                    reason=reason[:256],
                )
            except Exception:
                pass
        self.trace.emit(
            "session_failed",
            session_id=self.session_id.hex() if self.session_id else None,
            error_code=error_code,
            trigger_frame_type=trigger_frame_type,
            reason=reason,
        )
        self.set_state("CLOSED")
        self.done_event.set()

    async def handle_frame(
        self,
        incoming: Carrier,
        frame_type: int,
        fields: Dict[str, object],
    ) -> None:
        info = incoming.base_trace()
        info["frame_type"] = FRAME_NAMES.get(frame_type, f"0x{frame_type:x}")
        for key in (
            "stream_id",
            "transmission_id",
            "offset",
            "final_offset",
            "retired_through",
            "error_code",
            "trigger_frame_type",
            "token",
        ):
            if key in fields:
                info[key] = fields[key]
        if frame_type == FRAME_STREAM_DATA:
            info["data_length"] = len(fields["data"])  # type: ignore[arg-type]
        self.trace.emit("frame_recv", **info)

        if frame_type == FRAME_SESSION_CREDIT:
            consumed = int(fields["consumed_bytes"])
            maximum = int(fields["maximum_bytes"])
            if maximum < consumed:
                raise FlowControlError("invalid Session credit")
            self.session_peer_maximum = max(self.session_peer_maximum, maximum)
            self.session_credit_event.set()
            return

        if frame_type == FRAME_STREAM_CREDIT:
            stream_id = int(fields["stream_id"])
            stream = self.streams.get(stream_id)
            if stream is None:
                raise ProtocolError("Stream credit for unknown Stream")
            consumed = int(fields["consumed_offset"])
            maximum = int(fields["maximum_offset"])
            if maximum < consumed:
                raise FlowControlError("invalid Stream credit")
            stream.peer_maximum = max(stream.peer_maximum, maximum)
            stream.credit_event.set()
            return

        if frame_type == FRAME_STREAM_OPEN:
            await self.handle_stream_open(incoming, fields)
            return

        if frame_type == FRAME_STREAM_OPEN_OK:
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            stream = self.streams.get(stream_id)
            if stream is None:
                raise TransmissionError("OPEN_OK for unknown Stream")
            self.settle_tx(txid, "OPEN_OK", stream_id)
            stream.open_event.set()
            return

        if frame_type == FRAME_STREAM_OPEN_REJECT:
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            self.settle_tx(txid, "OPEN_REJECT", stream_id)
            return

        if frame_type == FRAME_STREAM_DATA:
            await self.handle_stream_data(incoming, fields)
            return

        if frame_type == FRAME_STREAM_FIN:
            await self.handle_stream_fin(incoming, fields)
            return

        if frame_type == FRAME_RESET_STREAM:
            await self.handle_reset_stream(incoming, fields)
            return

        if frame_type == FRAME_STOP_SENDING:
            await self.handle_stop_sending(incoming, fields)
            return

        if frame_type == FRAME_STREAM_CONSUMED:
            duplicate = self.register_peer_tx(frame_type, fields)
            await self.acknowledge(
                incoming,
                int(fields["stream_id"]),
                int(fields["transmission_id"]),
                frame_type,
            )
            return

        if frame_type == FRAME_TRANSMISSION_ACK:
            txid = int(fields["transmission_id"])
            stream_id = int(fields["stream_id"])
            self.settle_tx(txid, "ACK", stream_id)
            return

        if frame_type == FRAME_TRANSMISSION_RETIRE:
            value = int(fields["retired_through"])
            if value > self.peer_processed_through:
                raise TransmissionError(
                    f"retire {value} exceeds processed-through {self.peer_processed_through}"
                )
            if value > self.peer_retired_through:
                self.peer_retired_through = value
            self.trace.emit(
                "retire_received",
                **incoming.base_trace(),
                retired_through=value,
                retained_peer_processed_through=self.peer_processed_through,
            )
            for stream in self.streams.values():
                stream.retire_seen_event.set()
            return

        if frame_type == FRAME_CREDIT_PROBE:
            stream_id = int(fields["stream_id"])
            if stream_id != 0:
                stream = self.streams.get(stream_id)
                if stream is not None:
                    reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
                    await self.send_frame(
                        reply,
                        FRAME_STREAM_CREDIT,
                        stream_id=stream_id,
                        consumed_offset=0,
                        maximum_offset=stream.local_maximum,
                    )
                    self.stream_credit_refreshes += 1
            reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
            await self.send_frame(
                reply,
                FRAME_SESSION_CREDIT,
                consumed_bytes=0,
                maximum_bytes=self.session_local_maximum,
            )
            self.session_credit_refreshes += 1
            return

        if frame_type == FRAME_PING:
            reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
            await self.send_frame(reply, FRAME_PONG, token=int(fields["token"]))
            return

        if frame_type == FRAME_PONG:
            token = int(fields["token"])
            self.pong_tokens.add(token)
            self.pong_event.set()
            self.pong_event = asyncio.Event()
            return

        if frame_type == FRAME_CARRIER_CLOSE:
            await self.close_carrier(incoming.carrier_id, "peer-carrier-close")
            return

        if frame_type == FRAME_SESSION_CLOSE:
            self.session_close_received = dict(fields)
            self.trace.emit(
                "session_close_received",
                **incoming.base_trace(),
                error_code=int(fields["error_code"]),
                trigger_frame_type=int(fields["trigger_frame_type"]),
                reason=str(fields.get("reason", "")),
            )
            self.set_state("CLOSED")
            self.done_event.set()
            return

        raise ProtocolError(f"Gate 2 runtime does not handle {FRAME_NAMES.get(frame_type, frame_type)}")

    async def handle_stream_open(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        duplicate = self.register_peer_tx(FRAME_STREAM_OPEN, fields)
        stream = self.streams.get(stream_id)
        if stream is None:
            stream = StreamState(stream_id=stream_id)
            self.streams[stream_id] = stream
            self.trace.emit(
                "stream_created",
                session_id=self.session_id.hex() if self.session_id else None,
                stream_id=stream_id,
            )
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        await self.send_frame(
            reply,
            FRAME_STREAM_OPEN_OK,
            stream_id=stream_id,
            transmission_id=txid,
        )
        await self.send_frame(
            reply,
            FRAME_STREAM_CREDIT,
            stream_id=stream_id,
            consumed_offset=0,
            maximum_offset=stream.local_maximum,
        )
        self.stream_credit_refreshes += 1
        self.peer_tx_confirmation[txid] = (
            FRAME_STREAM_OPEN_OK,
            {"stream_id": stream_id, "transmission_id": txid},
        )

    async def handle_stream_data(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        offset = int(fields["offset"])
        txid = int(fields["transmission_id"])
        data = bytes(fields["data"])  # type: ignore[arg-type]
        duplicate = self.register_peer_tx(FRAME_STREAM_DATA, fields)
        stream = self.streams.get(stream_id)
        if stream is None:
            raise ProtocolError("DATA for unknown Stream")
        end = offset + len(data)
        if end > stream.local_maximum:
            raise FlowControlError("Stream credit exceeded")

        if not duplicate:
            old_committed = stream.recv_committed
            stream.recv_committed = max(stream.recv_committed, end)
            delta = stream.recv_committed - old_committed
            if self.session_recv_committed + delta > self.session_local_maximum:
                raise FlowControlError("Session credit exceeded")
            self.session_recv_committed += delta
            existing = stream.recv_segments.get(offset)
            if existing is not None and existing != data:
                raise TransmissionError("conflicting Stream bytes")
            stream.recv_segments[offset] = data
            while stream.recv_next in stream.recv_segments:
                chunk = stream.recv_segments.pop(stream.recv_next)
                stream.recv_data.extend(chunk)
                stream.recv_next += len(chunk)
                self.application_rx_bytes += len(chunk)
        else:
            self.application_duplicate_bytes_suppressed += len(data)

        if self.should_suppress_confirmation(FRAME_STREAM_DATA, fields, incoming):
            return
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        await self.send_frame(
            reply,
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=reply.timestamp_us(),
        )

    async def handle_stream_fin(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        final_offset = int(fields["final_offset"])
        duplicate = self.register_peer_tx(FRAME_STREAM_FIN, fields)
        stream = self.streams.get(stream_id)
        if stream is None:
            raise ProtocolError("FIN for unknown Stream")
        if final_offset < stream.recv_committed:
            raise FinalSizeError("Final Offset below commitment")
        if stream.recv_final is not None and stream.recv_final != final_offset:
            raise FinalSizeError("contradictory Final Offset")
        if final_offset > stream.local_maximum:
            raise FlowControlError("FIN exceeds Stream credit")
        delta = max(0, final_offset - stream.recv_committed)
        if self.session_recv_committed + delta > self.session_local_maximum:
            raise FlowControlError("FIN exceeds Session credit")
        if not duplicate:
            self.session_recv_committed += delta
            stream.recv_committed = max(stream.recv_committed, final_offset)
            stream.recv_final = final_offset
            if stream.terminal_mode != "RESET":
                stream.terminal_mode = "FIN"

        suppress = self.should_suppress_confirmation(FRAME_STREAM_FIN, fields, incoming)
        if (
            self.role == "server"
            and self.scenario == "fin-reset-retire"
            and suppress
            and self.server_stop_txid is None
        ):
            asyncio.create_task(self.send_test_stop_sending(stream_id, incoming))
        if suppress:
            return
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        await self.send_frame(
            reply,
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=reply.timestamp_us(),
        )

    async def send_test_stop_sending(self, stream_id: int, incoming: Carrier) -> None:
        await asyncio.sleep(0)
        stream = self.streams[stream_id]
        tx = self.alloc_tx(
            FRAME_STOP_SENDING,
            stream_id,
            stream_error_code=STREAM_REASON_TEST,
        )
        self.server_stop_txid = tx.txid
        carrier = self.alternate_carrier(incoming)
        await self.send_tx(tx, carrier)

    async def handle_reset_stream(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        final_offset = int(fields["final_offset"])
        duplicate = self.register_peer_tx(FRAME_RESET_STREAM, fields)
        stream = self.streams.get(stream_id)
        if stream is None:
            raise ProtocolError("RESET for unknown Stream")
        if stream.recv_final is not None and stream.recv_final != final_offset:
            raise FinalSizeError("RESET contradicts established final size")
        if final_offset < stream.recv_committed:
            raise FinalSizeError("RESET Final Offset below commitment")
        if final_offset > stream.local_maximum:
            raise FlowControlError("RESET exceeds Stream credit")
        delta = max(0, final_offset - stream.recv_committed)
        if self.session_recv_committed + delta > self.session_local_maximum:
            raise FlowControlError("RESET exceeds Session credit")
        if not duplicate:
            self.session_recv_committed += delta
            stream.recv_committed = max(stream.recv_committed, final_offset)
        stream.recv_final = final_offset
        stream.terminal_mode = "RESET"
        stream.stream_error_code = int(fields["stream_error_code"])
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        await self.send_frame(
            reply,
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=reply.timestamp_us(),
        )

    async def handle_stop_sending(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        duplicate = self.register_peer_tx(FRAME_STOP_SENDING, fields)
        stream = self.streams.get(stream_id)
        if stream is None:
            raise ProtocolError("STOP_SENDING for unknown Stream")
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        await self.send_frame(
            reply,
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=reply.timestamp_us(),
        )
        stream.stop_received_event.set()
        if not duplicate and stream.terminal_mode != "RESET":
            tx = self.alloc_tx(
                FRAME_RESET_STREAM,
                stream_id,
                final_offset=stream.send_offset,
                stream_error_code=int(fields["stream_error_code"]),
            )
            stream.send_final = stream.send_offset
            stream.terminal_mode = "RESET"
            stream.stream_error_code = int(fields["stream_error_code"])
            await self.send_tx(tx, reply)
            stream.reset_sent_event.set()

    async def open_stream(self, stream_id: int, carrier: Carrier) -> StreamState:
        stream = StreamState(stream_id=stream_id)
        self.streams[stream_id] = stream
        tx = self.alloc_tx(FRAME_STREAM_OPEN, stream_id)
        await self.send_tx(tx, carrier)
        await asyncio.wait_for(stream.open_event.wait(), timeout=10)
        await asyncio.wait_for(stream.credit_event.wait(), timeout=10)
        return stream

    async def send_stream_credit(self, stream: StreamState, carrier: Carrier) -> None:
        await self.send_frame(
            carrier,
            FRAME_STREAM_CREDIT,
            stream_id=stream.stream_id,
            consumed_offset=0,
            maximum_offset=stream.local_maximum,
        )
        self.stream_credit_refreshes += 1

    async def send_data(
        self,
        stream: StreamState,
        data: bytes,
        carrier: Carrier,
    ) -> TxState:
        if stream.send_offset + len(data) > stream.peer_maximum:
            raise FlowControlError("local sender lacks Stream credit")
        if self.session_send_committed + len(data) > self.session_peer_maximum:
            raise FlowControlError("local sender lacks Session credit")
        tx = self.alloc_tx(
            FRAME_STREAM_DATA,
            stream.stream_id,
            offset=stream.send_offset,
            data=data,
        )
        self.session_send_committed += len(data)
        stream.send_offset += len(data)
        await self.send_tx(tx, carrier)
        return tx

    async def send_retire(self, carrier: Carrier) -> None:
        if self.settled_through <= 0:
            return
        await self.send_frame(
            carrier,
            FRAME_TRANSMISSION_RETIRE,
            retired_through=self.settled_through,
        )
        self.last_retire_advertised = max(
            self.last_retire_advertised,
            self.settled_through,
        )

    async def send_credit_probe(self, carrier: Carrier, stream_id: int) -> None:
        await self.send_frame(carrier, FRAME_CREDIT_PROBE, stream_id=stream_id)

    async def ping(self, carrier: Carrier, token: int) -> None:
        await self.send_frame(carrier, FRAME_PING, token=token)
        deadline = asyncio.get_running_loop().time() + 5
        while token not in self.pong_tokens:
            remain = deadline - asyncio.get_running_loop().time()
            if remain <= 0:
                raise TimeoutError("PONG timeout")
            await asyncio.wait_for(self.pong_event.wait(), timeout=remain)

    async def send_session_close(self, carrier: Optional[Carrier] = None, reason: str = "gate2-complete") -> None:
        if self.state in {"CLOSING", "CLOSED"}:
            return
        self.set_state("CLOSING")
        if carrier is None:
            carrier = self.choose_carrier()
        await self.send_frame(
            carrier,
            FRAME_SESSION_CLOSE,
            error_code=ERROR_NO_ERROR,
            trigger_frame_type=0,
            reason=reason,
        )
        self.set_state("CLOSED")
        self.done_event.set()

    async def wait_for_state(self, wanted: str, timeout: float = 5.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while self.state != wanted:
            if self.fatal_error:
                raise RuntimeError(self.fatal_error)
            remain = deadline - asyncio.get_running_loop().time()
            if remain <= 0:
                raise TimeoutError(f"state {wanted} timeout; current={self.state}")
            await asyncio.wait_for(self.carrier_change_event.wait(), timeout=remain)

    async def wait_no_carriers(self, timeout: float = 5.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while self.carriers:
            remain = deadline - asyncio.get_running_loop().time()
            if remain <= 0:
                raise TimeoutError("Carriers did not drain")
            await asyncio.wait_for(self.carrier_change_event.wait(), timeout=remain)

    async def cleanup(self) -> None:
        tasks = list(self.carrier_tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=0.5)
            for task in done:
                try:
                    task.exception()
                except (Exception, asyncio.CancelledError):
                    pass
            for task in pending:
                task.cancel()
        carriers = list(self.carriers.values())
        self.carriers.clear()
        for carrier in carriers:
            await self._close_writer(carrier)

    def summary(self) -> Dict[str, object]:
        stream_results = {}
        for stream_id, stream in sorted(self.streams.items()):
            stream_results[str(stream_id)] = {
                "recv_bytes": len(stream.recv_data),
                "recv_sha256": hashlib.sha256(stream.recv_data).hexdigest(),
                "recv_final": stream.recv_final,
                "send_offset": stream.send_offset,
                "send_final": stream.send_final,
                "terminal_mode": stream.terminal_mode,
                "stream_error_code": stream.stream_error_code,
            }
        return {
            "role": self.role,
            "scenario": self.scenario,
            "session_id": self.session_id.hex() if self.session_id else None,
            "state": self.state,
            "state_history": self.state_history,
            "highest_accepted": {str(k): v for k, v in sorted(self.highest_accepted.items())},
            "highest_attempted": {str(k): v for k, v in sorted(self.highest_attempted.items())},
            "established_incarnations": [list(x) for x in self.established_incarnations],
            "lost_incarnations": [list(x) for x in self.lost_incarnations],
            "ambiguous_attempts": [list(x) for x in self.ambiguous_attempts],
            "settled_through": self.settled_through,
            "peer_processed_through": self.peer_processed_through,
            "peer_retired_through": self.peer_retired_through,
            "application_rx_bytes": self.application_rx_bytes,
            "application_duplicate_bytes_suppressed": self.application_duplicate_bytes_suppressed,
            "reinjection_attempts": self.reinjection_attempts,
            "duplicate_confirmations": self.duplicate_confirmations,
            "suppressed_confirmations": self.suppressed_confirmations,
            "session_credit_refreshes": self.session_credit_refreshes,
            "stream_credit_refreshes": self.stream_credit_refreshes,
            "session_close_received": self.session_close_received,
            "fatal_error": self.fatal_error,
            "streams": stream_results,
        }


async def client_handshake(
    session: Gate2Session,
    host: str,
    port: int,
    key: bytes,
    session_action: int,
    carrier_id: int,
    generation: int,
) -> Carrier:
    if session.session_id is None:
        raise RuntimeError("Client Session ID not initialized")
    session.highest_attempted[carrier_id] = max(
        generation,
        session.highest_attempted.get(carrier_id, -1),
    )
    reader, writer = await asyncio.open_connection(host, port)
    preface = MAGIC + vi_enc(VERSION)
    client_nonce = secrets.token_bytes(32)
    client_init = encode_client_init(
        session_id=session.session_id,
        carrier_id=carrier_id,
        generation=generation,
        client_nonce=client_nonce,
        limits=session.local_limits,
        session_action=session_action,
    )
    await write_raw(writer, preface + client_init, session.write_chunk)
    session.trace.emit(
        "handshake_send",
        stage="CLIENT_INIT",
        session_id=session.session_id.hex(),
        carrier_id=carrier_id,
        generation=generation,
        session_action="CREATE" if session_action == 0 else "JOIN",
    )

    message_type, _, server_init = await read_message(reader)
    if message_type != MSG_SERVER_INIT:
        raise RuntimeError(f"expected SERVER_INIT, got {message_type}")
    server_nonce, server_limits = parse_server_init(server_init)
    if session.server_limits is not None and not session.limits_equal(server_limits, session.server_limits):
        raise RuntimeError("Server changed Session-scoped limits on JOIN")

    client_finished, expected_server_finished, h0, prelim = derive_traffic(
        key,
        preface,
        client_init,
        server_init,
    )
    await write_raw(writer, client_finished, session.write_chunk)
    session.trace.emit(
        "handshake_send",
        stage="CLIENT_FINISHED",
        session_id=session.session_id.hex(),
        carrier_id=carrier_id,
        generation=generation,
    )

    try:
        message_type, _, server_finished = await read_message(reader)
    except asyncio.IncompleteReadError as exc:
        writer.close()
        await writer.wait_closed()
        session.ambiguous_attempts.append((carrier_id, generation))
        session.trace.emit(
            "handshake_ambiguous",
            session_id=session.session_id.hex(),
            carrier_id=carrier_id,
            generation=generation,
            point="SERVER_FINISHED_not_authenticated",
        )
        raise AmbiguousHandshake(carrier_id, generation) from exc

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
        raise RuntimeError("SERVER_FINISHED differs from canonical transcript result")

    _, _, _, traffic = derive_traffic(
        key,
        preface,
        client_init,
        server_init,
        client_finished=client_finished,
        server_finished=server_finished,
    )
    if session.server_limits is None:
        session.server_limits = server_limits
        session.client_limits = session.local_limits
        session.peer_limits = server_limits
        session.effective_carrier_limit = min(
            session.local_limits.max_carriers,
            server_limits.max_carriers,
        )

    carrier = Carrier(
        role="client",
        reader=reader,
        writer=writer,
        trace=session.trace,
        local_limits=session.local_limits,
        peer_limits=server_limits,
        send_key=traffic.client_key,
        send_iv=traffic.client_iv,
        recv_key=traffic.server_key,
        recv_iv=traffic.server_iv,
        session_id=session.session_id,
        carrier_id=carrier_id,
        generation=generation,
        write_chunk=session.write_chunk,
    )
    session.trace.emit(
        "handshake_established",
        **carrier.base_trace(),
        protocol_version=VERSION,
    )
    await session.add_carrier(carrier)
    return carrier


async def server_handshake(
    session: Gate2Session,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    key: bytes,
):
    magic = await reader.readexactly(4)
    if magic != MAGIC:
        raise ProtocolError("invalid MPX magic")
    version, version_raw = await read_varint(reader)
    if version != VERSION:
        raise ProtocolError("unsupported Protocol Version")
    preface = magic + version_raw

    message_type, _, client_init = await read_message(reader)
    if message_type != MSG_CLIENT_INIT:
        raise ProtocolError("expected CLIENT_INIT")
    init = parse_client_init(client_init)
    session.validate_server_candidate(init)
    session.trace.emit(
        "handshake_recv",
        stage="CLIENT_INIT",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
        session_action="CREATE" if init.session_action == 0 else "JOIN",
    )

    server_nonce = secrets.token_bytes(32)
    server_init = encode_server_init(server_nonce, session.local_limits)
    await write_raw(writer, server_init, session.write_chunk)

    expected_client_finished, server_finished_template, h0, prelim = derive_traffic(
        key,
        preface,
        client_init,
        server_init,
    )
    message_type, _, client_finished = await read_message(reader)
    if message_type != MSG_CLIENT_FINISHED:
        raise ProtocolError("expected CLIENT_FINISHED")
    validate_finished(
        client_finished,
        MSG_CLIENT_FINISHED,
        prelim.client_finished_key,
        h0,
    )
    if client_finished != expected_client_finished:
        raise AuthenticationError("CLIENT_FINISHED not canonical for transcript")

    _, server_finished, _, traffic = derive_traffic(
        key,
        preface,
        client_init,
        server_init,
        client_finished=client_finished,
    )
    if server_finished != server_finished_template:
        raise RuntimeError("internal SERVER_FINISHED derivation mismatch")

    # Server commits the candidate when it reaches its ESTABLISHED transition.
    # The ambiguity fault is injected after this commit but before the Client can
    # authenticate SERVER_FINISHED.
    session.commit_server_candidate(init)
    if session.should_drop_server_finished(init.carrier_id, init.generation):
        session.trace.emit(
            "fault_drop_server_finished",
            session_id=init.session_id.hex(),
            carrier_id=init.carrier_id,
            generation=init.generation,
            committed=True,
        )
        writer.close()
        await writer.wait_closed()
        session.lost_incarnations.append((init.carrier_id, init.generation))
        if not session.carriers:
            session.set_state("DORMANT", reason="ambiguous-candidate-transport-loss")
        return None

    await write_raw(writer, server_finished, session.write_chunk)
    carrier = Carrier(
        role="server",
        reader=reader,
        writer=writer,
        trace=session.trace,
        local_limits=session.local_limits,
        peer_limits=init.client_limits,
        send_key=traffic.server_key,
        send_iv=traffic.server_iv,
        recv_key=traffic.client_key,
        recv_iv=traffic.client_iv,
        session_id=init.session_id,
        carrier_id=init.carrier_id,
        generation=init.generation,
        write_chunk=session.write_chunk,
    )
    session.trace.emit(
        "handshake_established",
        **carrier.base_trace(),
        protocol_version=VERSION,
    )
    await session.add_carrier(carrier, accepted_locally=False)
    return carrier


async def server_main(session: Gate2Session, args: argparse.Namespace, key: bytes) -> Dict[str, object]:
    connection_tasks: Set[asyncio.Task[None]] = set()

    async def worker(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await server_handshake(session, reader, writer, key)
        except CandidateReject as exc:
            session.trace.emit(
                "candidate_rejected",
                error_code=exc.error_code,
                reason=str(exc),
            )
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            session.fatal_error = f"{type(exc).__name__}: {exc}"
            session.trace.emit(
                "handshake_error",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            writer.close()
            await writer.wait_closed()
            session.done_event.set()

    def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(worker(reader, writer))
        connection_tasks.add(task)
        task.add_done_callback(connection_tasks.discard)

    server = await asyncio.start_server(callback, args.host, args.port)
    sockets = server.sockets or []
    if not sockets:
        raise RuntimeError("Gate 2 server has no listening socket")
    port = int(sockets[0].getsockname()[1])
    print(json.dumps({"event": "READY", "host": args.host, "port": port}), flush=True)
    session.trace.emit("listener_ready", host=args.host, port=port)

    try:
        session.trace.emit("server_lifecycle", phase="wait_done_begin")
        await asyncio.wait_for(session.done_event.wait(), timeout=args.timeout * 6)
        session.trace.emit("server_lifecycle", phase="wait_done_end")
        await asyncio.sleep(0.05)
        if session.fatal_error:
            raise RuntimeError(session.fatal_error)
        session.trace.emit("server_lifecycle", phase="summary")
        return session.summary()
    finally:
        session.trace.emit("server_lifecycle", phase="listener_close_begin")
        server.close()
        await asyncio.sleep(0)
        session.trace.emit("server_lifecycle", phase="listener_close_end")
        for task in list(connection_tasks):
            if not task.done():
                task.cancel()
        if connection_tasks:
            session.trace.emit("server_lifecycle", phase="workers_gather_begin", workers=len(connection_tasks))
            await asyncio.gather(*connection_tasks, return_exceptions=True)
            session.trace.emit("server_lifecycle", phase="workers_gather_end")
        session.trace.emit("server_lifecycle", phase="session_cleanup_begin")
        await session.cleanup()
        session.trace.emit("server_lifecycle", phase="session_cleanup_end")


async def wait_tx(tx: TxState, timeout: float = 5.0) -> None:
    await asyncio.wait_for(tx.event.wait(), timeout=timeout)


async def scenario_multi_carrier(
    session: Gate2Session,
    args: argparse.Namespace,
    key: bytes,
) -> None:
    c1 = await client_handshake(session, args.host, args.port, key, 0, 1, 0)
    c96 = await client_handshake(session, args.host, args.port, key, 1, 96, 0)
    stream = await session.open_stream(1, c1)

    payload1 = b"A" * 16384
    tx2 = await session.send_data(stream, payload1, c1)
    # Second Attempt is sent immediately on another Carrier with the same
    # Transmission ID and identical semantic contents.
    await session.send_tx(tx2, c96, reinjection=True)
    await wait_tx(tx2)

    payload2 = b"B" * 16384
    tx3 = await session.send_data(stream, payload2, c1)
    await asyncio.sleep(0.15)
    if tx3.settled:
        raise RuntimeError("fault did not keep second DATA Transmission outstanding")
    await session.close_carrier(1, "gate2-reinjection-fault")
    await session.send_tx(tx3, c96, reinjection=True)
    await wait_tx(tx3)

    c1r = await client_handshake(session, args.host, args.port, key, 1, 1, 1)
    await session.ping(c1r, 0x2201)
    await session.send_retire(c96)
    await session.send_session_close(c96, "multi-carrier-reinjection-complete")


async def scenario_dormant_recovery(
    session: Gate2Session,
    args: argparse.Namespace,
    key: bytes,
) -> None:
    c1 = await client_handshake(session, args.host, args.port, key, 0, 1, 0)
    stream = await session.open_stream(1, c1)
    tx2 = await session.send_data(stream, b"D" * 16384, c1)
    await asyncio.sleep(0.15)
    if tx2.settled:
        raise RuntimeError("fault did not leave DATA outstanding before DORMANT")
    await session.close_carrier(1, "last-carrier-loss")
    await session.wait_for_state("DORMANT")

    c1r = await client_handshake(session, args.host, args.port, key, 1, 1, 1)
    await session.send_credit_probe(c1r, 1)
    await asyncio.wait_for(stream.credit_event.wait(), timeout=5)
    await session.send_tx(tx2, c1r, reinjection=True)
    await wait_tx(tx2)
    await session.send_retire(c1r)
    await asyncio.sleep(0.1)

    # Lose the last Carrier again, then recover once more. Because the local
    # settled prefix is non-zero, recovery refresh must include RETIRE.
    await session.close_carrier(1, "second-last-carrier-loss")
    await session.wait_for_state("DORMANT")
    c1r2 = await client_handshake(session, args.host, args.port, key, 1, 1, 2)
    await session.ping(c1r2, 0x2202)
    await session.send_session_close(c1r2, "dormant-recovery-complete")


async def scenario_ambiguous_replacement(
    session: Gate2Session,
    args: argparse.Namespace,
    key: bytes,
) -> None:
    c1 = await client_handshake(session, args.host, args.port, key, 0, 1, 0)
    await session.close_carrier(1, "prepare-ambiguous-replacement")
    await session.wait_for_state("DORMANT")

    try:
        await client_handshake(session, args.host, args.port, key, 1, 1, 1)
    except AmbiguousHandshake:
        pass
    else:
        raise RuntimeError("expected ambiguous replacement Generation 1")
    c1r = await client_handshake(session, args.host, args.port, key, 1, 1, 2)
    await session.ping(c1r, 0x2301)

    # First-use Carrier ID 96 becomes ambiguous at Generation 0. The Client
    # must recover with a fresh unused Carrier ID at Generation 0 rather than
    # inventing a non-zero first accepted Generation for ID 96.
    try:
        await client_handshake(session, args.host, args.port, key, 1, 96, 0)
    except AmbiguousHandshake:
        pass
    else:
        raise RuntimeError("expected ambiguous first-use Carrier 96 Generation 0")

    c97 = await client_handshake(session, args.host, args.port, key, 1, 97, 0)
    await session.ping(c97, 0x2302)
    await session.send_session_close(c97, "ambiguous-recovery-complete")


async def scenario_fin_reset_retire(
    session: Gate2Session,
    args: argparse.Namespace,
    key: bytes,
) -> None:
    c1 = await client_handshake(session, args.host, args.port, key, 0, 1, 0)
    c96 = await client_handshake(session, args.host, args.port, key, 1, 96, 0)
    stream = await session.open_stream(1, c1)

    tx2 = await session.send_data(stream, b"0123456789", c1)
    await wait_tx(tx2)

    fin = session.alloc_tx(
        FRAME_STREAM_FIN,
        stream.stream_id,
        final_offset=stream.send_offset,
    )
    stream.send_final = stream.send_offset
    await session.send_tx(fin, c1)
    await asyncio.wait_for(stream.stop_received_event.wait(), timeout=5)
    await asyncio.wait_for(stream.reset_sent_event.wait(), timeout=5)

    reset_txs = [
        tx
        for tx in session.local_tx.values()
        if tx.frame_type == FRAME_RESET_STREAM and tx.stream_id == stream.stream_id
    ]
    if len(reset_txs) != 1:
        raise RuntimeError("expected exactly one RESET_STREAM response")
    reset_tx = reset_txs[0]
    await wait_tx(reset_tx)
    if fin.settled:
        raise RuntimeError("FIN unexpectedly settled before reinjection")

    await session.send_tx(fin, c96, reinjection=True)
    await wait_tx(fin)
    await wait_tx(session.local_tx[1])
    if session.settled_through < reset_tx.txid:
        raise RuntimeError("settled prefix did not close FIN/RESET gap")
    await session.send_retire(c96)
    await asyncio.sleep(0.1)
    await session.send_session_close(c96, "fin-reset-retire-complete")


async def scenario_error_scope(
    session: Gate2Session,
    args: argparse.Namespace,
    key: bytes,
) -> None:
    c1 = await client_handshake(session, args.host, args.port, key, 0, 1, 0)
    # This ACK names a Transmission from the Server namespace that the Client
    # has never observed the Server allocate. It must cause Session-scoped
    # TRANSMISSION_ID_ERROR, not Carrier-local closure.
    await session.send_frame(
        c1,
        FRAME_TRANSMISSION_ACK,
        stream_id=1,
        transmission_id=999,
        receiver_timestamp_us=c1.timestamp_us(),
    )
    await asyncio.wait_for(session.done_event.wait(), timeout=5)
    close = session.session_close_received
    if close is None:
        raise RuntimeError("expected SESSION_CLOSE for invalid ACK")
    if int(close["error_code"]) != ERROR_TRANSMISSION_ID:
        raise RuntimeError(f"unexpected error scope/code: {close}")


async def client_main(session: Gate2Session, args: argparse.Namespace, key: bytes) -> Dict[str, object]:
    session.session_id = secrets.token_bytes(16)
    while session.session_id == b"\x00" * 16:
        session.session_id = secrets.token_bytes(16)
    session.set_state("CREATING")

    if args.scenario == "multi-carrier-reinjection":
        await scenario_multi_carrier(session, args, key)
    elif args.scenario == "dormant-recovery":
        await scenario_dormant_recovery(session, args, key)
    elif args.scenario == "ambiguous-replacement":
        await scenario_ambiguous_replacement(session, args, key)
    elif args.scenario == "fin-reset-retire":
        await scenario_fin_reset_retire(session, args, key)
    elif args.scenario == "error-scope":
        await scenario_error_scope(session, args, key)
    else:
        raise RuntimeError(f"unknown scenario {args.scenario}")

    await asyncio.sleep(0.1)
    if session.fatal_error:
        raise RuntimeError(session.fatal_error)
    return session.summary()


def write_result(path: Path, result: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="MPX/4 Draft 11 Gate 2 reference runtime")
    p.add_argument("role", choices=("client", "server"))
    p.add_argument("--scenario", choices=SCENARIOS, required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--trace", type=Path, required=True)
    p.add_argument("--result", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("--write-chunk", type=int, default=0)
    p.add_argument("--max-frame-payload", type=int, default=32768)
    p.add_argument("--max-record-size", type=int, default=65536)
    p.add_argument("--max-streams", type=int, default=32)
    p.add_argument("--max-carriers", type=int, default=4)
    return p


async def amain(args: argparse.Namespace) -> int:
    limits = Limits(
        max_frame_payload=args.max_frame_payload,
        max_record_size=args.max_record_size,
        max_streams=args.max_streams,
        max_carriers=args.max_carriers,
    )
    limits.validate()
    key = transport_key_from_env()
    trace = Trace(args.trace, args.role)
    session = Gate2Session(
        role=args.role,
        trace=trace,
        scenario=args.scenario,
        local_limits=limits,
        write_chunk=args.write_chunk,
    )
    try:
        if args.role == "server":
            result = await server_main(session, args, key)
        else:
            result = await client_main(session, args, key)
        result.update({"status": "PASS", "gate": "Gate 2"})
        write_result(args.result, result)
        return 0
    except Exception as exc:
        trace.emit("endpoint_error", error_type=type(exc).__name__, error=str(exc))
        result = session.summary()
        result.update(
            {
                "status": "FAIL",
                "gate": "Gate 2",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        write_result(args.result, result)
        print(
            f"{args.role}/{args.scenario} failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1
    finally:
        await session.cleanup()
        trace.close()


def main() -> int:
    args = parser().parse_args()
    return asyncio.run(amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
