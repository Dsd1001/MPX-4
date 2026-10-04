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
    FrameTypeProtocolError,
    FRAME_CARRIER_CLOSE,
    FRAME_CREDIT_PROBE,
    FRAME_NAMES,
    FRAME_PADDING,
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
    MAX_VARINT,
    MSG_CLIENT_FINISHED,
    MSG_CLIENT_INIT,
    MSG_HANDSHAKE_REJECT,
    MSG_SERVER_FINISHED,
    MSG_SERVER_INIT,
    MSG_VERSION_NEGOTIATION,
    ProtocolError,
    Trace,
    TransmissionError,
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
    vi_dec,
    vi_enc,
)

ERROR_NO_ERROR = 0x00
ERROR_PROTOCOL_VIOLATION = 0x02
ERROR_AUTHENTICATION_FAILED = 0x03
ERROR_RESOURCE_LIMIT = 0x05
ERROR_SESSION_NOT_FOUND = 0x06
ERROR_SESSION_CONFLICT = 0x07
ERROR_STREAM_LIMIT = 0x08
ERROR_FLOW_CONTROL = 0x09
ERROR_FRAME_ENCODING = 0x0A
ERROR_CARRIER_CONFLICT = 0x0C
ERROR_STREAM_STATE = 0x0E
ERROR_FINAL_SIZE = 0x0F
ERROR_TRANSMISSION_ID = 0x10

STREAM_CREDIT_WINDOW_LIMIT = 16 * 1024 * 1024
SESSION_CREDIT_WINDOW_LIMIT = 128 * 1024 * 1024

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


class VersionNegotiationReceived(RuntimeError):
    def __init__(self, versions: List[int]) -> None:
        super().__init__(f"VERSION_NEGOTIATION {versions}")
        self.versions = versions


class HandshakeRejected(RuntimeError):
    def __init__(self, error_code: int) -> None:
        super().__init__(f"HANDSHAKE_REJECT 0x{error_code:x}")
        self.error_code = error_code


class StreamStateError(ProtocolError):
    pass


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
    lifecycle: str = "OPEN"
    accepted: bool = True
    opening_txid: Optional[int] = None
    preopen_cancel_response: bool = False
    local_terminal_txid: Optional[int] = None
    local_terminal_settled: bool = False
    local_consumed: bool = False
    peer_final_consumed: bool = False
    peer_consumed: int = 0
    peer_maximum: int = 0
    recv_committed: int = 0
    recv_next: int = 0
    recv_final: Optional[int] = None
    send_offset: int = 0
    send_final: Optional[int] = None
    terminal_mode: str = "ACTIVE"
    recv_terminal_mode: str = "ACTIVE"
    send_terminal_mode: str = "ACTIVE"
    stream_error_code: Optional[int] = None
    recv_segments: Dict[int, bytes] = field(default_factory=dict)
    recv_history: Dict[int, bytes] = field(default_factory=dict)
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
        self.protocol_version: Optional[int] = None
        self.supported_versions: Set[int] = {VERSION}
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
        self.pending_candidates: Set[Tuple[int, int]] = set()
        self.established_incarnations: List[Tuple[int, int]] = []
        self.lost_incarnations: List[Tuple[int, int]] = []
        self.ambiguous_attempts: List[Tuple[int, int]] = []

        self.streams: Dict[int, StreamState] = {}
        self.opening_tombstones: Dict[int, Dict[str, object]] = {}
        self.tombstones: Dict[int, Dict[str, object]] = {}
        self.retired_stream_ids: Set[int] = set()
        self.retired_stream_info: Dict[int, Dict[str, object]] = {}
        self.next_stream_id = 1
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
        self.session_peer_consumed = 0
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
        self.dormant_retired = False

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
        if self.dormant_retired and init.session_action == 1:
            raise CandidateReject(ERROR_SESSION_NOT_FOUND, "JOIN Session retention expired")
        if self.state in {"CLOSING", "CLOSED"}:
            raise CandidateReject(ERROR_SESSION_CONFLICT, "Session is closing; candidate JOIN/CREATE forbidden")
        if init.session_action == 0:
            if self.session_id is not None:
                raise CandidateReject(ERROR_SESSION_CONFLICT, "CREATE collided with retained Session")
            if init.generation != 0:
                raise CandidateReject(ERROR_CARRIER_CONFLICT, "first Carrier generation must be zero")
            return

        if init.session_action != 1:
            raise CandidateReject(ERROR_SESSION_CONFLICT, "invalid Session action")
        if self.dormant_retired or self.session_id is None or init.session_id != self.session_id:
            raise CandidateReject(ERROR_SESSION_NOT_FOUND, "JOIN Session not found")
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

    def reserve_candidate(self, init) -> None:
        if any(cid == init.carrier_id and gen >= init.generation for cid, gen in self.pending_candidates):
            raise CandidateReject(ERROR_CARRIER_CONFLICT, "equal/stale candidate already pending")
        self.pending_candidates.add((init.carrier_id, init.generation))

    def release_candidate(self, carrier_id: int, generation: int) -> None:
        self.pending_candidates.discard((carrier_id, generation))

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

    def commit_server_candidate(self, init, protocol_version: int = VERSION) -> None:
        if init.session_action == 0:
            self.session_id = init.session_id
            self.protocol_version = protocol_version
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

    def schedule_resource_close(self, reason: str) -> None:
        if self.state in {"CLOSING", "CLOSED"}:
            return
        carrier = self.choose_carrier() if self.carriers else None
        asyncio.create_task(
            self.fail_session(ERROR_RESOURCE_LIMIT, 0, f"RESOURCE_LIMIT: {reason}", carrier)
        )

    def allocate_stream_id(self) -> int:
        stream_id = self.next_stream_id
        if stream_id > MAX_VARINT:
            self.schedule_resource_close("Stream ID space exhausted")
            raise RuntimeError("Stream ID space exhausted")
        self.next_stream_id += 2
        return stream_id

    def alloc_tx(self, frame_type: int, stream_id: int, **fields: object) -> TxState:
        txid = self.next_txid
        if txid > MAX_VARINT:
            self.schedule_resource_close("Transmission ID space exhausted")
            raise RuntimeError("Transmission ID space exhausted")
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
        stream = self.streams.get(tx.stream_id)
        if stream is not None and tx.frame_type in {FRAME_STREAM_FIN, FRAME_RESET_STREAM}:
            stream.local_terminal_settled = True
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

    def merge_credit_pair(
        self,
        old_consumed: int,
        old_maximum: int,
        new_consumed: int,
        new_maximum: int,
        window_limit: int,
        label: str,
    ) -> Tuple[int, int, str]:
        if new_consumed < 0 or new_maximum < new_consumed:
            raise FlowControlError(f"invalid {label} credit")
        if new_maximum - new_consumed > window_limit:
            raise FlowControlError(f"{label} credit window exceeds Draft 11 limit")
        if new_consumed >= old_consumed and new_maximum >= old_maximum:
            return new_consumed, new_maximum, "newer"
        if new_consumed <= old_consumed and new_maximum <= old_maximum:
            return old_consumed, old_maximum, "stale"
        raise FlowControlError(f"crossed {label} credit pair")

    def retain_ack(self, stream_id: int, txid: int) -> None:
        self.peer_tx_confirmation[txid] = (
            FRAME_TRANSMISSION_ACK,
            {"stream_id": stream_id, "transmission_id": txid},
        )

    async def acknowledge(
        self,
        incoming: Carrier,
        stream_id: int,
        txid: int,
        original_frame_type: int,
    ) -> None:
        self.retain_ack(stream_id, txid)
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
                try:
                    frames = await carrier.recv_record()
                except AuthenticationError as exc:
                    await self.fail_carrier(
                        carrier,
                        ERROR_AUTHENTICATION_FAILED,
                        0,
                        f"AUTHENTICATION_FAILED: {exc}",
                        report=False,
                    )
                    return
                except FrameTypeProtocolError as exc:
                    await self.fail_session(
                        ERROR_PROTOCOL_VIOLATION,
                        exc.frame_type,
                        f"PROTOCOL_VIOLATION: {exc}",
                        carrier,
                    )
                    return
                except ProtocolError as exc:
                    await self.fail_carrier(
                        carrier,
                        ERROR_FRAME_ENCODING,
                        0,
                        f"FRAME_ENCODING_ERROR: {exc}",
                        report=True,
                    )
                    return

                if self.state in {"CLOSING", "CLOSED"}:
                    return
                for frame_type, fields in frames:
                    if self.state in {"CLOSING", "CLOSED"}:
                        return
                    try:
                        await self.handle_frame(carrier, frame_type, fields)
                    except TransmissionError as exc:
                        await self.fail_session(
                            ERROR_TRANSMISSION_ID,
                            frame_type,
                            f"TRANSMISSION_ID_ERROR: {exc}",
                            carrier,
                        )
                    except FlowControlError as exc:
                        await self.fail_session(
                            ERROR_FLOW_CONTROL,
                            frame_type,
                            f"FLOW_CONTROL_ERROR: {exc}",
                            carrier,
                        )
                    except FinalSizeError as exc:
                        await self.fail_session(
                            ERROR_FINAL_SIZE,
                            frame_type,
                            f"FINAL_SIZE_ERROR: {exc}",
                            carrier,
                        )
                    except StreamStateError as exc:
                        await self.fail_session(
                            ERROR_STREAM_STATE,
                            frame_type,
                            f"STREAM_STATE_ERROR: {exc}",
                            carrier,
                        )
                    except ProtocolError as exc:
                        await self.fail_session(
                            ERROR_PROTOCOL_VIOLATION,
                            frame_type,
                            f"PROTOCOL_VIOLATION: {exc}",
                            carrier,
                        )
                    if self.state in {"CLOSING", "CLOSED"}:
                        return
        except asyncio.IncompleteReadError:
            await self.on_carrier_lost(carrier, "transport-eof")
        except (ConnectionError, BrokenPipeError):
            await self.on_carrier_lost(carrier, "transport-error")

    async def fail_carrier(
        self,
        carrier: Carrier,
        error_code: int,
        trigger_frame_type: int,
        reason: str,
        report: bool,
    ) -> None:
        current = self.carriers.get(carrier.carrier_id)
        if current is None or current.generation != carrier.generation:
            return
        if report:
            try:
                await self.send_frame(
                    carrier,
                    FRAME_CARRIER_CLOSE,
                    error_code=error_code,
                    trigger_frame_type=trigger_frame_type,
                    reason=reason[:256],
                )
            except Exception:
                pass
        self.trace.emit(
            "carrier_failed",
            **carrier.base_trace(),
            error_code=error_code,
            trigger_frame_type=trigger_frame_type,
            reason=reason,
        )
        await self._close_writer(carrier)
        await self.on_carrier_lost(carrier, reason)

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
        carriers = list(self.carriers.values())
        for item in carriers:
            await self._close_writer(item)
        self.carriers.clear()
        self.set_state("CLOSED")
        self.done_event.set()

    def retire_stream_to_tombstone(self, stream_id: int) -> Dict[str, object]:
        stream = self.streams.pop(stream_id, None)
        if stream is None:
            raise RuntimeError("Stream not active")
        tombstone = {
            "stream_id": stream_id,
            "recv_final": stream.recv_final,
            "send_final": stream.send_final,
            "terminal_mode": stream.terminal_mode,
            "recv_terminal_mode": stream.recv_terminal_mode,
            "send_terminal_mode": stream.send_terminal_mode,
            "stream_error_code": stream.stream_error_code,
            "opening_txid": stream.opening_txid,
            "opening_decision": "accepted" if stream.accepted else None,
        }
        self.tombstones[stream_id] = tombstone
        self.trace.emit("stream_tombstoned", session_id=self.session_id.hex() if self.session_id else None, stream_id=stream_id)
        return tombstone

    def compact_tombstone(self, stream_id: int) -> None:
        retained = self.tombstones.get(stream_id) or self.opening_tombstones.get(stream_id)
        if retained is None:
            raise RuntimeError("no Stream tombstone")
        unsettled = [
            tx.txid for tx in self.local_tx.values()
            if tx.stream_id == stream_id and not tx.settled
        ]
        if unsettled:
            raise RuntimeError(f"cannot compact Stream with unsettled local Transmissions {unsettled}")
        missing_replay = []
        for txid, semantic in self.peer_tx_semantics.items():
            semantic_fields = dict(semantic[1])
            if int(semantic_fields.get("stream_id", -1)) != stream_id:
                continue
            if txid > self.peer_retired_through and txid not in self.peer_tx_confirmation:
                missing_replay.append(txid)
        if missing_replay:
            raise RuntimeError(f"cannot compact Stream without confirmation replay {missing_replay}")
        info = dict(retained)
        if "opening_decision" not in info and "decision" in info:
            info["opening_decision"] = info.get("decision")
        self.retired_stream_info[stream_id] = info
        self.tombstones.pop(stream_id, None)
        self.opening_tombstones.pop(stream_id, None)
        self.retired_stream_ids.add(stream_id)
        self.trace.emit("stream_identity_retired", session_id=self.session_id.hex() if self.session_id else None, stream_id=stream_id)

    def retire_dormant(self) -> None:
        if self.state != "DORMANT" or self.carriers:
            raise RuntimeError("Session is not retainable DORMANT state")
        self.dormant_retired = True
        self.set_state("CLOSED", reason="dormant-retention-expired")

    def validate_peer_stream_id(self, stream_id: int) -> None:
        if stream_id <= 0 or (stream_id & 1) == 0:
            raise StreamStateError("invalid client Stream ID")

    async def replay_peer_confirmation(self, incoming: Carrier, txid: int) -> bool:
        retained = self.peer_tx_confirmation.get(txid)
        if retained is None:
            return False
        response_type, response_fields = retained
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        wire_fields = dict(response_fields)
        if response_type == FRAME_TRANSMISSION_ACK:
            wire_fields["receiver_timestamp_us"] = reply.timestamp_us()
        await self.send_frame(reply, response_type, **wire_fields)
        self.trace.emit(
            "confirmation_replayed",
            session_id=self.session_id.hex() if self.session_id else None,
            transmission_id=txid,
            frame_type=FRAME_NAMES.get(response_type, response_type),
        )
        return True

    async def replay_retired_reliable(
        self,
        incoming: Carrier,
        frame_type: int,
        fields: Dict[str, object],
    ) -> bool:
        stream_id = int(fields["stream_id"])
        if stream_id not in self.retired_stream_ids:
            return False
        txid = int(fields["transmission_id"])
        if txid <= self.peer_retired_through:
            return True
        old = self.peer_tx_semantics.get(txid)
        if old is not None:
            if old != self.peer_semantic(frame_type, fields):
                raise TransmissionError(f"conflicting retired peer Transmission {txid}")
            if not await self.replay_peer_confirmation(incoming, txid):
                raise TransmissionError(f"retired peer Transmission {txid} lacks confirmation replay")
            return True

        info = self.retired_stream_info.get(stream_id)
        if info is None:
            return False
        opening_decision = info.get("opening_decision", info.get("decision"))
        if opening_decision != "accepted":
            return False

        if frame_type == FRAME_STREAM_FIN:
            final_offset = int(fields["final_offset"])
            recorded_final = info.get("recv_final")
            if recorded_final is None:
                raise StreamStateError("retired Stream lacks receive Final Offset")
            if int(recorded_final) != final_offset:
                raise FinalSizeError("late FIN contradicts retired Final Offset")
        elif frame_type == FRAME_RESET_STREAM:
            final_offset = int(fields["final_offset"])
            recorded_final = info.get("recv_final")
            if recorded_final is None:
                raise StreamStateError("retired Stream lacks receive Final Offset")
            if int(recorded_final) != final_offset:
                raise FinalSizeError("late RESET contradicts retired Final Offset")
            error_code = int(fields["stream_error_code"])
            if info.get("recv_terminal_mode") == "RESET":
                recorded_error = info.get("stream_error_code")
                if recorded_error is not None and int(recorded_error) != error_code:
                    raise StreamStateError("late RESET changes retired Stream Error Code")
            else:
                info["recv_terminal_mode"] = "RESET"
                info["terminal_mode"] = "RESET"
                info["stream_error_code"] = error_code
        elif frame_type == FRAME_STREAM_DATA:
            recorded_final = info.get("recv_final")
            if recorded_final is None:
                raise StreamStateError("retired Stream lacks receive Final Offset")
            data = bytes(fields["data"])
            end = int(fields["offset"]) + len(data)
            if end > int(recorded_final):
                raise FinalSizeError("late DATA exceeds retired Final Offset")
            self.application_duplicate_bytes_suppressed += len(data)
        elif frame_type == FRAME_STOP_SENDING:
            if info.get("send_final") is None or info.get("send_terminal_mode") not in {"FIN", "RESET"}:
                raise StreamStateError("STOP_SENDING cannot target an unterminated retired send direction")
        elif frame_type == FRAME_STREAM_CONSUMED:
            recorded_final = info.get("send_final")
            if recorded_final is None or int(recorded_final) != int(fields["final_offset"]):
                raise FinalSizeError("late STREAM_CONSUMED contradicts retired local Final Offset")
        else:
            return False

        self.register_peer_tx(frame_type, fields)
        await self.acknowledge(incoming, stream_id, txid, frame_type)
        self.trace.emit(
            "retired_confirmation_recovered",
            session_id=self.session_id.hex() if self.session_id else None,
            stream_id=stream_id,
            transmission_id=txid,
            frame_type=FRAME_NAMES.get(frame_type, frame_type),
        )
        return True

    async def send_stream_consumed(self, stream: StreamState, carrier: Carrier) -> TxState:
        if stream.recv_final is None:
            raise RuntimeError("cannot consume Stream without peer final size")
        tx = self.alloc_tx(
            FRAME_STREAM_CONSUMED,
            stream.stream_id,
            final_offset=stream.recv_final,
        )
        stream.local_consumed = True
        await self.send_tx(tx, carrier)
        return tx

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

        if frame_type == FRAME_PADDING:
            return

        if frame_type == FRAME_SESSION_CREDIT:
            consumed = int(fields["consumed_bytes"])
            maximum = int(fields["maximum_bytes"])
            (
                self.session_peer_consumed,
                self.session_peer_maximum,
                merge_result,
            ) = self.merge_credit_pair(
                self.session_peer_consumed,
                self.session_peer_maximum,
                consumed,
                maximum,
                SESSION_CREDIT_WINDOW_LIMIT,
                "Session",
            )
            self.trace.emit(
                "credit_merge",
                session_id=self.session_id.hex() if self.session_id else None,
                scope="session",
                consumed=consumed,
                maximum=maximum,
                result=merge_result,
            )
            self.session_credit_event.set()
            return

        if frame_type == FRAME_STREAM_CREDIT:
            stream_id = int(fields["stream_id"])
            stream = self.streams.get(stream_id)
            if stream is None:
                tombstone = self.tombstones.get(stream_id)
                if tombstone is not None:
                    consumed = int(fields["consumed_offset"])
                    maximum = int(fields["maximum_offset"])
                    send_final = tombstone.get("send_final")
                    if send_final is not None and consumed > send_final:
                        raise FinalSizeError("STREAM_CREDIT Consumed Offset exceeds tombstone local Final Offset")
                    self.merge_credit_pair(0, 0, consumed, maximum, STREAM_CREDIT_WINDOW_LIMIT, "Stream")
                    return
                if stream_id in self.retired_stream_ids:
                    return
                raise StreamStateError("Stream credit for unknown Stream")
            consumed = int(fields["consumed_offset"])
            maximum = int(fields["maximum_offset"])
            if stream.send_final is not None and consumed > stream.send_final:
                raise FinalSizeError("STREAM_CREDIT Consumed Offset exceeds local Final Offset")
            stream.peer_consumed, stream.peer_maximum, merge_result = self.merge_credit_pair(
                stream.peer_consumed,
                stream.peer_maximum,
                consumed,
                maximum,
                STREAM_CREDIT_WINDOW_LIMIT,
                "Stream",
            )
            self.trace.emit(
                "credit_merge",
                session_id=self.session_id.hex() if self.session_id else None,
                scope="stream",
                stream_id=stream_id,
                consumed=consumed,
                maximum=maximum,
                result=merge_result,
            )
            if stream.lifecycle == "OPENING" and not stream.accepted:
                stream.accepted = True
                self.trace.emit("opening_acceptance_evidence", session_id=self.session_id.hex() if self.session_id else None, stream_id=stream_id, frame_type="STREAM_CREDIT")
            elif stream.lifecycle == "OPENING_CANCEL_PENDING" and not stream.accepted:
                stream.accepted = True
                stream.lifecycle = "OPEN"
            stream.credit_event.set()
            return

        if frame_type == FRAME_STREAM_OPEN:
            await self.handle_stream_open(incoming, fields)
            return

        if frame_type == FRAME_STREAM_OPEN_OK:
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            self.validate_peer_stream_id(stream_id)
            stream = self.streams.get(stream_id)
            if stream is not None:
                if stream.accepted and stream.lifecycle != "OPENING":
                    self.settle_tx(txid, "OPEN_OK", stream_id)
                    return
                self.settle_tx(txid, "OPEN_OK", stream_id)
                stream.accepted = True
                stream.lifecycle = "OPEN"
                stream.open_event.set()
                return
            self.settle_tx(txid, "OPEN_OK", stream_id)
            retained = self.opening_tombstones.get(stream_id)
            if retained is None:
                retained = self.tombstones.get(stream_id)
            if retained is None:
                retained = self.retired_stream_info.get(stream_id)
            if retained is None:
                raise StreamStateError("OPEN_OK for unknown Stream identity")
            decision = retained.get("opening_decision", retained.get("decision"))
            if decision != "accepted":
                raise StreamStateError("OPEN_OK conflicts with retained opening decision")
            return

        if frame_type == FRAME_STREAM_OPEN_REJECT:
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            error_code = int(fields["error_code"])
            self.validate_peer_stream_id(stream_id)
            stream = self.streams.get(stream_id)
            if stream is not None:
                if stream.accepted:
                    raise StreamStateError("OPEN_REJECT after acceptance evidence")
                self.settle_tx(txid, "OPEN_REJECT", stream_id)
                normal_cancel = stream.lifecycle == "OPENING_CANCEL_PENDING"
                self.streams.pop(stream_id, None)
                self.opening_tombstones[stream_id] = {
                    "opening_txid": txid,
                    "decision": "cancelled" if normal_cancel else "rejected",
                    "opening_decision": "cancelled" if normal_cancel else "rejected",
                    "error_code": error_code,
                }
                return
            self.settle_tx(txid, "OPEN_REJECT", stream_id)
            retained = self.opening_tombstones.get(stream_id)
            if retained is None:
                retained = self.tombstones.get(stream_id)
            if retained is None:
                retained = self.retired_stream_info.get(stream_id)
            if retained is None:
                raise StreamStateError("OPEN_REJECT for unknown Stream identity")
            decision = retained.get("opening_decision", retained.get("decision"))
            if decision not in {"rejected", "cancelled"}:
                raise StreamStateError("OPEN_REJECT conflicts with retained acceptance")
            recorded_txid = retained.get("opening_txid")
            if recorded_txid is not None and int(recorded_txid) != txid:
                raise TransmissionError("OPEN_REJECT references a different opening Transmission")
            recorded_error = retained.get("error_code")
            if recorded_error is not None and int(recorded_error) != error_code:
                raise StreamStateError("OPEN_REJECT changed retained rejection reason")
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
            stream_id = int(fields["stream_id"])
            txid = int(fields["transmission_id"])
            final_offset = int(fields["final_offset"])
            stream = self.streams.get(stream_id)
            if stream is None:
                tomb = self.tombstones.get(stream_id)
                if tomb is not None:
                    if tomb.get("send_final") != final_offset:
                        raise FinalSizeError("STREAM_CONSUMED final size differs from tombstone")
                elif stream_id in self.retired_stream_ids:
                    if await self.replay_retired_reliable(incoming, frame_type, fields):
                        return
                    raise StreamStateError("STREAM_CONSUMED for retired Stream without replay state")
                else:
                    raise StreamStateError("STREAM_CONSUMED for unknown Stream")
            else:
                if stream.send_final is None or stream.send_final != final_offset:
                    raise FinalSizeError("STREAM_CONSUMED Final Offset mismatch")
                stream.peer_final_consumed = True
            self.register_peer_tx(frame_type, fields)
            await self.acknowledge(incoming, stream_id, txid, frame_type)
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
                for txid in [x for x in self.peer_tx_confirmation if x <= value]:
                    self.peer_tx_confirmation.pop(txid, None)
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
            await self.send_frame(incoming, FRAME_PONG, token=int(fields["token"]))
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
            if self.state == "CLOSED":
                return
            self.session_close_received = dict(fields)
            self.trace.emit(
                "session_close_received",
                **incoming.base_trace(),
                error_code=int(fields["error_code"]),
                trigger_frame_type=int(fields["trigger_frame_type"]),
                reason=str(fields.get("reason", "")),
            )
            self.set_state("CLOSING")
            carriers = list(self.carriers.values())
            for carrier in carriers:
                await self._close_writer(carrier)
            self.carriers.clear()
            self.set_state("CLOSED")
            self.done_event.set()
            return

        raise ProtocolError(f"Gate 2 runtime does not handle {FRAME_NAMES.get(frame_type, frame_type)}")

    async def handle_stream_open(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        if self.role != "server":
            raise StreamStateError("server-initiated Streams are not defined by Draft 11 Core")
        stream_id = int(fields["stream_id"])
        txid = int(fields["transmission_id"])
        self.validate_peer_stream_id(stream_id)

        opening = self.opening_tombstones.get(stream_id)
        if opening is not None:
            recorded_txid = opening.get("opening_txid")
            if recorded_txid is not None and int(recorded_txid) != txid:
                raise TransmissionError("STREAM_OPEN reused retained Stream ID with a different Transmission")
            self.register_peer_tx(FRAME_STREAM_OPEN, fields)
            if recorded_txid is not None and await self.replay_peer_confirmation(incoming, txid):
                return
            if recorded_txid is not None and txid <= self.peer_retired_through:
                return
            error_code = int(opening.get("error_code", ERROR_STREAM_STATE))
            opening["opening_txid"] = txid
            opening["opening_decision"] = "cancelled" if str(opening.get("decision", "")).startswith("preopen") else opening.get("decision", "rejected")
            opening["error_code"] = error_code
            reject_fields = {"stream_id": stream_id, "transmission_id": txid, "error_code": error_code}
            self.peer_tx_confirmation[txid] = (FRAME_STREAM_OPEN_REJECT, reject_fields)
            reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
            await self.send_frame(reply, FRAME_STREAM_OPEN_REJECT, **reject_fields)
            return

        tombstone = self.tombstones.get(stream_id)
        if tombstone is not None:
            recorded_txid = tombstone.get("opening_txid")
            if recorded_txid is not None and int(recorded_txid) != txid:
                raise TransmissionError("STREAM_OPEN conflicts with retained accepted Stream identity")
            if recorded_txid is not None:
                self.register_peer_tx(FRAME_STREAM_OPEN, fields)
                if await self.replay_peer_confirmation(incoming, txid):
                    return
                if txid <= self.peer_retired_through:
                    return
                reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
                ok_fields = {"stream_id": stream_id, "transmission_id": txid}
                self.peer_tx_confirmation[txid] = (FRAME_STREAM_OPEN_OK, ok_fields)
                await self.send_frame(reply, FRAME_STREAM_OPEN_OK, **ok_fields)
                return

        if stream_id in self.retired_stream_ids:
            if await self.replay_retired_reliable(incoming, FRAME_STREAM_OPEN, fields):
                return
            self.register_peer_tx(FRAME_STREAM_OPEN, fields)
            reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
            reject_fields = {"stream_id": stream_id, "transmission_id": txid, "error_code": ERROR_STREAM_STATE}
            self.peer_tx_confirmation[txid] = (FRAME_STREAM_OPEN_REJECT, reject_fields)
            await self.send_frame(reply, FRAME_STREAM_OPEN_REJECT, **reject_fields)
            return

        stream = self.streams.get(stream_id)
        if stream is not None and stream.opening_txid is not None and stream.opening_txid != txid:
            raise TransmissionError("STREAM_OPEN reused Stream ID with a different Transmission")
        duplicate = self.register_peer_tx(FRAME_STREAM_OPEN, fields)
        if stream is not None and duplicate:
            if await self.replay_peer_confirmation(incoming, txid):
                return
        if stream is not None and not duplicate:
            raise TransmissionError("STREAM_OPEN reused Stream ID with a different Transmission")
        if stream is None and len(self.streams) >= self.local_limits.max_streams:
            reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
            reject_fields = {"stream_id": stream_id, "transmission_id": txid, "error_code": ERROR_STREAM_LIMIT}
            self.opening_tombstones[stream_id] = {
                "opening_txid": txid,
                "decision": "rejected",
                "opening_decision": "rejected",
                "error_code": ERROR_STREAM_LIMIT,
            }
            self.peer_tx_confirmation[txid] = (FRAME_STREAM_OPEN_REJECT, reject_fields)
            await self.send_frame(reply, FRAME_STREAM_OPEN_REJECT, **reject_fields)
            return
        if stream is None:
            stream = StreamState(stream_id=stream_id, lifecycle="OPEN", accepted=True)
            stream.opening_txid = txid
            self.streams[stream_id] = stream
            self.trace.emit(
                "stream_created",
                session_id=self.session_id.hex() if self.session_id else None,
                stream_id=stream_id,
            )
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        ok_fields = {"stream_id": stream_id, "transmission_id": txid}
        self.peer_tx_confirmation[txid] = (FRAME_STREAM_OPEN_OK, ok_fields)
        await self.send_frame(reply, FRAME_STREAM_OPEN_OK, **ok_fields)
        await self.send_frame(
            reply,
            FRAME_STREAM_CREDIT,
            stream_id=stream_id,
            consumed_offset=0,
            maximum_offset=stream.local_maximum,
        )
        self.stream_credit_refreshes += 1

    def validate_stream_byte_identity(self, stream: StreamState, offset: int, data: bytes) -> None:
        end = offset + len(data)
        for old_offset, old_data in stream.recv_history.items():
            old_end = old_offset + len(old_data)
            overlap_start = max(offset, old_offset)
            overlap_end = min(end, old_end)
            if overlap_start >= overlap_end:
                continue
            new_slice = data[overlap_start - offset : overlap_end - offset]
            old_slice = old_data[overlap_start - old_offset : overlap_end - old_offset]
            if new_slice != old_slice:
                raise ProtocolError("conflicting overlapping Stream bytes")

    def remember_received_chunk(self, stream: StreamState, offset: int, data: bytes) -> None:
        previous = stream.recv_history.get(offset)
        if previous is None or len(data) > len(previous):
            stream.recv_history[offset] = data
        pending = stream.recv_segments.get(offset)
        if pending is None or len(data) > len(pending):
            stream.recv_segments[offset] = data

    def drain_contiguous_receive_data(self, stream: StreamState) -> None:
        while True:
            candidates = [
                (start, chunk)
                for start, chunk in stream.recv_history.items()
                if start <= stream.recv_next < start + len(chunk)
            ]
            if not candidates:
                break
            start, chunk = max(candidates, key=lambda item: item[0] + len(item[1]))
            tail = chunk[stream.recv_next - start :]
            if not tail:
                break
            stream.recv_data.extend(tail)
            stream.recv_next += len(tail)
            self.application_rx_bytes += len(tail)
        for start, chunk in list(stream.recv_segments.items()):
            if start + len(chunk) <= stream.recv_next:
                stream.recv_segments.pop(start, None)

    async def handle_stream_data(self, incoming: Carrier, fields: Dict[str, object]) -> None:
        stream_id = int(fields["stream_id"])
        self.validate_peer_stream_id(stream_id)
        offset = int(fields["offset"])
        txid = int(fields["transmission_id"])
        data = bytes(fields["data"])  # type: ignore[arg-type]
        stream = self.streams.get(stream_id)
        if stream is None:
            tomb = self.tombstones.get(stream_id)
            if tomb is not None:
                final = tomb.get("recv_final")
                end = offset + len(data)
                if final is not None and end > int(final):
                    raise FinalSizeError("stale DATA exceeds tombstone Final Offset")
                duplicate = self.register_peer_tx(FRAME_STREAM_DATA, fields)
                if not duplicate:
                    self.application_duplicate_bytes_suppressed += len(data)
                await self.acknowledge(incoming, stream_id, txid, FRAME_STREAM_DATA)
                return
            if stream_id in self.retired_stream_ids:
                if await self.replay_retired_reliable(incoming, FRAME_STREAM_DATA, fields):
                    return
                raise StreamStateError("DATA for retired Stream without replay state")
            raise StreamStateError("DATA for unknown Stream")
        if stream.lifecycle in {"OPENING", "OPENING_CANCEL_PENDING"} and not stream.accepted:
            raise StreamStateError("DATA before Stream acceptance")
        end = offset + len(data)
        if stream.recv_final is not None and end > stream.recv_final:
            raise FinalSizeError("DATA exceeds established Final Offset")
        if end > stream.local_maximum:
            raise FlowControlError("Stream credit exceeded")

        duplicate = self.register_peer_tx(FRAME_STREAM_DATA, fields)
        if not duplicate:
            self.validate_stream_byte_identity(stream, offset, data)
            self.remember_received_chunk(stream, offset, data)
            old_committed = stream.recv_committed
            new_committed = max(stream.recv_committed, end)
            delta = new_committed - old_committed
            if self.session_recv_committed + delta > self.session_local_maximum:
                raise FlowControlError("Session credit exceeded")
            self.session_recv_committed += delta
            stream.recv_committed = new_committed

            if stream.recv_terminal_mode == "RESET":
                self.application_duplicate_bytes_suppressed += len(data)
                self.trace.emit(
                    "application_delivery_suppressed",
                    session_id=self.session_id.hex() if self.session_id else None,
                    stream_id=stream_id,
                    transmission_id=txid,
                    reason="RESET authoritative",
                    data_length=len(data),
                )
            else:
                self.drain_contiguous_receive_data(stream)
        else:
            self.application_duplicate_bytes_suppressed += len(data)

        self.retain_ack(stream_id, txid)
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
        self.validate_peer_stream_id(stream_id)
        txid = int(fields["transmission_id"])
        final_offset = int(fields["final_offset"])
        stream = self.streams.get(stream_id)
        if stream is None:
            tomb = self.tombstones.get(stream_id)
            if tomb is not None:
                if tomb.get("recv_final") != final_offset:
                    raise FinalSizeError("FIN contradicts tombstone Final Offset")
                self.register_peer_tx(FRAME_STREAM_FIN, fields)
                await self.acknowledge(incoming, stream_id, txid, FRAME_STREAM_FIN)
                return
            if stream_id in self.retired_stream_ids:
                if await self.replay_retired_reliable(incoming, FRAME_STREAM_FIN, fields):
                    return
                raise StreamStateError("FIN for retired Stream without replay state")
            raise StreamStateError("FIN for unknown Stream")
        if stream.lifecycle == "OPENING" and not stream.accepted:
            if final_offset != 0:
                raise StreamStateError("pre-acceptance FIN must have Final Offset 0")
            stream.accepted = True
        duplicate = self.register_peer_tx(FRAME_STREAM_FIN, fields)
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
        if stream.recv_terminal_mode != "RESET":
            stream.recv_terminal_mode = "FIN"
            stream.terminal_mode = "FIN"

        self.retain_ack(stream_id, txid)
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
        self.validate_peer_stream_id(stream_id)
        txid = int(fields["transmission_id"])
        final_offset = int(fields["final_offset"])
        stream = self.streams.get(stream_id)
        if stream is None:
            tomb = self.tombstones.get(stream_id)
            if tomb is not None:
                if tomb.get("recv_final") != final_offset:
                    raise FinalSizeError("RESET contradicts tombstone Final Offset")
                self.register_peer_tx(FRAME_RESET_STREAM, fields)
                await self.acknowledge(incoming, stream_id, txid, FRAME_RESET_STREAM)
                return
            opening = self.opening_tombstones.get(stream_id)
            if opening is not None:
                if final_offset != 0:
                    raise StreamStateError("pre-open RESET must retain Final Offset 0")
                self.register_peer_tx(FRAME_RESET_STREAM, fields)
                await self.acknowledge(incoming, stream_id, txid, FRAME_RESET_STREAM)
                return
            if stream_id in self.retired_stream_ids:
                if await self.replay_retired_reliable(incoming, FRAME_RESET_STREAM, fields):
                    return
                raise StreamStateError("RESET for retired Stream without replay state")
            if self.role == "server" and final_offset == 0:
                self.register_peer_tx(FRAME_RESET_STREAM, fields)
                self.opening_tombstones[stream_id] = {
                    "decision": "preopen-reset",
                    "recv_final": 0,
                    "terminal_txid": txid,
                }
                await self.acknowledge(incoming, stream_id, txid, FRAME_RESET_STREAM)
                return
            raise StreamStateError("RESET for unknown Stream")
        if stream.lifecycle == "OPENING_CANCEL_PENDING" and not stream.accepted and final_offset == 0:
            stream.preopen_cancel_response = True
            stream.recv_final = 0
            stream.recv_terminal_mode = "RESET"
            stream.terminal_mode = "RESET"
            self.register_peer_tx(FRAME_RESET_STREAM, fields)
            await self.acknowledge(incoming, stream_id, txid, FRAME_RESET_STREAM)
            return
        if stream.lifecycle == "OPENING" and not stream.accepted:
            if final_offset != 0:
                raise StreamStateError("pre-acceptance RESET must have Final Offset 0")
            stream.accepted = True
        duplicate = self.register_peer_tx(FRAME_RESET_STREAM, fields)
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
        stream.recv_terminal_mode = "RESET"
        stream.terminal_mode = "RESET"
        stream.stream_error_code = int(fields["stream_error_code"])
        self.retain_ack(stream_id, txid)
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
        self.validate_peer_stream_id(stream_id)
        txid = int(fields["transmission_id"])
        stream = self.streams.get(stream_id)
        if stream is None:
            tombstone = self.tombstones.get(stream_id)
            if tombstone is not None:
                self.register_peer_tx(FRAME_STOP_SENDING, fields)
                await self.acknowledge(incoming, stream_id, txid, FRAME_STOP_SENDING)
                return
            opening = self.opening_tombstones.get(stream_id)
            if opening is not None:
                self.register_peer_tx(FRAME_STOP_SENDING, fields)
                await self.acknowledge(incoming, stream_id, txid, FRAME_STOP_SENDING)
                return
            if stream_id in self.retired_stream_ids:
                if await self.replay_retired_reliable(incoming, FRAME_STOP_SENDING, fields):
                    return
                raise StreamStateError("STOP_SENDING for retired Stream without replay state")
            if self.role == "server":
                duplicate = self.register_peer_tx(FRAME_STOP_SENDING, fields)
                self.opening_tombstones[stream_id] = {
                    "decision": "preopen-stop",
                    "terminal_txid": txid,
                }
                reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
                self.retain_ack(stream_id, txid)
                await self.send_frame(
                    reply,
                    FRAME_TRANSMISSION_ACK,
                    stream_id=stream_id,
                    transmission_id=txid,
                    receiver_timestamp_us=reply.timestamp_us(),
                )
                if not duplicate:
                    tx = self.alloc_tx(
                        FRAME_RESET_STREAM,
                        stream_id,
                        final_offset=0,
                        stream_error_code=int(fields["stream_error_code"]),
                    )
                    await self.send_tx(tx, reply)
                return
            raise StreamStateError("STOP_SENDING for unknown Stream")
        if stream.lifecycle == "OPENING" and not stream.accepted:
            stream.accepted = True
        duplicate = self.register_peer_tx(FRAME_STOP_SENDING, fields)
        reply = self.alternate_carrier(incoming) if len(self.carriers) > 1 else incoming
        self.retain_ack(stream_id, txid)
        await self.send_frame(
            reply,
            FRAME_TRANSMISSION_ACK,
            stream_id=stream_id,
            transmission_id=txid,
            receiver_timestamp_us=reply.timestamp_us(),
        )
        stream.stop_received_event.set()
        send_closed = stream.send_terminal_mode == "RESET" or (
            stream.send_terminal_mode == "FIN" and stream.local_terminal_settled
        )
        if not duplicate and not send_closed:
            final_offset = stream.send_final if stream.send_final is not None else stream.send_offset
            tx = self.alloc_tx(
                FRAME_RESET_STREAM,
                stream_id,
                final_offset=final_offset,
                stream_error_code=int(fields["stream_error_code"]),
            )
            stream.send_final = final_offset
            stream.send_terminal_mode = "RESET"
            stream.local_terminal_txid = tx.txid
            stream.stream_error_code = int(fields["stream_error_code"])
            await self.send_tx(tx, reply)
            stream.reset_sent_event.set()

    async def open_stream(self, stream_id: int, carrier: Carrier) -> StreamState:
        if self.state != "ACTIVE":
            raise RuntimeError("new Stream forbidden unless Session is ACTIVE")
        if stream_id <= 0 or stream_id % 2 == 0:
            raise RuntimeError("invalid local Stream ID")
        if stream_id in self.streams or stream_id in self.opening_tombstones or stream_id in self.tombstones or stream_id in self.retired_stream_ids:
            raise RuntimeError("Stream ID already used")
        stream = StreamState(stream_id=stream_id, lifecycle="OPENING", accepted=False)
        self.streams[stream_id] = stream
        tx = self.alloc_tx(FRAME_STREAM_OPEN, stream_id)
        stream.opening_txid = tx.txid
        await self.send_tx(tx, carrier)
        await asyncio.wait_for(stream.open_event.wait(), timeout=10)
        await asyncio.wait_for(stream.credit_event.wait(), timeout=10)
        return stream

    async def open_next_stream(self, carrier: Carrier) -> StreamState:
        return await self.open_stream(self.allocate_stream_id(), carrier)

    async def begin_preopen_cancel(self, stream_id: int, carrier: Carrier, reason: int = STREAM_REASON_TEST) -> StreamState:
        if stream_id in self.streams or stream_id in self.opening_tombstones or stream_id in self.tombstones or stream_id in self.retired_stream_ids:
            raise RuntimeError("Stream ID already used")
        stream = StreamState(stream_id=stream_id, lifecycle="OPENING_CANCEL_PENDING", accepted=False)
        self.streams[stream_id] = stream
        open_tx = self.alloc_tx(FRAME_STREAM_OPEN, stream_id)
        stream.opening_txid = open_tx.txid
        stop_tx = self.alloc_tx(FRAME_STOP_SENDING, stream_id, stream_error_code=reason)
        await self.send_tx(stop_tx, carrier)
        return stream

    async def send_pending_open(self, stream_id: int, carrier: Carrier) -> None:
        stream = self.streams[stream_id]
        if stream.opening_txid is None:
            raise RuntimeError("no pending STREAM_OPEN")
        await self.send_tx(self.local_tx[stream.opening_txid], carrier)

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
        carriers = list(self.carriers.values())
        for item in carriers:
            await self._close_writer(item)
        self.carriers.clear()
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
                "recv_terminal_mode": stream.recv_terminal_mode,
                "send_terminal_mode": stream.send_terminal_mode,
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
    if session.state in {"CLOSING", "CLOSED"}:
        raise RuntimeError("Session is closing; no new Carrier candidate may be created")
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

    message_type, message_body, server_init = await read_message(reader)
    if message_type == MSG_VERSION_NEGOTIATION:
        count, pos = vi_dec(message_body)
        versions: List[int] = []
        for _ in range(count):
            item, pos = vi_dec(message_body, pos)
            versions.append(item)
        if pos != len(message_body):
            raise ProtocolError("VERSION_NEGOTIATION trailing bytes")
        writer.close()
        await writer.wait_closed()
        session.trace.emit("version_negotiation_received", versions=versions, automatic_retry=False)
        raise VersionNegotiationReceived(versions)
    if message_type == MSG_HANDSHAKE_REJECT:
        error_code, pos = vi_dec(message_body)
        if pos != len(message_body):
            raise ProtocolError("HANDSHAKE_REJECT trailing bytes")
        writer.close()
        await writer.wait_closed()
        session.trace.emit("handshake_reject_received", error_code=error_code, state_mutated=False)
        raise HandshakeRejected(error_code)
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
        message_type, message_body, server_finished = await read_message(reader)
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

    if message_type == MSG_HANDSHAKE_REJECT:
        error_code, pos = vi_dec(message_body)
        if pos != len(message_body):
            raise ProtocolError("HANDSHAKE_REJECT trailing bytes")
        writer.close()
        await writer.wait_closed()
        session.trace.emit("handshake_reject_received", error_code=error_code, state_mutated=False)
        raise HandshakeRejected(error_code)
    if message_type == MSG_VERSION_NEGOTIATION:
        writer.close()
        await writer.wait_closed()
        raise ProtocolError("VERSION_NEGOTIATION after SERVER_INIT")
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
        session.protocol_version = VERSION
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
    if version not in session.supported_versions:
        offered = sorted(session.supported_versions, reverse=True)
        body = vi_enc(len(offered)) + b"".join(vi_enc(v) for v in offered)
        await write_raw(writer, encode_message(MSG_VERSION_NEGOTIATION, body), session.write_chunk)
        session.trace.emit("version_negotiation_sent", requested_version=version, supported_versions=offered)
        writer.close()
        await writer.wait_closed()
        return None
    preface = magic + version_raw

    message_type, _, client_init = await read_message(reader)
    if message_type != MSG_CLIENT_INIT:
        raise ProtocolError("expected CLIENT_INIT")
    init = parse_client_init(client_init)
    try:
        if session.protocol_version is not None and version != session.protocol_version:
            raise CandidateReject(ERROR_SESSION_CONFLICT, "candidate Protocol Version differs from Session")
        session.validate_server_candidate(init)
    except CandidateReject as exc:
        await write_raw(
            writer,
            encode_message(MSG_HANDSHAKE_REJECT, vi_enc(exc.error_code)),
            session.write_chunk,
        )
        session.trace.emit(
            "handshake_reject_sent",
            error_code=exc.error_code,
            carrier_id=init.carrier_id,
            generation=init.generation,
        )
        raise
    try:
        session.reserve_candidate(init)
    except CandidateReject as exc:
        await write_raw(
            writer,
            encode_message(MSG_HANDSHAKE_REJECT, vi_enc(exc.error_code)),
            session.write_chunk,
        )
        session.trace.emit(
            "handshake_reject_sent",
            error_code=exc.error_code,
            carrier_id=init.carrier_id,
            generation=init.generation,
        )
        raise
    session.trace.emit(
        "handshake_recv",
        stage="CLIENT_INIT",
        session_id=init.session_id.hex(),
        carrier_id=init.carrier_id,
        generation=init.generation,
        session_action="CREATE" if init.session_action == 0 else "JOIN",
    )

    try:
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
    except Exception:
        session.release_candidate(init.carrier_id, init.generation)
        raise

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
    session.commit_server_candidate(init, protocol_version=version)
    session.release_candidate(init.carrier_id, init.generation)
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
        except (AuthenticationError, ProtocolError, asyncio.IncompleteReadError) as exc:
            session.trace.emit(
                "candidate_handshake_failed",
                error_type=type(exc).__name__,
                error=str(exc),
                session_preserved=session.session_id is not None,
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
