#!/usr/bin/env python3
"""Small executable Session/Stream model for the Draft 11 Mandatory profile.

This is runtime test code, not the specification validator.  It exists so
Gate 3 can exercise stateful requirements that are awkward to force through a
single TCP happy-path endpoint (identity exhaustion, tombstone compaction,
opening races, credit reordering, candidate admission, and failure scope).

The model intentionally exposes protocol state rather than test-vector
"expected" strings.  Gate 3 drives operations and checks observed state/errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

MAX_VARINT = (1 << 62) - 1

ERR_RESOURCE_LIMIT = "RESOURCE_LIMIT"
ERR_SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
ERR_SESSION_CONFLICT = "SESSION_CONFLICT"
ERR_STREAM_LIMIT = "STREAM_LIMIT"
ERR_FLOW_CONTROL = "FLOW_CONTROL_ERROR"
ERR_FINAL_SIZE = "FINAL_SIZE_ERROR"
ERR_CARRIER_CONFLICT = "CARRIER_CONFLICT"
ERR_STREAM_STATE = "STREAM_STATE_ERROR"
ERR_TRANSMISSION_ID = "TRANSMISSION_ID_ERROR"
ERR_FRAME_ENCODING = "FRAME_ENCODING_ERROR"
ERR_PROTOCOL = "PROTOCOL_VIOLATION"
ERR_AUTH = "AUTHENTICATION_FAILED"


class ModelFailure(RuntimeError):
    def __init__(self, code: str, scope: str, trigger: Optional[str] = None) -> None:
        super().__init__(f"{code} ({scope})")
        self.code = code
        self.scope = scope
        self.trigger = trigger


@dataclass
class Tx:
    txid: int
    frame: str
    stream_id: int
    semantic: Tuple[object, ...]
    confirmation: str
    allocated: bool = True
    attempted: bool = False
    settled: bool = False


@dataclass
class Stream:
    stream_id: int
    state: str = "OPENING"
    local_maximum: int = 0
    peer_maximum: int = 0
    recv_committed: int = 0
    recv_highest_end: int = 0
    recv_final: Optional[int] = None
    send_final: Optional[int] = None
    terminal_txid: Optional[int] = None
    terminal_frame: Optional[str] = None
    application_bytes: bytearray = field(default_factory=bytearray)
    segments: Dict[int, bytes] = field(default_factory=dict)
    recv_next: int = 0
    cancellation_pending: bool = False
    accepted: bool = False
    local_consumed: bool = False


@dataclass
class CarrierIdentity:
    highest_accepted: Optional[int] = None
    highest_attempted: Optional[int] = None
    active_generation: Optional[int] = None
    superseded_generations: Set[int] = field(default_factory=set)


class SessionModel:
    def __init__(
        self,
        *,
        max_streams: int = 32,
        max_carriers: int = 4,
        session_maximum: int = 8 * 1024 * 1024,
        protocol_version: int = 4,
    ) -> None:
        self.state = "ACTIVE"
        self.protocol_version = protocol_version
        self.max_streams = max_streams
        self.effective_carrier_limit = max_carriers
        self.session_maximum = session_maximum
        self.session_committed = 0
        self.streams: Dict[int, Stream] = {}
        self.tombstones: Dict[int, Stream] = {}
        self.retired_stream_ids: Set[int] = set()
        self.used_stream_ids: Set[int] = set()
        self.next_stream_id = 1

        self.carriers: Dict[int, CarrierIdentity] = {}
        self.active_carriers: Set[int] = set()
        self.session_limits = (32768, 65536, max_streams, max_carriers)

        self.next_txid = 1
        self.local_tx: Dict[int, Tx] = {}
        self.peer_tx_semantic: Dict[int, Tuple[object, ...]] = {}
        self.peer_processed: Set[int] = set()
        self.peer_processed_through = 0
        self.peer_retired_through = 0
        self.settled_through = 0
        self.replay_confirmation: Dict[int, str] = {}

        self.closed_error: Optional[str] = None
        self.close_scope: Optional[str] = None
        self.new_work_blocked = False

    # ------------------------------------------------------------------
    # Error / close helpers
    # ------------------------------------------------------------------

    def fail(self, code: str, scope: str, trigger: Optional[str] = None) -> None:
        if scope == "session":
            self.state = "CLOSING"
            self.closed_error = code
            self.close_scope = scope
            self.new_work_blocked = True
        raise ModelFailure(code, scope, trigger)

    def session_close(self, error: str = "NO_ERROR") -> None:
        self.state = "CLOSED"
        self.closed_error = error
        self.close_scope = "session"
        self.new_work_blocked = True
        self.active_carriers.clear()

    def receive_session_close(self) -> str:
        if self.state in {"CLOSING", "CLOSED"}:
            self.state = "CLOSED"
            self.new_work_blocked = True
            return "idempotent"
        self.session_close()
        return "closed"

    # ------------------------------------------------------------------
    # Stream identity and opening
    # ------------------------------------------------------------------

    def allocate_stream_id(self) -> int:
        if self.state != "ACTIVE":
            raise RuntimeError("new Stream forbidden outside ACTIVE")
        if self.next_stream_id > MAX_VARINT:
            raise RuntimeError("stream namespace exhausted")
        sid = self.next_stream_id
        self.next_stream_id += 2
        self.used_stream_ids.add(sid)
        return sid

    def force_next_stream_id(self, value: int) -> None:
        self.next_stream_id = value

    def open_stream(self, stream_id: int, *, initiator: bool = True) -> Stream:
        if self.state != "ACTIVE":
            self.fail(ERR_STREAM_STATE, "session", "STREAM_OPEN")
        if stream_id <= 0 or stream_id > MAX_VARINT or (initiator and stream_id % 2 != 1):
            self.fail(ERR_STREAM_STATE, "session", "STREAM_OPEN")
        if stream_id in self.used_stream_ids or stream_id in self.tombstones or stream_id in self.retired_stream_ids:
            self.fail(ERR_STREAM_STATE, "session", "STREAM_OPEN")
        if len(self.streams) >= self.max_streams:
            raise ModelFailure(ERR_STREAM_LIMIT, "stream_opening", "STREAM_OPEN")
        self.used_stream_ids.add(stream_id)
        st = Stream(stream_id=stream_id)
        self.streams[stream_id] = st
        return st

    def accept_open(self, stream_id: int) -> None:
        st = self.streams[stream_id]
        st.accepted = True
        st.state = "OPEN"

    def credit_acceptance_evidence(self, stream_id: int, maximum: int) -> None:
        st = self.streams[stream_id]
        if st.state not in {"OPENING", "OPENING_CANCEL_PENDING", "OPEN"}:
            self.fail(ERR_STREAM_STATE, "session", "STREAM_CREDIT")
        st.accepted = True
        st.peer_maximum = max(st.peer_maximum, maximum)
        if st.state == "OPENING":
            st.state = "OPEN"

    def preopen_reset(self, stream_id: int, txid: int, final_offset: int) -> str:
        if stream_id in self.streams:
            return "already_seen"
        if final_offset != 0:
            self.fail(ERR_STREAM_STATE, "session", "RESET_STREAM")
        st = Stream(stream_id=stream_id, state="PREOPEN_CANCELLED", recv_final=0)
        st.terminal_txid = txid
        st.terminal_frame = "RESET_STREAM"
        self.streams[stream_id] = st
        self.used_stream_ids.add(stream_id)
        self.replay_confirmation[txid] = "TRANSMISSION_ACK"
        return "preopen_cancellation"

    def preopen_stop(self, stream_id: int, txid: int) -> str:
        if stream_id in self.streams:
            return "already_seen"
        st = Stream(stream_id=stream_id, state="PREOPEN_CANCELLED", recv_final=0)
        self.streams[stream_id] = st
        self.used_stream_ids.add(stream_id)
        self.replay_confirmation[txid] = "TRANSMISSION_ACK"
        return "ack_and_reset_zero"

    def late_open_after_preopen_cancel(self, stream_id: int) -> str:
        st = self.streams.get(stream_id)
        if st is None or st.state != "PREOPEN_CANCELLED":
            return "normal_open"
        return "STREAM_OPEN_REJECT_STREAM_STATE_ERROR"

    def start_opening_cancel(self, stream_id: int) -> None:
        st = self.streams[stream_id]
        if st.state != "OPENING":
            raise RuntimeError("not opening")
        st.state = "OPENING_CANCEL_PENDING"
        st.cancellation_pending = True

    def cancellation_reset_response(self, stream_id: int, final_offset: int) -> str:
        st = self.streams[stream_id]
        if st.state != "OPENING_CANCEL_PENDING" or final_offset != 0:
            self.fail(ERR_STREAM_STATE, "session", "RESET_STREAM")
        return "cancellation_response_not_acceptance"

    def opening_acceptance_wins(self, stream_id: int) -> str:
        st = self.streams[stream_id]
        if st.state != "OPENING_CANCEL_PENDING":
            raise RuntimeError("wrong state")
        st.accepted = True
        st.state = "RESET"
        st.recv_final = 0
        return "accepted_then_terminal"

    # ------------------------------------------------------------------
    # Flow control and Stream data/final state
    # ------------------------------------------------------------------

    def advertise_stream_credit(self, stream_id: int, consumed: int, maximum: int) -> str:
        if not (0 <= consumed <= maximum <= MAX_VARINT):
            self.fail(ERR_FLOW_CONTROL, "session", "STREAM_CREDIT")
        st = self.streams[stream_id]
        old = getattr(st, "_credit_pair", (0, 0))
        old_c, old_m = old
        if consumed >= old_c and maximum >= old_m:
            st._credit_pair = (consumed, maximum)  # type: ignore[attr-defined]
            st.peer_maximum = maximum
            return "applied"
        if consumed <= old_c and maximum <= old_m:
            return "stale_ignored"
        self.fail(ERR_FLOW_CONTROL, "session", "STREAM_CREDIT")
        return "unreachable"

    def advertise_session_credit(self, consumed: int, maximum: int) -> str:
        if not (0 <= consumed <= maximum <= MAX_VARINT):
            self.fail(ERR_FLOW_CONTROL, "session", "SESSION_CREDIT")
        old_c, old_m = getattr(self, "_session_credit_pair", (0, 0))
        if consumed >= old_c and maximum >= old_m:
            self._session_credit_pair = (consumed, maximum)
            return "applied"
        if consumed <= old_c and maximum <= old_m:
            return "stale_ignored"
        self.fail(ERR_FLOW_CONTROL, "session", "SESSION_CREDIT")
        return "unreachable"

    def set_receive_credit(self, stream_id: int, stream_maximum: int, session_maximum: Optional[int] = None) -> None:
        st = self.streams[stream_id]
        st.local_maximum = stream_maximum
        if session_maximum is not None:
            self.session_maximum = session_maximum

    def _register_peer_tx(self, txid: int, semantic: Tuple[object, ...], confirmation: str) -> bool:
        old = self.peer_tx_semantic.get(txid)
        if old is not None:
            if old != semantic:
                self.fail(ERR_TRANSMISSION_ID, "session")
            return True
        self.peer_tx_semantic[txid] = semantic
        self.peer_processed.add(txid)
        self.replay_confirmation[txid] = confirmation
        while self.peer_processed_through + 1 in self.peer_processed:
            self.peer_processed_through += 1
        return False

    def receive_data(self, stream_id: int, offset: int, data: bytes, txid: int) -> str:
        st = self.streams.get(stream_id)
        if st is None:
            self.fail(ERR_STREAM_STATE, "session", "STREAM_DATA")
        assert st is not None
        if st.state in {"OPENING", "OPENING_CANCEL_PENDING", "PREOPEN_CANCELLED"}:
            self.fail(ERR_STREAM_STATE, "session", "STREAM_DATA")
        end = offset + len(data)
        semantic = ("STREAM_DATA", stream_id, offset, bytes(data))
        duplicate = self._register_peer_tx(txid, semantic, "TRANSMISSION_ACK")

        if st.recv_final is not None and end > st.recv_final:
            self.fail(ERR_FINAL_SIZE, "session", "STREAM_DATA")
        if end > st.local_maximum:
            self.fail(ERR_FLOW_CONTROL, "session", "STREAM_DATA")

        old_committed = st.recv_committed
        new_committed = max(old_committed, end)
        delta = new_committed - old_committed
        if self.session_committed + delta > self.session_maximum:
            self.fail(ERR_FLOW_CONTROL, "session", "STREAM_DATA")

        existing = st.segments.get(offset)
        if existing is not None and existing != data:
            self.fail(ERR_PROTOCOL, "session", "STREAM_DATA")

        if st.state in {"RESET", "TOMBSTONE"}:
            return "duplicate_suppressed"

        if not duplicate:
            self.session_committed += delta
            st.recv_committed = new_committed
            st.recv_highest_end = max(st.recv_highest_end, end)
            st.segments[offset] = bytes(data)
            while st.recv_next in st.segments:
                chunk = st.segments.pop(st.recv_next)
                st.application_bytes.extend(chunk)
                st.recv_next += len(chunk)
        return "duplicate" if duplicate else "applied"

    def receive_fin(self, stream_id: int, txid: int, final_offset: int) -> str:
        st = self.streams[stream_id]
        semantic = ("STREAM_FIN", stream_id, final_offset)
        duplicate = self._register_peer_tx(txid, semantic, "TRANSMISSION_ACK")
        if st.recv_final is not None and final_offset != st.recv_final:
            self.fail(ERR_FINAL_SIZE, "session", "STREAM_FIN")
        if final_offset < st.recv_highest_end or final_offset < st.recv_committed:
            self.fail(ERR_FINAL_SIZE, "session", "STREAM_FIN")
        if final_offset > st.local_maximum:
            self.fail(ERR_FLOW_CONTROL, "session", "STREAM_FIN")
        delta = max(0, final_offset - st.recv_committed)
        if self.session_committed + delta > self.session_maximum:
            self.fail(ERR_FLOW_CONTROL, "session", "STREAM_FIN")
        if not duplicate:
            self.session_committed += delta
            st.recv_committed = max(st.recv_committed, final_offset)
        st.recv_final = final_offset
        if st.state != "RESET":
            st.state = "FIN"
        st.terminal_txid = txid
        st.terminal_frame = "STREAM_FIN"
        return "ack_without_graceful_restore" if st.state == "RESET" else ("duplicate" if duplicate else "fin")

    def receive_reset(self, stream_id: int, txid: int, final_offset: int, reason: int = 0) -> str:
        st = self.streams[stream_id]
        semantic = ("RESET_STREAM", stream_id, final_offset, reason)
        duplicate = self._register_peer_tx(txid, semantic, "TRANSMISSION_ACK")
        if st.recv_final is not None and final_offset != st.recv_final:
            self.fail(ERR_FINAL_SIZE, "session", "RESET_STREAM")
        if final_offset < st.recv_highest_end or final_offset < st.recv_committed:
            self.fail(ERR_FINAL_SIZE, "session", "RESET_STREAM")
        if final_offset > st.local_maximum:
            self.fail(ERR_FLOW_CONTROL, "session", "RESET_STREAM")
        delta = max(0, final_offset - st.recv_committed)
        if self.session_committed + delta > self.session_maximum:
            self.fail(ERR_FLOW_CONTROL, "session", "RESET_STREAM")
        if not duplicate:
            self.session_committed += delta
            st.recv_committed = max(st.recv_committed, final_offset)
        st.recv_final = final_offset
        st.state = "RESET"
        st.terminal_txid = txid
        st.terminal_frame = "RESET_STREAM"
        return "duplicate" if duplicate else "reset"

    def stream_consumed(self, stream_id: int, txid: int, final_offset: int) -> str:
        st = self.streams[stream_id]
        if st.send_final is not None and final_offset != st.send_final:
            self.fail(ERR_FINAL_SIZE, "session", "STREAM_CONSUMED")
        self._register_peer_tx(txid, ("STREAM_CONSUMED", stream_id, final_offset), "TRANSMISSION_ACK")
        st.local_consumed = True
        return "applied"

    def retire_stream_to_tombstone(self, stream_id: int) -> None:
        st = self.streams.pop(stream_id)
        st.state = "TOMBSTONE"
        self.tombstones[stream_id] = st

    def receive_tombstone_terminal(self, stream_id: int, txid: int, frame: str, final_offset: int) -> str:
        st = self.tombstones[stream_id]
        if st.recv_final is not None and final_offset != st.recv_final:
            self.fail(ERR_FINAL_SIZE, "session", frame)
        if txid == st.terminal_txid and frame == st.terminal_frame:
            return "idempotent_ack"
        if txid in self.replay_confirmation:
            return "repeat_confirmation"
        self.fail(ERR_TRANSMISSION_ID, "session", frame)
        return "unreachable"

    def compact_tombstone(self, stream_id: int) -> None:
        st = self.tombstones.pop(stream_id)
        st.state = "RETIRED"
        self.retired_stream_ids.add(stream_id)

    def retired_frame(self, stream_id: int, txid: int) -> str:
        if stream_id not in self.retired_stream_ids:
            raise RuntimeError("not retired")
        if txid <= self.peer_retired_through:
            return "ignored"
        if txid in self.replay_confirmation:
            return "repeat_confirmation_without_recreate"
        self.fail(ERR_TRANSMISSION_ID, "session")
        return "unreachable"

    # ------------------------------------------------------------------
    # Local reliable Transmission namespace
    # ------------------------------------------------------------------

    def force_next_txid(self, value: int) -> None:
        self.next_txid = value

    def allocate_tx(self, frame: str, stream_id: int, semantic: Tuple[object, ...], confirmation: str = "TRANSMISSION_ACK") -> Tx:
        if self.state not in {"ACTIVE", "CLOSING"}:
            raise RuntimeError("no allocation outside usable state")
        if self.next_txid > MAX_VARINT:
            self.state = "CLOSING"
            self.closed_error = ERR_RESOURCE_LIMIT
            self.new_work_blocked = True
            raise ModelFailure(ERR_RESOURCE_LIMIT, "session")
        txid = self.next_txid
        self.next_txid += 1
        tx = Tx(txid, frame, stream_id, semantic, confirmation)
        self.local_tx[txid] = tx
        return tx

    def attempt(self, txid: int) -> None:
        tx = self.local_tx[txid]
        if self.state == "DORMANT":
            raise RuntimeError("no eligible carrier")
        tx.attempted = True

    def confirm(self, txid: int, confirmation: str, stream_id: int) -> str:
        tx = self.local_tx.get(txid)
        if tx is None:
            self.fail(ERR_TRANSMISSION_ID, "session")
        assert tx is not None
        if tx.stream_id != stream_id or tx.confirmation != confirmation:
            self.fail(ERR_TRANSMISSION_ID, "session")
        if tx.settled:
            return "duplicate"
        tx.settled = True
        while True:
            nxt = self.local_tx.get(self.settled_through + 1)
            if nxt is None or not nxt.settled:
                break
            self.settled_through += 1
        return "settled"

    def receive_retire(self, value: int) -> str:
        if value > self.peer_processed_through:
            self.fail(ERR_TRANSMISSION_ID, "session", "TRANSMISSION_RETIRE")
        if value <= self.peer_retired_through:
            return "stale_ignored"
        self.peer_retired_through = value
        for txid in list(self.replay_confirmation):
            if txid <= value:
                self.replay_confirmation.pop(txid, None)
        return "advanced"

    # ------------------------------------------------------------------
    # Carrier identity / Session lifecycle
    # ------------------------------------------------------------------

    def candidate(
        self,
        carrier_id: int,
        generation: int,
        *,
        limits: Optional[Tuple[int, int, int, int]] = None,
        protocol_version: int = 4,
        authenticated: bool = True,
    ) -> str:
        if self.state in {"CLOSING", "CLOSED"}:
            raise ModelFailure(ERR_SESSION_CONFLICT, "pre_establishment_carrier")
        if protocol_version != self.protocol_version:
            raise ModelFailure(ERR_SESSION_CONFLICT, "pre_establishment_carrier")
        if limits is not None and limits != self.session_limits:
            raise ModelFailure(ERR_SESSION_CONFLICT, "pre_establishment_carrier")
        ident = self.carriers.setdefault(carrier_id, CarrierIdentity())
        ident.highest_attempted = generation if ident.highest_attempted is None else max(ident.highest_attempted, generation)
        if ident.highest_accepted is None:
            if generation != 0:
                raise ModelFailure(ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
            needs_slot = carrier_id not in self.active_carriers
        else:
            if generation <= ident.highest_accepted:
                raise ModelFailure(ERR_CARRIER_CONFLICT, "pre_establishment_carrier")
            needs_slot = carrier_id not in self.active_carriers
        if needs_slot and len(self.active_carriers) >= self.effective_carrier_limit:
            raise ModelFailure(ERR_RESOURCE_LIMIT, "pre_establishment_carrier")
        if not authenticated:
            raise ModelFailure(ERR_AUTH, "carrier")
        if ident.active_generation is not None and generation > ident.active_generation:
            ident.superseded_generations.add(ident.active_generation)
        ident.highest_accepted = generation
        ident.active_generation = generation
        self.active_carriers.add(carrier_id)
        if self.state == "DORMANT":
            self.state = "ACTIVE"
        return "established"

    def lose_carrier(self, carrier_id: int, *, retain_session: bool = True) -> str:
        ident = self.carriers[carrier_id]
        ident.active_generation = None
        self.active_carriers.discard(carrier_id)
        if not self.active_carriers:
            self.state = "DORMANT" if retain_session else "CLOSED"
        return self.state

    def carrier_close(self, carrier_id: int) -> str:
        return self.lose_carrier(carrier_id, retain_session=True)

    def dormant_retire(self) -> None:
        if self.state != "DORMANT":
            raise RuntimeError("not dormant")
        self.state = "CLOSED"
        self.new_work_blocked = True

    def join_discarded(self) -> None:
        if self.state == "CLOSED":
            raise ModelFailure(ERR_SESSION_NOT_FOUND, "pre_establishment_carrier")

    def schedule_on_generation(self, carrier_id: int, generation: int) -> str:
        ident = self.carriers[carrier_id]
        if generation in ident.superseded_generations or generation != ident.active_generation:
            return "forbidden"
        return "allowed"

    # ------------------------------------------------------------------
    # Record/close helpers
    # ------------------------------------------------------------------

    def apply_record_frames(self, frames: Tuple[str, ...]) -> str:
        terminal_index = None
        for idx, frame in enumerate(frames):
            if frame in {"CARRIER_CLOSE", "SESSION_CLOSE"}:
                terminal_index = idx
                break
        if terminal_index is None:
            return "applied"
        trailing = frames[terminal_index + 1 :]
        if frames[terminal_index] == "SESSION_CLOSE":
            self.session_close()
        if trailing:
            return "trailing_ignored"
        return "terminal"

    def half_close(self) -> str:
        return "transport_half_close_only"


def expect_failure(func, code: str, scope: str) -> ModelFailure:
    try:
        func()
    except ModelFailure as exc:
        if exc.code != code or exc.scope != scope:
            raise AssertionError((exc.code, exc.scope, code, scope))
        return exc
    raise AssertionError(f"expected {code}/{scope}")
