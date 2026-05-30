import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


TCP_FLAG_ORDER = (
    ("syn", "SYN"),
    ("ack", "ACK"),
    ("psh", "PSH"),
    ("rst", "RST"),
    ("fin", "FIN"),
    ("urg", "URG"),
)


def yes_no(value: bool) -> str:
    return "YES" if value else "NO"


def ok_failed(value: bool) -> str:
    return "OK" if value else "FAILED"


def packet_flags(packet: Any) -> str:
    flags = []
    tcp = getattr(packet, "tcp", None)
    for attr, label in TCP_FLAG_ORDER:
        if bool(getattr(tcp, attr, False)):
            flags.append(label)
    return "+".join(flags) if flags else "NONE"


def payload_len(packet: Any) -> int:
    payload = getattr(getattr(packet, "tcp", None), "payload", b"") or b""
    return len(payload)


def is_tls_client_hello(data: bytes) -> bool:
    """Best-effort TLS ClientHello detector for diagnostics only."""
    if not data or len(data) < 6:
        return False
    # TLS record: ContentType=22(handshake), Version=03.xx, Length=2 bytes,
    # first handshake message type=1(ClientHello).
    return data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01


def seq_delta(start: int, end: int) -> int:
    """Return unsigned TCP sequence distance from start to end."""
    return (end - start) & 0xFFFFFFFF


@dataclass
class PacketLogEntry:
    timestamp: float
    direction: str
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    ack: int
    flags: str
    payload_len: int
    note: str = ""

    def to_line(self) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        suffix = f" note={self.note}" if self.note else ""
        return (
            f"{ts}.{int((self.timestamp % 1) * 1000):03d} "
            f"{self.direction:<8} {self.src}:{self.sport} -> {self.dst}:{self.dport} "
            f"seq={self.seq} ack={self.ack} flags={self.flags} len={self.payload_len}{suffix}"
        )


@dataclass
class ConnectionDiagnostics:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    mode: str
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None

    initial_reachability: bool = False
    tcp_syn_seen: bool = False
    tcp_syn_ack_seen: bool = False
    tcp_final_ack_seen: bool = False
    tcp_handshake_completed: bool = False
    drop_before_handshake: bool = False
    drop_after_handshake: bool = False

    tls_clienthello_sent: bool = False
    wrong_seq_packet_observed_outbound: bool = False
    ack_for_wrong_seq_packet_received: bool = False
    wrong_seq_ack_advanced: Optional[bool] = None

    rst_received: bool = False
    fin_received: bool = False
    timeout: bool = False
    silent_drop: bool = False
    packet_loss_suspected: bool = False

    close_reason: str = ""
    likely_cause: str = "unknown"
    notes: List[str] = field(default_factory=list)
    packet_log: List[PacketLogEntry] = field(default_factory=list)

    wrong_seq_seq: Optional[int] = None
    wrong_seq_len: int = 0
    last_packet_at: Optional[float] = None

    def add_note(self, note: str) -> None:
        if note and note not in self.notes:
            self.notes.append(note)

    def observe_socket_connect_success(self) -> None:
        self.initial_reachability = True
        self.tcp_handshake_completed = True
        self.add_note("OS socket connect() completed; TCP handshake is complete from the local stack perspective.")

    def observe_socket_connect_failure(self, exc: BaseException) -> None:
        self.close_reason = f"connect_failed: {exc!r}"
        self.drop_before_handshake = True
        self.add_note("connect() failed before a usable TCP stream was established.")

    def mark_tls_clienthello_sent(self, source: str) -> None:
        self.tls_clienthello_sent = True
        self.add_note(f"TLS ClientHello observed from {source}.")

    def mark_timeout(self, reason: str) -> None:
        self.timeout = True
        self.close_reason = reason

    def mark_wrong_seq_sent(self, seq: int, ack: int, length: int) -> None:
        self.wrong_seq_packet_observed_outbound = True
        self.wrong_seq_seq = seq
        self.wrong_seq_len = length
        self.tls_clienthello_sent = True
        self.add_note(
            f"wrong_seq probe sent with seq={seq}, ack={ack}, payload_len={length}; this is logged for lab diagnostics only."
        )

    def mark_wrong_seq_ack(self, ack_num: int) -> None:
        self.ack_for_wrong_seq_packet_received = True
        if self.wrong_seq_seq is not None and self.wrong_seq_len:
            expected_end = (self.wrong_seq_seq + self.wrong_seq_len) & 0xFFFFFFFF
            self.wrong_seq_ack_advanced = seq_delta(expected_end, ack_num) < 0x80000000 and ack_num == expected_end
            if self.wrong_seq_ack_advanced:
                self.add_note("Inbound ACK exactly matched the end of the wrong-sequence payload.")
            else:
                self.add_note(
                    "Inbound ACK was seen after the wrong-sequence payload, but it did not advance to the injected payload end."
                )

    def mark_unexpected(self, reason: str) -> None:
        self.close_reason = reason
        self.add_note(reason)

    def log_packet(self, packet: Any, direction: str, note: str = "") -> None:
        now = time.time()
        self.last_packet_at = now
        tcp = getattr(packet, "tcp", None)
        ip = getattr(packet, "ip", None)
        payload = getattr(tcp, "payload", b"") or b""
        flags = packet_flags(packet)

        if "RST" in flags:
            self.rst_received = True
            self.close_reason = self.close_reason or "rst_received"
        if "FIN" in flags:
            self.fin_received = True
            self.close_reason = self.close_reason or "fin_received"

        outbound = direction.startswith("out")
        inbound = direction.startswith("in")
        if outbound and bool(getattr(tcp, "syn", False)) and not bool(getattr(tcp, "ack", False)):
            self.tcp_syn_seen = True
        elif inbound and bool(getattr(tcp, "syn", False)) and bool(getattr(tcp, "ack", False)):
            self.tcp_syn_ack_seen = True
            self.initial_reachability = True
        elif (
            outbound
            and bool(getattr(tcp, "ack", False))
            and not bool(getattr(tcp, "syn", False))
            and self.tcp_syn_ack_seen
        ):
            self.tcp_final_ack_seen = True
            self.tcp_handshake_completed = True

        if outbound and payload and is_tls_client_hello(payload):
            self.mark_tls_clienthello_sent("outbound packet capture")

        self.packet_log.append(
            PacketLogEntry(
                timestamp=now,
                direction="OUT" if outbound else "IN" if inbound else direction.upper(),
                src=getattr(ip, "src_addr", ""),
                sport=int(getattr(tcp, "src_port", 0)),
                dst=getattr(ip, "dst_addr", ""),
                dport=int(getattr(tcp, "dst_port", 0)),
                seq=int(getattr(tcp, "seq_num", 0)),
                ack=int(getattr(tcp, "ack_num", 0)),
                flags=flags,
                payload_len=len(payload),
                note=note,
            )
        )

    def finalize(self) -> None:
        self.ended_at = time.time()
        self.drop_before_handshake = bool(self.timeout and not self.tcp_handshake_completed)
        self.drop_after_handshake = bool(self.timeout and self.tcp_handshake_completed)
        self.silent_drop = bool(self.timeout and not self.rst_received and not self.fin_received)
        self.packet_loss_suspected = bool(self.timeout and not self.rst_received and not self.fin_received)

        if not self.tcp_handshake_completed:
            if self.rst_received:
                self.likely_cause = "TCP reset before handshake completed"
            elif self.timeout:
                self.likely_cause = "drop before TCP handshake completed or SYN/SYN-ACK path loss"
            else:
                self.likely_cause = "TCP handshake not confirmed"
        elif self.rst_received:
            self.likely_cause = "connection reset after TCP handshake by endpoint or an on-path device"
        elif self.fin_received:
            self.likely_cause = "connection closed with FIN after TCP handshake"
        elif self.wrong_seq_packet_observed_outbound and self.ack_for_wrong_seq_packet_received:
            if self.wrong_seq_ack_advanced:
                self.likely_cause = "wrong_seq packet received an ACK; inspect path because endpoint behavior is unusual"
            else:
                self.likely_cause = "wrong_seq appears ignored by TCP state while still visible in outbound capture"
        elif self.wrong_seq_packet_observed_outbound and self.timeout:
            self.likely_cause = "wrong_seq no longer produced a useful response; packet may be ignored, normalized, or dropped"
        elif self.tls_clienthello_sent and self.timeout:
            self.likely_cause = "silent drop after TLS ClientHello phase"
        else:
            self.likely_cause = "no failure signature captured"

    def summary_dict(self) -> Dict[str, Any]:
        return {
            "Initial reachability": ok_failed(self.initial_reachability),
            "TCP handshake": ok_failed(self.tcp_handshake_completed),
            "Drop before TCP handshake": yes_no(self.drop_before_handshake),
            "Drop after TCP handshake": yes_no(self.drop_after_handshake),
            "TLS ClientHello sent": yes_no(self.tls_clienthello_sent),
            "Wrong-sequence packet observed outbound": yes_no(self.wrong_seq_packet_observed_outbound),
            "ACK for wrong-sequence packet received": yes_no(self.ack_for_wrong_seq_packet_received),
            "RST received": yes_no(self.rst_received),
            "FIN received": yes_no(self.fin_received),
            "Timeout": yes_no(self.timeout),
            "Silent drop": yes_no(self.silent_drop),
            "Packet loss suspected": yes_no(self.packet_loss_suspected),
            "Likely cause": self.likely_cause,
        }

    def report_text(self, include_packets: bool = True) -> str:
        self.finalize()
        lines = [f"Diagnostic report for {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"]
        lines.append(f"Mode: {self.mode}")
        lines.append(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.started_at))}")
        if self.ended_at:
            lines.append(f"Duration: {self.ended_at - self.started_at:.3f}s")
        lines.append("")
        for key, value in self.summary_dict().items():
            lines.append(f"{key}: {value}")
        if self.close_reason:
            lines.append(f"Close reason: {self.close_reason}")
        if self.notes:
            lines.append("")
            lines.append("Notes:")
            lines.extend(f"- {note}" for note in self.notes)
        if include_packets:
            lines.append("")
            lines.append("Packet log:")
            if self.packet_log:
                lines.extend(entry.to_line() for entry in self.packet_log)
            else:
                lines.append("- No packets captured for this connection.")
        return "\n".join(lines)

    def report_json(self) -> str:
        self.finalize()
        data = asdict(self)
        data["summary"] = self.summary_dict()
        return json.dumps(data, indent=2, sort_keys=True)


def write_report(report_dir: str, diagnostics: ConnectionDiagnostics, include_packets: bool = True) -> str:
    os.makedirs(report_dir, exist_ok=True)
    safe_name = (
        f"diagnostic_{int(diagnostics.started_at)}_"
        f"{diagnostics.src_ip}_{diagnostics.src_port}_to_{diagnostics.dst_ip}_{diagnostics.dst_port}.txt"
    ).replace(":", "_")
    path = os.path.join(report_dir, safe_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(diagnostics.report_text(include_packets=include_packets))
        f.write("\n")
    return path
