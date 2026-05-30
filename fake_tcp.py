import asyncio
import socket
import sys
import threading
import time

from pydivert import Packet

from diagnostics import ConnectionDiagnostics
from injecter import TcpInjector
from monitor_connection import MonitorConnection


class FakeInjectiveConnection(MonitorConnection):
    def __init__(
        self,
        sock: socket.socket,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        fake_data: bytes,
        bypass_method: str,
        peer_sock: socket.socket,
        diagnostics: ConnectionDiagnostics,
    ):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()
        self.diagnostics = diagnostics
        self.observe_only = False


class FakeTcpInjector(TcpInjector):
    def __init__(
        self,
        w_filter: str,
        connections: dict[tuple, FakeInjectiveConnection],
        capture_only: bool = False,
        print_packet_logs: bool = False,
    ):
        super().__init__(w_filter)
        self.connections = connections
        self.capture_only = capture_only
        self.print_packet_logs = print_packet_logs

    def _log_packet(self, connection: FakeInjectiveConnection, packet: Packet, direction: str, note: str = ""):
        connection.diagnostics.log_packet(packet, direction, note)
        if self.print_packet_logs:
            print(connection.diagnostics.packet_log[-1].to_line())

    def _finish_waiter(self, connection: FakeInjectiveConnection, msg: str) -> None:
        connection.t2a_msg = msg
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        time.sleep(0.001)
        with connection.thread_lock:
            if not connection.monitor:
                return

            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF

            if connection.bypass_method == "wrong_seq":
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xFFFFFFFF
                connection.fake_sent = True
                connection.diagnostics.mark_wrong_seq_sent(
                    packet.tcp.seq_num,
                    packet.tcp.ack_num,
                    len(packet.tcp.payload),
                )
                self._log_packet(connection, packet, "outbound", "wrong_seq injected outbound")
                self.w.send(packet, True)
            else:
                connection.diagnostics.mark_unexpected(f"not implemented method: {connection.bypass_method}")
                self._finish_waiter(connection, "unexpected_close")

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        self._log_packet(connection, packet, "inbound" if packet.is_inbound else "outbound", info_m)
        connection.diagnostics.mark_unexpected(info_m)
        connection.monitor = False
        try:
            connection.sock.close()
        finally:
            connection.peer_sock.close()
        self._finish_waiter(connection, "unexpected_close")
        self.w.send(packet, False)

    def _handle_terminal_packet(self, packet: Packet, connection: FakeInjectiveConnection, direction: str) -> bool:
        if packet.tcp.rst:
            self._log_packet(connection, packet, direction, "RST observed")
            connection.monitor = False
            self._finish_waiter(connection, "rst_received")
            self.w.send(packet, False)
            return True
        if packet.tcp.fin:
            self._log_packet(connection, packet, direction, "FIN observed")
            connection.monitor = False
            self._finish_waiter(connection, "fin_received")
            self.w.send(packet, False)
            return True
        return False

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if self._handle_terminal_packet(packet, connection, "inbound"):
            return

        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no SYN sent")
            return

        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
            len(packet.tcp.payload) == 0
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound SYN-ACK packet, seq changed: "
                    + str(seq_num)
                    + " != "
                    + str(connection.syn_ack_seq),
                )
                return
            if ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound SYN-ACK packet, ack mismatch: "
                    + str(ack_num)
                    + " != "
                    + str(connection.syn_seq),
                )
                return
            connection.syn_ack_seq = seq_num
            self._log_packet(connection, packet, "inbound", "SYN-ACK observed")
            self.w.send(packet, False)
            return

        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
            len(packet.tcp.payload) == 0
        ) and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xFFFFFFFF) != seq_num:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound ACK packet, seq mismatch: "
                    + str(seq_num)
                    + " != "
                    + str(connection.syn_ack_seq),
                )
                return
            connection.diagnostics.mark_wrong_seq_ack(ack_num)
            self._log_packet(connection, packet, "inbound", "ACK after wrong_seq observed")
            connection.monitor = False
            self._finish_waiter(connection, "fake_data_ack_recv")
            self.w.send(packet, False)
            return

        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if self._handle_terminal_packet(packet, connection, "outbound"):
            return

        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet after wrong_seq was scheduled")
            return

        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
            len(packet.tcp.payload) == 0
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound SYN packet, ack_num is not zero")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound SYN packet, seq mismatch: "
                    + str(seq_num)
                    + " != "
                    + str(connection.syn_seq),
                )
                return
            connection.syn_seq = seq_num
            self._log_packet(connection, packet, "outbound", "SYN observed")
            self.w.send(packet, False)
            return

        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
            len(packet.tcp.payload) == 0
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xFFFFFFFF) != seq_num:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound ACK packet, seq mismatch: "
                    + str(seq_num)
                    + " != "
                    + str(connection.syn_seq),
                )
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound ACK packet, ack mismatch: "
                    + str(ack_num)
                    + " != "
                    + str(connection.syn_ack_seq),
                )
                return

            self._log_packet(connection, packet, "outbound", "final ACK observed; TCP handshake complete")
            self.w.send(packet, False)
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return

        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

    def inject(self, packet: Packet):
        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            direction = "inbound"
        elif packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            direction = "outbound"
        else:
            sys.exit("impossible direction")

        try:
            connection = self.connections[c_id]
        except KeyError:
            self.w.send(packet, False)
            return

        with connection.thread_lock:
            if self.capture_only or connection.observe_only:
                self._log_packet(
                    connection,
                    packet,
                    direction,
                    "capture-only" if self.capture_only else "observe-after-probe",
                )
                self.w.send(packet, False)
                return
            if not connection.monitor:
                self.w.send(packet, False)
                return
            if packet.is_inbound:
                self.on_inbound_packet(packet, connection)
            else:
                self.on_outbound_packet(packet, connection)
