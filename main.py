import asyncio
import json
import os
import socket
import sys
import threading
import traceback
from typing import Any, Dict, Optional

from diagnostics import ConnectionDiagnostics, is_tls_client_hello, write_report
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_DEFAULTS: Dict[str, Any] = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_PORT": 443,
    "FAKE_SNI": "example.com",
    "DATA_MODE": "tls",
    "BYPASS_METHOD": "wrong_seq",
    "MODE": "diagnose_wrong_seq",
    "HANDSHAKE_TIMEOUT": 5.0,
    "FAKE_ACK_TIMEOUT": 2.0,
    "IDLE_TIMEOUT": 30.0,
    "CAPTURE_SECONDS": 10.0,
    "REPORT_DIR": "diagnostic_reports",
    "PRINT_PACKET_LOGS": True,
}


def load_config() -> Dict[str, Any]:
    config_path = os.path.join(get_exe_dir(), "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        user_config = json.load(f)
    config = dict(CONFIG_DEFAULTS)
    config.update(user_config)
    return config


config = load_config()
LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = int(config["LISTEN_PORT"])
FAKE_SNI = str(config["FAKE_SNI"]).encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = int(config["CONNECT_PORT"])
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = config.get("DATA_MODE", "tls")
BYPASS_METHOD = config.get("BYPASS_METHOD", "wrong_seq")
MODE = config.get("MODE", "diagnose_wrong_seq")
CAPTURE_ONLY = MODE == "capture_only"
HANDSHAKE_TIMEOUT = float(config.get("HANDSHAKE_TIMEOUT", 5.0))
FAKE_ACK_TIMEOUT = float(config.get("FAKE_ACK_TIMEOUT", 2.0))
IDLE_TIMEOUT = float(config.get("IDLE_TIMEOUT", 30.0))
CAPTURE_SECONDS = float(config.get("CAPTURE_SECONDS", 10.0))
REPORT_DIR = str(config.get("REPORT_DIR", "diagnostic_reports"))
PRINT_PACKET_LOGS = bool(config.get("PRINT_PACKET_LOGS", True))

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


def close_socket(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def configure_keepalive(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # These names are not available on every platform/Python build.
    for option_name, value in (("TCP_KEEPIDLE", 11), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, option_name, None)
        if option is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
            except OSError:
                pass


async def relay_main_loop(
    sock_1: socket.socket,
    sock_2: socket.socket,
    peer_task: asyncio.Task,
    first_prefix_data: bytes,
    diagnostics: Optional[ConnectionDiagnostics] = None,
    relay_name: str = "",
):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data = await asyncio.wait_for(loop.sock_recv(sock_1, 65575), timeout=IDLE_TIMEOUT)
            if not data:
                raise EOFError("eof")
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
            if diagnostics and relay_name == "client_to_target" and is_tls_client_hello(data):
                diagnostics.mark_tls_clienthello_sent("application relay")
            await loop.sock_sendall(sock_2, data)
        except asyncio.TimeoutError:
            if diagnostics:
                diagnostics.mark_timeout(f"idle_timeout_{IDLE_TIMEOUT}s_in_{relay_name}")
            break
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if diagnostics:
                diagnostics.close_reason = diagnostics.close_reason or f"relay_closed_{relay_name}: {exc!r}"
            break

    close_socket(sock_1)
    close_socket(sock_2)
    peer_task.cancel()


async def wait_for_wrong_seq_result(connection: FakeInjectiveConnection) -> bool:
    try:
        await asyncio.wait_for(connection.t2a_event.wait(), FAKE_ACK_TIMEOUT)
    except asyncio.TimeoutError:
        connection.diagnostics.mark_timeout(f"wrong_seq_ack_timeout_{FAKE_ACK_TIMEOUT}s")
        return False

    if connection.t2a_msg == "fake_data_ack_recv":
        return True
    connection.diagnostics.close_reason = connection.t2a_msg or "unexpected_close"
    return False


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    outgoing_sock: Optional[socket.socket] = None
    fake_injective_conn: Optional[FakeInjectiveConnection] = None
    diagnostics: Optional[ConnectionDiagnostics] = None

    try:
        loop = asyncio.get_running_loop()

        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32)
            )
        else:
            raise ValueError(f"unsupported DATA_MODE={DATA_MODE!r}")

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        if INTERFACE_IPV4:
            outgoing_sock.bind((INTERFACE_IPV4, 0))
        configure_keepalive(outgoing_sock)
        src_port = outgoing_sock.getsockname()[1]

        diagnostics = ConnectionDiagnostics(
            src_ip=INTERFACE_IPV4 or "0.0.0.0",
            src_port=src_port,
            dst_ip=CONNECT_IP,
            dst_port=CONNECT_PORT,
            mode=MODE,
        )

        fake_injective_conn = FakeInjectiveConnection(
            outgoing_sock,
            INTERFACE_IPV4,
            CONNECT_IP,
            src_port,
            CONNECT_PORT,
            fake_data,
            BYPASS_METHOD,
            incoming_sock,
            diagnostics,
        )
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn

        try:
            await asyncio.wait_for(loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT)), HANDSHAKE_TIMEOUT)
            diagnostics.observe_socket_connect_success()
        except Exception as exc:
            diagnostics.observe_socket_connect_failure(exc)
            return

        if CAPTURE_ONLY:
            diagnostics.add_note(
                "capture_only mode is active: packets are logged and forwarded unchanged; no wrong_seq packet is injected."
            )
        elif BYPASS_METHOD == "wrong_seq":
            ok = await wait_for_wrong_seq_result(fake_injective_conn)
            if not ok:
                return
        else:
            raise ValueError(f"unknown BYPASS_METHOD={BYPASS_METHOD!r}")

        if CAPTURE_ONLY:
            fake_injective_conn.monitor = True
        else:
            # Keep the flow in the WinDivert map after the probe so later RST/FIN/TLS packets
            # are still logged without modifying them.
            fake_injective_conn.monitor = False
            fake_injective_conn.observe_only = True

        target_to_client = asyncio.create_task(
            relay_main_loop(
                outgoing_sock,
                incoming_sock,
                asyncio.current_task(),
                b"",
                diagnostics,
                "target_to_client",
            )
        )
        client_to_target = asyncio.create_task(
            relay_main_loop(
                incoming_sock,
                outgoing_sock,
                asyncio.current_task(),
                b"",
                diagnostics,
                "client_to_target",
            )
        )

        if CAPTURE_ONLY:
            done, pending = await asyncio.wait(
                {target_to_client, client_to_target},
                timeout=CAPTURE_SECONDS,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                diagnostics.close_reason = f"capture_window_elapsed_{CAPTURE_SECONDS}s"
                diagnostics.add_note("Capture window elapsed; packets were observed without modifying the flow.")
            for task in pending:
                task.cancel()
        else:
            await asyncio.wait({target_to_client, client_to_target}, return_when=asyncio.FIRST_COMPLETED)

    except Exception:
        traceback.print_exc()
        if diagnostics:
            diagnostics.close_reason = diagnostics.close_reason or "handle_exception"
    finally:
        if fake_injective_conn:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)
        close_socket(outgoing_sock)
        close_socket(incoming_sock)
        if diagnostics:
            report_path = write_report(REPORT_DIR, diagnostics, include_packets=True)
            print("\n" + diagnostics.report_text(include_packets=False))
            print(f"Full packet report written to: {report_path}\n")


async def main():
    if not INTERFACE_IPV4:
        raise RuntimeError(f"Could not determine default IPv4 interface for {CONNECT_IP}")

    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    configure_keepalive(mother_sock)
    mother_sock.listen()

    print(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Target: {CONNECT_IP}:{CONNECT_PORT}")
    print(f"Mode: {MODE}")
    if CAPTURE_ONLY:
        print("Capture-only mode: observing packets without modification.")
    else:
        print(f"Diagnostic method: {BYPASS_METHOD}")

    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        configure_keepalive(incoming_sock)
        print(f"Accepted local connection from {addr}")
        asyncio.create_task(handle(incoming_sock, addr))


if __name__ == "__main__":
    w_filter = (
        "tcp and "
        + "("
        + "(ip.SrcAddr == "
        + INTERFACE_IPV4
        + " and ip.DstAddr == "
        + CONNECT_IP
        + ")"
        + " or "
        + "(ip.SrcAddr == "
        + CONNECT_IP
        + " and ip.DstAddr == "
        + INTERFACE_IPV4
        + ")"
        + ")"
    )
    fake_tcp_injector = FakeTcpInjector(
        w_filter,
        fake_injective_connections,
        capture_only=CAPTURE_ONLY,
        print_packet_logs=PRINT_PACKET_LOGS,
    )
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    asyncio.run(main())
