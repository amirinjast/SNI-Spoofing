# SNI-Spoofing TCP/TLS Diagnostics Lab

This repository is now scoped as an educational TCP/TLS/SNI diagnostics lab. It is intended for controlled environments where you own the client, server, and network path, or where you have explicit permission to observe traffic. Do not use it to bypass production network controls or third-party policies.

## What this tool measures

The tool observes a TCP connection to a configured target and writes a per-connection diagnostic report. The report is designed to answer these questions:

- Did the TCP handshake complete?
- Did the connection drop before or after the handshake?
- Was a TLS ClientHello observed?
- Was a `wrong_seq` diagnostic packet observed outbound?
- Was any ACK seen after the `wrong_seq` packet?
- Was the failure a timeout, RST, FIN, silent drop, or likely packet loss?
- What were the TCP sequence number, ACK number, flags, timestamp, direction, and payload length for each packet?

Example summary:

```text
Initial reachability: OK
TCP handshake: OK
Drop before TCP handshake: NO
Drop after TCP handshake: YES
TLS ClientHello sent: YES
Wrong-sequence packet observed outbound: YES
ACK for wrong-sequence packet received: NO
RST received: NO
FIN received: NO
Timeout: YES
Silent drop: YES
Packet loss suspected: YES
Likely cause: wrong_seq no longer produced a useful response; packet may be ignored, normalized, or dropped
```

The tool cannot cryptographically prove whether the endpoint, OS, NAT, firewall, middlebox, or DPI device made a decision. It reports observed packets and gives a best-effort inference from the TCP/TLS state.

## Modes

### `capture_only`

Observes and logs the TCP/TLS flow without modifying packets. Use this first to establish the baseline behavior.

```json
"MODE": "capture_only"
```

### `diagnose_wrong_seq`

Runs the existing `wrong_seq` diagnostic behavior and records whether the crafted outbound packet and later ACK/RST/FIN/timeout behavior are visible.

```json
"MODE": "diagnose_wrong_seq",
"BYPASS_METHOD": "wrong_seq"
```

## Configuration

Edit `config.json`. The checked-in defaults use documentation-only lab values; replace them only with hosts in your authorized lab environment.

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "192.0.2.10",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "lab.example.test",
  "DATA_MODE": "tls",
  "MODE": "capture_only",
  "BYPASS_METHOD": "wrong_seq",
  "HANDSHAKE_TIMEOUT": 5.0,
  "FAKE_ACK_TIMEOUT": 2.0,
  "IDLE_TIMEOUT": 30.0,
  "CAPTURE_SECONDS": 10.0,
  "REPORT_DIR": "diagnostic_reports",
  "PRINT_PACKET_LOGS": true
}
```

Timeouts are seconds:

- `HANDSHAKE_TIMEOUT`: max wait for `connect()` / TCP handshake completion.
- `FAKE_ACK_TIMEOUT`: max wait for a packet after the `wrong_seq` diagnostic packet.
- `IDLE_TIMEOUT`: relay idle timeout after the connection is established.
- `CAPTURE_SECONDS`: max capture window in `capture_only` mode.

## Running in a lab from source

Install dependencies and run as Administrator on Windows because WinDivert packet capture requires elevated privileges:

```bash
pip install -r requirements.txt
python main.py
```

Then point a local TCP/TLS client at `LISTEN_HOST:LISTEN_PORT`. Each connection prints a summary and writes a full packet log under `diagnostic_reports/`.

## Building a Windows exe

Use the included PyInstaller scripts from the project root:

```powershell
.\build_exe.ps1 -Clean
```

Or with CMD:

```bat
build_exe.bat -Clean
```

Default output is an onedir build:

```text
dist\SNI-Spoofing-Diagnostics\SNI-Spoofing-Diagnostics.exe
```

The build script embeds/copies `config.json` and uses PyInstaller `--uac-admin`, so Windows should ask for Administrator permission when the exe starts. Administrator permission is required for WinDivert capture. For a single-file exe, run:

```powershell
.\build_exe.ps1 -Clean -OneFile
```

For development builds without UAC metadata:

```powershell
.\build_exe.ps1 -NoUacAdmin
```

## How to interpret common results

- `TCP handshake: FAILED` with timeout usually means the drop happens before a usable TCP stream exists.
- `TCP handshake: OK`, `TLS ClientHello sent: NO` means the TCP connection worked but the application did not send TLS data through the proxy during the capture window.
- `TLS ClientHello sent: YES` plus `RST received: YES` suggests an endpoint or on-path device actively reset the connection.
- `TLS ClientHello sent: YES` plus `Silent drop: YES` suggests packets stopped without RST/FIN, which can be consistent with filtering, path loss, or a middlebox policy.
- `Wrong-sequence packet observed outbound: YES` plus no useful ACK/RST/FIN means the packet was visible locally but did not create an observable remote TCP response. That can happen when the endpoint ignores it, the OS/NAT normalizes behavior, or an on-path device drops it.

## Safety and scope

This project is for network-course analysis of TCP sequence numbers, ACK behavior, TLS ClientHello visibility, and lab-only packet observation. Keep tests inside authorized lab networks and document the topology when you compare results.
