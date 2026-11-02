from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from typing import Any


SIGNATURE = b"ESC/VP.net"
HEADER_SIZE = 18
HELLO_PACKET = SIGNATURE + bytes((0x10, 0x01, 0x00, 0x00, 0x00, 0x00))
V2_CONNECT_PACKET = (
    SIGNATURE
    + bytes((0x20, 0x03, 0x00, 0x00, 0x00, 0x01))
    + bytes((0x01, 0x03))
    + bytes(16)
)


def parse_response(data: bytes) -> dict[str, Any]:
    if len(data) < 16:
        raise ValueError(f"response is shorter than the 16-byte header ({len(data)} bytes)")
    if data[:10] != SIGNATURE:
        raise ValueError("response has an invalid ESC/VP.net signature")

    header_count = data[15]
    expected_length = 16 + HEADER_SIZE * header_count
    if len(data) < expected_length:
        raise ValueError(
            f"response declares {header_count} headers ({expected_length} bytes), "
            f"but only {len(data)} bytes arrived"
        )

    headers = []
    for offset in range(16, expected_length, HEADER_SIZE):
        headers.append(
            {
                "id": data[offset],
                "attribute": data[offset + 1],
                "information": data[offset + 2 : offset + HEADER_SIZE],
            }
        )

    return {
        "version": data[10],
        "message_type": data[11],
        "status": data[14],
        "headers": headers,
    }


def get_header(packet: dict[str, Any], header_id: int) -> dict[str, Any] | None:
    for header in packet["headers"]:
        if header["id"] == header_id:
            return header
    return None


def decode_text_header(packet: dict[str, Any], header_id: int) -> str | None:
    header = get_header(packet, header_id)
    if header is None:
        return None
    return header["information"].decode("ascii", errors="replace").rstrip("\x00 ")


def discover_projectors(
    timeout: float = 2.0,
    broadcast_ip: str = "10.1.255.255",
    port: int = 3629,
    local_ip: str = "0.0.0.0",
) -> list[dict[str, Any]]:
    """Find projectors responding to the documented V1 UDP HELLO request."""
    projectors: dict[str, dict[str, Any]] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((local_ip, port))
        sock.sendto(HELLO_PACKET, (broadcast_ip, port))

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, address = sock.recvfrom(4096)
            except socket.timeout:
                break

            ip = address[0]
            if ip in projectors:
                continue
            try:
                response = parse_response(data)
            except ValueError as exc:
                print(f"Ignoring malformed UDP response from {ip}: {exc}", file=sys.stderr)
                continue
            if response["message_type"] != 0x01:
                continue

            im_type = get_header(response, 0x04)
            command_type = get_header(response, 0x05)
            projectors[ip] = {
                "ip": ip,
                "projector_name": decode_text_header(response, 0x03),
                "udp_hello_status": f"0x{response['status']:02X}",
                "udp_hello_response_version": f"0x{response['version']:02X}",
                "im_type": f"0x{im_type['attribute']:02X}" if im_type else None,
                "esc_vp21_command_type": (
                    f"0x{command_type['attribute']:02X}" if command_type else None
                ),
            }

    return list(projectors.values())


def recv_exact(sock: socket.socket, length: int) -> bytes:
    received = bytearray()
    while len(received) < length:
        chunk = sock.recv(length - len(received))
        if not chunk:
            raise ConnectionError(
                f"connection closed after {len(received)} of {length} expected bytes"
            )
        received.extend(chunk)
    return bytes(received)


def probe_v2(ip: str, port: int = 3629, timeout: float = 2.0) -> dict[str, Any]:
    """Probe V2 with a zero-value digest challenge; never send a password or proof."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(V2_CONNECT_PACKET)
            response_header = recv_exact(sock, 16)
            response_length = 16 + HEADER_SIZE * response_header[15]
            response_data = response_header + recv_exact(sock, response_length - 16)
        response = parse_response(response_data)
        if response["message_type"] != 0x03:
            raise ValueError(
                f"expected CONNECT response type 0x03, got 0x{response['message_type']:02X}"
            )
    except (OSError, ValueError) as exc:
        return {
            "tcp_connect_status": None,
            "v2_support": "unknown",
            "detected_version": "unknown",
            "probe_error": str(exc),
        }

    status = response["status"]
    result: dict[str, Any] = {
        "tcp_connect_status": f"0x{status:02X}",
        "tcp_response_version": f"0x{response['version']:02X}",
    }
    if status == 0x55:
        result.update(
            v2_support="unsupported",
            detected_version="V1 (V2 unsupported)",
        )
    elif status in (0x20, 0x41):
        result.update(v2_support="supported", detected_version="V2")
    else:
        result.update(v2_support="unknown", detected_version="unknown")
    return result


def render_projector_table(projectors: list[dict[str, Any]]) -> str:
    if not projectors:
        return "No projectors found."

    columns = (
        ("IP", "ip"),
        ("Projector", "projector_name"),
        ("UDP HELLO", "udp_hello_status"),
        ("TCP CONNECT", "tcp_connect_status"),
        ("Detected version", "detected_version"),
    )
    # Sort projectors by name 
    projectors.sort(key=lambda p: p.get("projector_name") or "")
    rows = [
        [str(projector.get(key) or "-") for _, key in columns]
        for projector in projectors
    ]
    widths = [
        max(len(title), *(len(row[index]) for row in rows))
        for index, (title, _) in enumerate(columns)
    ]
    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"

    def format_row(values: list[str]) -> str:
        return "| " + " | ".join(
            value.ljust(width) for value, width in zip(values, widths)
        ) + " |"

    lines = [separator, format_row([title for title, _ in columns]), separator]
    lines.extend(format_row(row) for row in rows)
    lines.append(separator)

    for projector in projectors:
        error = projector.get("probe_error")
        if error:
            lines.append(f"Probe error for {projector['ip']}: {error}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Discover projectors with UDP HELLO and detect V2 support over TCP."
    )
    parser.add_argument("--broadcast-ip", default="10.1.255.255")
    parser.add_argument("--local-ip", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3629)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--json",
        action="store_true",
        help="print results as JSON instead of a terminal table",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    projectors = discover_projectors(
        timeout=args.timeout,
        broadcast_ip=args.broadcast_ip,
        port=args.port,
        local_ip=args.local_ip,
    )
    for projector in projectors:
        projector.update(probe_v2(projector["ip"], args.port, args.timeout))

    if args.json:
        print(json.dumps(projectors, indent=2))
    else:
        print(render_projector_table(projectors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
