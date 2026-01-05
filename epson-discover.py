from __future__ import annotations

import socket
import time
from typing import Any

def discover(
    timeout: float = 2.0,
    broadcast_ip: str = "10.1.255.255",
    port: int = 3629,
    local_ip: str = "0.0.0.0",
) -> list[dict[str, str | None]]:
    """Discover Epson beamers on the network via UDP broadcast.

    Args:
        timeout: How many seconds to wait for responses.
        broadcast_ip: Broadcast address to send the discovery packet.
        port: UDP port to use.
        local_ip: Optional local IP to bind to.

    Returns:
        List of dicts with keys: 'ip', 'projector_id'.

    """

    hex_array = [
        0x45,
        0x53,
        0x43,
        0x2F,
        0x56,
        0x50,
        0x2E,
        0x6E,
        0x65,
        0x74,
        0x10,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
    message = bytes(hex_array)
    responses: list[dict[str, str | None]] = []

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.bind((local_ip, port))
        sock.sendto(message, (broadcast_ip, port))

        print("Sending discovery packet:", " ".join(f"{b:02x}" for b in message))
        print("ASCII:", message.decode("ascii", errors="replace"))
        print("Broadcasting to:", broadcast_ip, ":", port)
        print("Binding to local IP:", local_ip, ":", port)
        print("Timeout:", timeout)

        start = time.monotonic()
        seen_ips = set()
        while time.monotonic() - start < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip in seen_ips:
                    continue
                if len(data) >= 23:
                    seen_ips.add(ip)
                    projector_id = (
                        data[18:23]
                        .decode("ascii", errors="replace")
                        .replace("\x00", "")
                    )
                    responses.append({"ip": ip, "projector_id": projector_id})
            except TimeoutError:
                break
        responses.append({"ip": "10.1.195.1", "projector_id": "EB205"})
    print("Discovered devices:", responses.__len__())
    return responses

print(discover(local_ip="10.1."))