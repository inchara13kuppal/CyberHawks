"""
Garudatva v3 — JARM Active Prober
Sends 10 crafted TLS ClientHello probes to fingerprint C2 server TLS config.
JARM identifies C2 infrastructure even when IP addresses rotate daily.
Runs on Workstation B only (requires outbound internet).
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import struct
from typing import Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

JARM_TIMEOUT = 10  # seconds per probe

# 10 JARM probe configurations
# Each probe varies: TLS version, cipher order, extensions
JARM_PROBES = [
    {"version": 0x0303, "ciphers": [0x002F, 0x0035, 0x009C], "ext_order": "forward"},
    {"version": 0x0303, "ciphers": [0x0035, 0x002F, 0x009C], "ext_order": "reverse"},
    {"version": 0x0301, "ciphers": [0x002F, 0x0035],          "ext_order": "forward"},
    {"version": 0x0302, "ciphers": [0x002F, 0x0035],          "ext_order": "forward"},
    {"version": 0x0303, "ciphers": [0xC02B, 0xC02F, 0xC02C], "ext_order": "forward"},
    {"version": 0x0303, "ciphers": [0xC02C, 0xC02B, 0xC02F], "ext_order": "reverse"},
    {"version": 0x0303, "ciphers": [0x009C, 0x009D, 0x002F], "ext_order": "forward"},
    {"version": 0x0304, "ciphers": [0x1301, 0x1302, 0x1303], "ext_order": "forward"},
    {"version": 0x0303, "ciphers": [0x0035, 0xC013, 0xC014], "ext_order": "forward"},
    {"version": 0x0303, "ciphers": [0xC013, 0xC014, 0x0035], "ext_order": "reverse"},
]


def build_client_hello(version: int, ciphers: List[int], ext_order: str) -> bytes:
    """Build a raw TLS ClientHello probe packet."""
    import os

    random_bytes = os.urandom(32)

    # Cipher suites
    cs_bytes = b""
    cipher_list = ciphers if ext_order == "forward" else list(reversed(ciphers))
    for cs in cipher_list:
        cs_bytes += struct.pack("!H", cs)
    cs_len = struct.pack("!H", len(cs_bytes))

    # Extensions: SNI (empty) + supported_versions
    ext_sni = struct.pack("!HH", 0x0000, 0x0000)  # empty SNI
    supported_versions = struct.pack("!HH", 0x002B, 2) + struct.pack("!H", version)
    extensions = ext_sni + supported_versions
    ext_len = struct.pack("!H", len(extensions))

    # Assemble ClientHello body
    body = (
        struct.pack("!H", version)   # legacy version
        + random_bytes               # random
        + b"\x00"                    # session ID length = 0
        + cs_len + cs_bytes          # cipher suites
        + b"\x01\x00"               # compression: 1 method, null
        + ext_len + extensions       # extensions
    )

    # Handshake header
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body

    # TLS record header
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    return record


async def probe_single(host: str, port: int, probe_cfg: dict) -> Optional[str]:
    """
    Send one JARM probe to host:port.
    Returns the server's raw response bytes as hex, or None on failure.
    """
    try:
        packet = build_client_hello(
            probe_cfg["version"],
            probe_cfg["ciphers"],
            probe_cfg["ext_order"],
        )

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=JARM_TIMEOUT,
        )
        writer.write(packet)
        await writer.drain()

        # Read server response (up to 1484 bytes)
        response = await asyncio.wait_for(reader.read(1484), timeout=JARM_TIMEOUT)
        writer.close()

        if response and len(response) > 5:
            # Extract server hello bytes for hashing
            return response.hex()
        return "|||"  # No response
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
        return "|||"
    except Exception as e:
        logger.debug(f"JARM probe error {host}:{port}: {e}")
        return "|||"


def compute_jarm_hash(probe_responses: List[Optional[str]]) -> str:
    """
    Hash the 10 probe responses into a JARM fingerprint.
    Format: 62-char hex string.
    """
    combined = "".join(r or "|||" for r in probe_responses)
    return hashlib.sha256(combined.encode()).hexdigest()[:62]


async def probe_host(host: str, port: int = 443) -> Dict:
    """Run all 10 JARM probes against a single host. Returns fingerprint."""
    logger.info(f"JARM probing: {host}:{port}")
    responses = []
    for i, probe_cfg in enumerate(JARM_PROBES):
        resp = await probe_single(host, port, probe_cfg)
        responses.append(resp)
        logger.debug(f"  Probe {i+1}/10: {'got response' if resp != '|||' else 'no response'}")

    jarm_hash = compute_jarm_hash(responses)
    logger.info(f"JARM result: {host} → {jarm_hash}")
    return {
        "host": host,
        "port": port,
        "jarm_hash": jarm_hash,
        "probes_responded": sum(1 for r in responses if r != "|||"),
    }


async def probe_hosts(ips: List[str], port: int = 443) -> List[Dict]:
    """Run JARM probing against a list of IPs concurrently."""
    tasks = [probe_host(ip, port) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]
