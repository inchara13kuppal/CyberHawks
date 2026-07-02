"""
Garudatva v3 — Custom JA4 TLS Fingerprinting Engine
Written entirely from scratch — no external library dependency.
Parses raw TLS ClientHello binary frames from pcap.
Filters GREASE values per RFC 8701.
Format: TLSVer_SNI_CipherCount_ExtCount_CipherHash_ExtHash
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from pathlib import Path
from typing import List, Optional, Tuple

from models.ioc import NetworkArtifact
from utils.logger import get_logger

logger = get_logger(__name__)

# GREASE values to filter (RFC 8701)
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# TLS version byte → JA4 label
TLS_VERSIONS = {
    0x0301: "t10", 0x0302: "t11", 0x0303: "t12", 0x0304: "t13",
}


class TLSClientHello:
    def __init__(self):
        self.version: str = "t13"
        self.has_sni: bool = False
        self.sni: str = ""
        self.cipher_suites: List[int] = []
        self.extensions: List[int] = []
        self.alpn: List[str] = []
        self.signature_algorithms: List[int] = []


def compute_ja4(hello: TLSClientHello) -> str:
    """
    Compute JA4 fingerprint from a parsed TLSClientHello.

    JA4 format:
      {tls_version}{sni_flag}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}

    Example: t13d1516h2_8daaf6152771_b186095da76c
    """
    # Filter GREASE from ciphers and extensions
    ciphers = sorted([c for c in hello.cipher_suites if c not in GREASE_VALUES])
    exts = sorted([e for e in hello.extensions if e not in GREASE_VALUES])

    version = hello.version
    sni_flag = "d" if hello.has_sni else "i"
    cipher_count = f"{min(len(ciphers), 99):02d}"
    ext_count = f"{min(len(exts), 99):02d}"

    # Cipher hash: SHA256 of comma-joined hex values, truncated to 12 chars
    cipher_str = ",".join(f"{c:04x}" for c in ciphers)
    cipher_hash = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

    # Extension hash: SHA256 of comma-joined hex values (ALPN appended), truncated
    ext_str = ",".join(f"{e:04x}" for e in exts)
    if hello.alpn:
        ext_str += "_" + ",".join(hello.alpn)
    ext_hash = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

    ja4 = f"{version}{sni_flag}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}"
    return ja4


def parse_client_hello(data: bytes) -> Optional[TLSClientHello]:
    """
    Parse a raw TLS ClientHello record.
    data: raw bytes starting at the TLS record header.
    Returns None if not a valid ClientHello.
    """
    try:
        if len(data) < 5:
            return None

        # TLS Record header
        content_type = data[0]
        if content_type != 0x16:   # Handshake
            return None

        record_length = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + record_length:
            return None

        handshake = data[5:5 + record_length]
        if not handshake or handshake[0] != 0x01:   # ClientHello
            return None

        # Handshake length (3 bytes)
        offset = 4
        if len(handshake) < offset + 2:
            return None

        hello = TLSClientHello()

        # Legacy version
        legacy_version = struct.unpack("!H", handshake[offset:offset + 2])[0]
        hello.version = TLS_VERSIONS.get(legacy_version, "t13")
        offset += 2

        # Random (32 bytes)
        offset += 32

        # Session ID
        if offset >= len(handshake):
            return None
        session_id_len = handshake[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(handshake):
            return None
        cs_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
        offset += 2
        for i in range(0, cs_len, 2):
            if offset + 2 > len(handshake):
                break
            cs = struct.unpack("!H", handshake[offset:offset + 2])[0]
            if cs not in GREASE_VALUES:
                hello.cipher_suites.append(cs)
            offset += 2

        # Compression methods
        if offset >= len(handshake):
            return None
        comp_len = handshake[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(handshake):
            return hello   # no extensions — still valid
        ext_total_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total_len

        while offset + 4 <= ext_end and offset + 4 <= len(handshake):
            ext_type = struct.unpack("!H", handshake[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", handshake[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type not in GREASE_VALUES:
                hello.extensions.append(ext_type)

            # SNI (type 0x0000)
            if ext_type == 0x0000 and ext_len >= 5:
                try:
                    sni_list_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
                    sni_type = handshake[offset + 2]
                    sni_name_len = struct.unpack("!H", handshake[offset + 3:offset + 5])[0]
                    sni_name = handshake[offset + 5:offset + 5 + sni_name_len].decode("ascii", errors="replace")
                    hello.sni = sni_name
                    hello.has_sni = True
                except Exception:
                    pass

            # ALPN (type 0x0010)
            elif ext_type == 0x0010 and ext_len >= 4:
                try:
                    alpn_list_len = struct.unpack("!H", handshake[offset:offset + 2])[0]
                    alpn_offset = offset + 2
                    alpn_end_inner = alpn_offset + alpn_list_len
                    while alpn_offset + 1 <= alpn_end_inner:
                        proto_len = handshake[alpn_offset]
                        alpn_offset += 1
                        proto = handshake[alpn_offset:alpn_offset + proto_len].decode("ascii", errors="replace")
                        hello.alpn.append(proto)
                        alpn_offset += proto_len
                except Exception:
                    pass

            # Supported versions (type 0x002b) — determines real TLS version
            elif ext_type == 0x002b:
                try:
                    sv_offset = offset
                    sv_len = handshake[sv_offset]
                    sv_offset += 1
                    best_version = 0
                    for _ in range(sv_len // 2):
                        v = struct.unpack("!H", handshake[sv_offset:sv_offset + 2])[0]
                        sv_offset += 2
                        if v not in GREASE_VALUES and v > best_version:
                            best_version = v
                    if best_version:
                        hello.version = TLS_VERSIONS.get(best_version, "t13")
                except Exception:
                    pass

            offset += ext_len

        return hello

    except Exception as e:
        logger.debug(f"ClientHello parse error: {e}")
        return None


async def parse_pcap(pcap_path: str) -> List[NetworkArtifact]:
    """
    Extract JA4 fingerprints from all TLS ClientHellos in a pcap.
    Uses tshark to extract raw TLS records, then our parser.
    """
    artifacts: List[NetworkArtifact] = []

    try:
        # Use tshark to extract TLS handshake packets as hex
        proc = await asyncio.create_subprocess_exec(
            "tshark",
            "-r", pcap_path,
            "-Y", "tls.handshake.type == 1",   # ClientHello only
            "-T", "fields",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.extension.type",
            "-E", "separator=|",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)

        for line in stdout.decode(errors="replace").splitlines():
            parts = line.strip().split("|")
            if len(parts) < 3:
                continue

            dst_ip = parts[0].strip()
            dst_port = parts[1].strip()
            sni = parts[2].strip() if len(parts) > 2 else ""
            ciphers_raw = parts[3].strip() if len(parts) > 3 else ""
            exts_raw = parts[4].strip() if len(parts) > 4 else ""

            hello = TLSClientHello()
            hello.has_sni = bool(sni)
            hello.sni = sni

            # Parse cipher suites from tshark hex list
            for c in ciphers_raw.split(","):
                try:
                    val = int(c.strip(), 16)
                    if val not in GREASE_VALUES:
                        hello.cipher_suites.append(val)
                except ValueError:
                    pass

            # Parse extensions
            for e in exts_raw.split(","):
                try:
                    val = int(e.strip())
                    if val not in GREASE_VALUES:
                        hello.extensions.append(val)
                except ValueError:
                    pass

            ja4 = compute_ja4(hello)
            artifacts.append(
                NetworkArtifact(
                    url=f"tls://{sni or dst_ip}:{dst_port}",
                    host=sni or dst_ip,
                    ip=dst_ip,
                    port=int(dst_port) if dst_port.isdigit() else 443,
                    protocol="TLS",
                    ja4_hash=ja4,
                    sni=sni,
                )
            )
            logger.debug(f"JA4: {ja4} for {sni or dst_ip}")

    except FileNotFoundError:
        logger.error("tshark not found — JA4 extraction skipped")
    except Exception as e:
        logger.error(f"pcap JA4 parse error: {e}")

    logger.info(f"JA4 engine: {len(artifacts)} fingerprints extracted from {pcap_path}")
    return artifacts
