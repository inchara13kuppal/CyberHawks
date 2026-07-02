"""
Garudatva v3 — Custody Chain Exhibit Template
Renders the full BSA Sec 63 custody chain as a PDF exhibit.
Each entry shows: sequence, stage, action, actor, timestamp, hash.
Chain verification result prominently displayed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle

GARUDATVA_DARK = colors.HexColor("#1a1a2e")
GARUDATVA_BLUE = colors.HexColor("#16213e")
GARUDATVA_GOLD = colors.HexColor("#e94560")
VALID_GREEN    = colors.HexColor("#27ae60")
BROKEN_RED     = colors.HexColor("#c0392b")


def render_custody_exhibit(styles: dict, custody) -> list:
    """
    Render the full custody chain manifest as a PDF exhibit section.
    custody: CustodyChain instance with .to_manifest() method.
    """
    elements = [
        Paragraph("EXHIBIT B — CUSTODY CHAIN AUDIT TRAIL", styles["SectionHeader"]),
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3 * cm),
    ]

    manifest = custody.to_manifest()
    chain_valid = manifest.chain_valid

    # ── Verification banner ───────────────────────────────────────────────────
    banner_color = VALID_GREEN if chain_valid else BROKEN_RED
    banner_text  = (
        "✓ CHAIN INTEGRITY VERIFIED — All SHA256 hashes consistent. "
        "No tampering detected. Admissible under BSA Section 63."
        if chain_valid else
        "✗ CHAIN INTEGRITY COMPROMISED — Hash mismatch detected. "
        "Evidence may have been tampered. Immediate investigation required."
    )
    elements.append(Paragraph(
        banner_text,
        ParagraphStyle(
            "ChainBanner", fontSize=10, fontName="Helvetica-Bold",
            textColor=banner_color, spaceAfter=8, spaceBefore=4,
        ),
    ))

    # ── Summary stats ─────────────────────────────────────────────────────────
    elements.append(_summary_table(manifest))
    elements.append(Spacer(1, 0.3 * cm))

    # ── Methodology note ──────────────────────────────────────────────────────
    elements.append(Paragraph(
        "METHODOLOGY: Each custody entry is serialised using Canonical JSON "
        "(RFC 8785 — keys sorted alphabetically, no insignificant whitespace) "
        "to ensure deterministic serialisation. The SHA256 digest of each entry "
        "is computed over the canonical form concatenated with the previous "
        "entry's digest (blockchain-style linkage). Entry identifiers use "
        "UUIDv7 — the first 48 bits encode a millisecond-precision timestamp, "
        "enabling chronological sorting by identifier alone without a separate "
        "timestamp field. Any post-hoc modification to any entry invalidates "
        "all subsequent hashes, making tampering immediately detectable.",
        styles["Body"],
    ))
    elements.append(Spacer(1, 0.3 * cm))

    # ── Chain entries ─────────────────────────────────────────────────────────
    elements.append(Paragraph("Chain Entries:", styles["SubHeader"]))
    elements.append(Spacer(1, 0.15 * cm))

    rows = [["Seq", "Timestamp (UTC)", "Stage", "Action", "Actor"]]
    for entry in manifest.entries:
        ts = entry.timestamp[:19].replace("T", " ") if entry.timestamp else "—"
        rows.append([
            str(entry.sequence),
            ts,
            entry.stage[:22],
            entry.action[:45],
            entry.actor[:18],
        ])
    elements.append(_chain_table(rows))
    elements.append(Spacer(1, 0.3 * cm))

    # ── Hash linkage detail (first 5 and last 5) ──────────────────────────────
    elements.append(Paragraph(
        "Hash Linkage Detail (first and last entries):",
        styles["SubHeader"],
    ))
    elements.append(Spacer(1, 0.1 * cm))

    show_entries = (
        list(manifest.entries[:5]) +
        (list(manifest.entries[-5:]) if len(manifest.entries) > 5 else [])
    )
    for entry in show_entries:
        elements.append(Paragraph(
            f"[{entry.sequence:03d}] {entry.stage}",
            styles["SubHeader"],
        ))
        hash_rows = [
            ["Field",        "Value"],
            ["Entry ID",     entry.entry_id],
            ["Timestamp",    entry.timestamp],
            ["Action",       entry.action],
            ["Actor",        entry.actor],
            ["Prev Hash",    entry.prev_hash or "GENESIS"],
            ["Entry Hash",   entry.entry_hash],
        ]
        if entry.artifact_sha256:
            hash_rows.append(["Artifact SHA256", entry.artifact_sha256])
        elements.append(_hash_detail_table(hash_rows))
        elements.append(Spacer(1, 0.15 * cm))

    if len(manifest.entries) > 10:
        elements.append(Paragraph(
            f"… {len(manifest.entries) - 10} additional entries omitted for brevity. "
            f"Full chain available in machine-readable JSON export.",
            styles["Body"],
        ))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Helpers ───────────────────────────────────────────────────────────────────

def _summary_table(manifest) -> Table:
    rows = [
        ["Property",           "Value"],
        ["Analysis ID",        manifest.analysis_id],
        ["Case ID",            manifest.case_id],
        ["APK SHA256",         manifest.apk_sha256[:48] + "…" if len(manifest.apk_sha256) > 48 else manifest.apk_sha256],
        ["Total Entries",      str(manifest.total_entries)],
        ["Chain Valid",        "YES ✓" if manifest.chain_valid else "NO ✗ — INVESTIGATE IMMEDIATELY"],
        ["Hash Algorithm",     "SHA256 (FIPS 180-4)"],
        ["Serialisation",      "Canonical JSON (sort_keys=True, separators=(',',':'))"],
        ["ID Standard",        "UUIDv7 (RFC 9562 — timestamp-embedded)"],
        ["Legal Framework",    "Bharatiya Sakshya Adhiniyam Section 63"],
        ["Generated",          datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
    ]
    t = Table(rows)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  GARUDATVA_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
    ]))
    return t


def _chain_table(rows: list) -> Table:
    t = Table(rows, colWidths=[1*cm, 3.5*cm, 3.5*cm, 7*cm, 2.5*cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  GARUDATVA_BLUE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, -1), "Courier"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return t


def _hash_detail_table(rows: list) -> Table:
    t = Table(rows, colWidths=[3*cm, 14*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1),  colors.HexColor("#f0f0f0")),
        ("FONTNAME",    (0, 0), (0, -1),  "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1),  "Courier"),
        ("FONTSIZE",    (0, 0), (-1, -1), 7),
        ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("WORDWRAP",    (1, 0), (1, -1),  True),
    ]))
    return t
