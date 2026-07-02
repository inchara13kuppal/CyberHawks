"""
Garudatva v3 — Forensic Report Template
12-section layout and content for the PDF report.
Called by pdf_builder.py to get section-specific flowables.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle

GARUDATVA_DARK = colors.HexColor("#1a1a2e")
GARUDATVA_BLUE = colors.HexColor("#16213e")
GARUDATVA_GOLD = colors.HexColor("#e94560")

TIER_COLORS = {
    "BENIGN":     colors.HexColor("#27ae60"),
    "SUSPICIOUS": colors.HexColor("#f39c12"),
    "HIGH_RISK":  colors.HexColor("#e67e22"),
    "CRITICAL":   colors.HexColor("#c0392b"),
}

RECOMMENDED_ACTIONS = {
    "BENIGN": [
        "Document analysis result. No immediate enforcement action required.",
        "Archive signed report per standard records retention policy.",
        "Re-analyse if new intelligence links package name to known campaign.",
    ],
    "SUSPICIOUS": [
        "Forward signed report to Cyber Crime Unit for senior review.",
        "Preserve seized device — do not factory reset or power off.",
        "Identify victim financial accounts and request precautionary freeze.",
        "Issue notice to app distribution platform for takedown.",
    ],
    "HIGH_RISK": [
        "Issue preservation notice to payment gateway operators immediately.",
        "Apply for arrest warrant — this report constitutes supporting evidence.",
        "Submit mutual legal assistance request for C2 server jurisdiction.",
        "Notify CERT-In under IT Act Section 70B within 6 hours.",
        "Brief public prosecutor — report is court-admissible under BSA Sec 63.",
        "Freeze mule accounts identified via IMPS/NEFT transaction strings.",
    ],
    "CRITICAL": [
        "IMMEDIATE: Contact victim's bank for emergency account freeze.",
        "Apply for arrest warrant — report provides prima facie evidence.",
        "Emergency mutual legal assistance request for C2 server takedown.",
        "Notify CBI Cyber Crime Unit and CERT-In simultaneously.",
        "Initiate UAPA Section 46 proceedings if transnational links confirmed.",
        "Obtain ISP call data records and network logs via legal process.",
        "Coordinate with Financial Intelligence Unit — India (FIU-IND).",
        "Request SFIO referral if corporate fraud indicators present.",
    ],
}


def section_divider(styles: dict) -> list:
    """Standard section divider with gold rule."""
    return [
        HRFlowable(width="100%", thickness=1, color=GARUDATVA_GOLD),
        Spacer(1, 0.3 * cm),
    ]


def make_table(rows: list, col_widths: list = None) -> Table:
    """Styled two-tone table for all report sections."""
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0),  (-1, 0),  GARUDATVA_BLUE),
        ("TEXTCOLOR",     (0, 0),  (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0),  (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0),  (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1),  (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",          (0, 0),  (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN",        (0, 0),  (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0),  (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0),  (-1, -1), 5),
        ("TOPPADDING",    (0, 0),  (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0),  (-1, -1), 3),
    ]))
    return t


# ── Section 1 — Application Identity ─────────────────────────────────────────

def section_app_identity(styles: dict, static, analysis_id: str) -> list:
    elements = [
        Paragraph("1. APPLICATION IDENTITY", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    rows = [["Property", "Value"]]
    rows.append(["Analysis ID", analysis_id])
    if static:
        rows.append(["APK SHA256", getattr(static, "apk_sha256", "—")])
        if static.manifest:
            m = static.manifest
            rows += [
                ["Package Name",  m.package_name or "—"],
                ["Version Name",  m.version_name or "—"],
                ["Version Code",  m.version_code or "—"],
                ["Min SDK",       m.min_sdk or "—"],
                ["Target SDK",    m.target_sdk or "—"],
                ["Debuggable",    "YES ⚠" if m.debuggable else "No"],
                ["Allow Backup",  "YES" if m.allow_backup else "No"],
                ["Cleartext HTTP","YES ⚠" if m.uses_cleartext_traffic else "No"],
            ]
        if static.cert:
            c = static.cert
            subj = c.subject[:70] + "…" if len(c.subject) > 70 else c.subject
            rows += [
                ["Cert Subject",    subj],
                ["Cert SHA256",     (c.signing_cert_sha256 or "—")[:48] + "…"],
                ["Self-Signed",     "YES ⚠" if c.is_self_signed else "No"],
                ["Expired",         "YES ⚠" if c.is_expired else "No"],
                ["Debug Cert",      "YES ⚠" if c.is_debug_cert else "No"],
            ]
    rows.append(["Report Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")])
    elements.append(make_table(rows))
    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 2 — Case Metadata ─────────────────────────────────────────────────

def section_case_metadata(styles: dict, case) -> list:
    elements = [
        Paragraph("2. CASE METADATA", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if case:
        rows = [
            ["Field", "Value"],
            ["FIR Number",         case.fir_number],
            ["Case ID",            case.case_id],
            ["District",           case.district],
            ["Police Station",     case.station],
            ["Reporting Officer",  f"{case.reporting_officer.name}  |  Badge: {case.reporting_officer.badge_id}  |  Rank: {case.reporting_officer.rank}"],
            ["Reviewing Officer",  f"{case.reviewing_officer.name}  |  Badge: {case.reviewing_officer.badge_id}  |  Rank: {case.reviewing_officer.rank}"],
            ["Device IMEI",        case.device.imei],
            ["Device Make/Model",  f"{case.device.make} {case.device.model}"],
            ["Android Version",    case.device.android_version],
        ]
        if case.seizure_video_hash:
            rows.append(["Seizure Video SHA256", case.seizure_video_hash[:48] + "…"])
        if case.seizure_gps_lat:
            rows.append(["Seizure GPS",
                          f"{case.seizure_gps_lat:.6f}, {case.seizure_gps_lon:.6f}"])
        if case.seizure_witnesses:
            rows.append(["Witnesses", ", ".join(case.seizure_witnesses)])
        elements.append(make_table(rows))
    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 3 — Permissions ───────────────────────────────────────────────────

def section_permissions(styles: dict, static, permission_reasons: list) -> list:
    elements = [
        Paragraph("3. PERMISSIONS ANALYSIS", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if static and static.manifest:
        m = static.manifest
        elements.append(Paragraph(
            f"The application declares {len(m.permissions)} permissions in total, "
            f"of which {len(m.toxic_permissions)} are classified as toxic or high-risk.",
            styles["Body"],
        ))
        if m.toxic_permissions:
            elements.append(Spacer(1, 0.2 * cm))
            rows = [["Toxic Permission", "Category"]]
            for p in m.toxic_permissions:
                short = p.replace("android.permission.", "")
                cat = _permission_category(p)
                rows.append([short, cat])
            elements.append(make_table(rows))
        if m.dangerous_components:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("Dangerous Component Declarations:", styles["SubHeader"]))
            for comp in m.dangerous_components:
                elements.append(Paragraph(f"• {comp}", styles["Mono"]))
        if permission_reasons:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("Scoring Factors:", styles["SubHeader"]))
            for reason in permission_reasons[:12]:
                elements.append(Paragraph(f"• {reason}", styles["Body"]))
    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 4 — Code Analysis ─────────────────────────────────────────────────

def section_code_analysis(styles: dict, static) -> list:
    elements = [
        Paragraph("4. CODE ANALYSIS FINDINGS", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if static:
        if static.dex:
            d = static.dex
            elements.append(Paragraph(
                f"DEX bytecode analysis extracted {len(d.all_strings):,} strings, "
                f"identified {len(d.urls)} hardcoded URLs and {len(d.ips)} IP addresses. "
                f"Obfuscation level assessed at {d.obfuscation_level}/3. "
                f"Dynamic DEX class loading: {'DETECTED' if d.dynamic_loading else 'Not detected'}. "
                f"Java Reflection API: {'DETECTED' if d.reflection_used else 'Not detected'}. "
                f"Encoded payload blobs: {len(d.encoded_payloads)}.",
                styles["Body"],
            ))
            if d.obfuscation_evidence:
                elements.append(Spacer(1, 0.2 * cm))
                elements.append(Paragraph("Obfuscation Evidence:", styles["SubHeader"]))
                for ev in d.obfuscation_evidence:
                    elements.append(Paragraph(f"• {ev}", styles["Body"]))

        if static.india_matches:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph(
                f"India-Specific Fraud Pattern Matches ({len(static.india_matches)} patterns):",
                styles["SubHeader"],
            ))
            rows = [["Pattern ID", "Pattern Name", "Category", "Severity"]]
            for m in static.india_matches:
                rows.append([m.pattern_id, m.pattern_name, m.category, m.severity])
            elements.append(make_table(rows))

        if static.yara and static.yara.matches:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph(
                f"YARA Ruleset Matches ({len(static.yara.matches)} rules across "
                f"{len(static.yara.categories_hit)} categories):",
                styles["SubHeader"],
            ))
            rows = [["Rule Name", "Category", "Rule File"]]
            for match in static.yara.matches:
                rows.append([match.rule_name, match.category, match.rule_file])
            elements.append(make_table(rows))

        if static.native:
            n = static.native
            if n.suspicious_imports or n.anti_debug_signals:
                elements.append(Spacer(1, 0.3 * cm))
                elements.append(Paragraph("Native Library (.so) Findings:", styles["SubHeader"]))
                elements.append(Paragraph(
                    f"Analysed {len(n.so_files_analyzed)} native libraries. "
                    f"Suspicious imports: {len(n.suspicious_imports)}. "
                    f"Anti-debug signals: {', '.join(n.anti_debug_signals) if n.anti_debug_signals else 'None'}.",
                    styles["Body"],
                ))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 5 — Dynamic Behavior ──────────────────────────────────────────────

def section_dynamic(styles: dict, dynamic) -> list:
    elements = [
        Paragraph("5. DYNAMIC BEHAVIOR", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if not dynamic:
        elements.append(Paragraph(
            "Dynamic sandbox analysis was not performed. "
            "Static risk score did not meet the threshold for dynamic escalation (≥65).",
            styles["Body"],
        ))
    else:
        rows = [
            ["Metric", "Value"],
            ["C2 URLs captured",        str(len(dynamic.get("c2_urls", [])))],
            ["Network artifacts",        str(len(dynamic.get("network_artifacts", [])))],
            ["Crypto operations logged", str(len(dynamic.get("crypto_artifacts", [])))],
            ["SMS intercept events",     str(len(dynamic.get("sms_intercepts", [])))],
            ["Clipboard events",         str(len(dynamic.get("clipboard_events", [])))],
            ["Accessibility events",     str(len(dynamic.get("accessibility_events", [])))],
            ["JA4 TLS fingerprints",     str(len(dynamic.get("ja4_hashes", [])))],
        ]
        if dynamic.get("monkey_stats"):
            ms = dynamic["monkey_stats"]
            rows += [
                ["UI taps emulated",     str(ms.get("taps", 0))],
                ["UI swipes emulated",   str(ms.get("swipes", 0))],
                ["Text inputs sent",     str(ms.get("text_inputs", 0))],
                ["Analysis duration (s)",str(ms.get("duration_seconds", 0))],
            ]
        elements.append(make_table(rows))

        if dynamic.get("c2_urls"):
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph("Captured C2 URLs (pre-encryption):", styles["SubHeader"]))
            for url in dynamic["c2_urls"][:15]:
                elements.append(Paragraph(f"• {url}", styles["Mono"]))

        if dynamic.get("anti_evasion"):
            ae = dynamic["anti_evasion"]
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph(
                f"Anti-evasion profile applied: {len(ae.get('steps', []))} spoofing measures. "
                f"Battery spoofed to {ae.get('battery_level', '—')}%.",
                styles["Body"],
            ))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 6 — Cryptographic Artifacts ──────────────────────────────────────

def section_crypto(styles: dict, dynamic) -> list:
    elements = [
        Paragraph("6. CRYPTOGRAPHIC ARTIFACTS", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if not dynamic or not dynamic.get("crypto_artifacts"):
        elements.append(Paragraph(
            "No cryptographic artifacts were captured. "
            "Either dynamic analysis was not performed or no encryption operations were observed.",
            styles["Body"],
        ))
    else:
        artifacts = dynamic["crypto_artifacts"]
        elements.append(Paragraph(
            f"{len(artifacts)} cryptographic operation(s) were intercepted "
            f"during dynamic analysis. Each is identified by a unique Cipher object "
            f"hashCode() linking the key initialisation to its payload.",
            styles["Body"],
        ))
        elements.append(Spacer(1, 0.2 * cm))
        rows = [["Cipher ID", "Algorithm", "Mode", "Key Length (bits)", "Interceptor Class"]]
        for a in artifacts[:20]:
            rows.append([
                str(a.get("cipher_id", "—")),
                a.get("algorithm", "—"),
                "ENCRYPT" if a.get("mode") == 1 else "DECRYPT",
                str(a.get("key_length_bits", "—")),
                (a.get("interceptor_class") or "—")[:40],
            ])
        elements.append(make_table(rows))

        # Show interceptor classes (the malware class names)
        interceptor_classes = list(set(
            a.get("interceptor_class") for a in artifacts
            if a.get("interceptor_class")
        ))
        if interceptor_classes:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph(
                "Custom OkHttp Interceptor Classes (malware-specific encryptors):",
                styles["SubHeader"],
            ))
            for cls in interceptor_classes[:10]:
                elements.append(Paragraph(f"• {cls}", styles["Mono"]))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 7 — Network Communication ────────────────────────────────────────

def section_network(styles: dict, static, dynamic) -> list:
    elements = [
        Paragraph("7. NETWORK COMMUNICATION ANALYSIS", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    from models.ioc import IOCType

    static_ips, static_urls, static_phones = [], [], []
    if static and static.iocs:
        static_ips   = [i.value for i in static.iocs if i.ioc_type == IOCType.IP][:15]
        static_urls  = [i.value for i in static.iocs if i.ioc_type == IOCType.URL][:10]
        static_phones= [i.value for i in static.iocs if i.ioc_type == IOCType.PHONE_NUMBER][:10]

    if static_ips:
        elements.append(Paragraph("IP Addresses (extracted from DEX strings):", styles["SubHeader"]))
        for ip in static_ips:
            elements.append(Paragraph(f"• {ip}", styles["Mono"]))
        elements.append(Spacer(1, 0.2 * cm))

    if static_phones:
        elements.append(Paragraph("Phone Numbers (extracted from DEX strings):", styles["SubHeader"]))
        for ph in static_phones:
            elements.append(Paragraph(f"• {ph}", styles["Mono"]))
        elements.append(Spacer(1, 0.2 * cm))

    if dynamic and dynamic.get("ja4_hashes"):
        elements.append(Paragraph("JA4 TLS Client Fingerprints (custom engine):", styles["SubHeader"]))
        for h in dynamic["ja4_hashes"][:8]:
            elements.append(Paragraph(f"• {h}", styles["Mono"]))
        elements.append(Spacer(1, 0.2 * cm))

    if dynamic and dynamic.get("network_artifacts"):
        elements.append(Paragraph(
            f"Total network connections observed during dynamic analysis: "
            f"{len(dynamic['network_artifacts'])}.",
            styles["Body"],
        ))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 8 — Cloud C2 ──────────────────────────────────────────────────────

def section_cloud_c2(styles: dict, cloud) -> list:
    elements = [
        Paragraph("8. CLOUD C2 ASSESSMENT", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if not cloud:
        elements.append(Paragraph("Cloud C2 classification was not performed.", styles["Body"]))
    else:
        additions = cloud.get("score_additions", {})
        label_map = {
            "connects_to_cloud_asn":    "Cloud ASN Connection Detected",
            "dga_domain_detected":      "DGA (Algorithmically Generated) Domain",
            "domain_fronting_detected": "Domain Fronting (SNI/Host Mismatch)",
            "firebase_c2_pattern":      "Firebase Realtime Database C2 Channel",
            "tunnel_service_detected":  "Tunnel Service (ngrok / Cloudflare Tunnel)",
        }
        if additions:
            rows = [["Detection Type", "Score Addition"]]
            for key, val in additions.items():
                rows.append([label_map.get(key, key), f"+{val} pts"])
            elements.append(make_table(rows))
            elements.append(Spacer(1, 0.2 * cm))

        if cloud.get("firebase_c2"):
            elements.append(Paragraph("Firebase C2 Endpoints:", styles["SubHeader"]))
            for fb in cloud["firebase_c2"][:5]:
                elements.append(Paragraph(f"• {fb}", styles["Mono"]))

        if cloud.get("tunnel_services"):
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("Tunnel Services Detected:", styles["SubHeader"]))
            for t in cloud["tunnel_services"][:5]:
                elements.append(Paragraph(
                    f"• {t.get('domain', '')} via {t.get('service', '')}",
                    styles["Mono"],
                ))

        if cloud.get("dga_domains"):
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph("DGA Domains (Shannon entropy > 3.8):", styles["SubHeader"]))
            for dga in cloud["dga_domains"][:5]:
                elements.append(Paragraph(
                    f"• {dga.get('domain', '')} — entropy: {dga.get('entropy', '')}",
                    styles["Mono"],
                ))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 9 — IOCs ──────────────────────────────────────────────────────────

def section_iocs(styles: dict, static, dynamic) -> list:
    elements = [
        Paragraph("9. INDICATORS OF COMPROMISE", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    all_iocs = []
    if static and static.iocs:
        all_iocs.extend(static.iocs)

    if not all_iocs:
        elements.append(Paragraph("No IOCs extracted.", styles["Body"]))
    else:
        rows = [["Type", "Value", "Source", "Context"]]
        for ioc in all_iocs[:30]:
            rows.append([
                ioc.ioc_type.value,
                ioc.value[:55],
                ioc.source[:20],
                (ioc.context or "")[:30],
            ])
        elements.append(make_table(rows))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 10 — Syndicate ────────────────────────────────────────────────────

def section_syndicate(styles: dict, graph) -> list:
    elements = [
        Paragraph("10. SYNDICATE LINKAGE", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    syndicates = graph.get("syndicates", []) if graph else []
    if not syndicates:
        elements.append(Paragraph(
            "No syndicate links were identified. This APK does not share "
            "C2 infrastructure, signing certificates, or AES keys with any "
            "previously analysed case in the Garudatva graph database.",
            styles["Body"],
        ))
    else:
        elements.append(Paragraph(
            f"{len(syndicates)} syndicate link(s) identified. "
            "This APK shares infrastructure with cases from other districts, "
            "indicating coordinated criminal operations.",
            styles["Body"],
        ))
        elements.append(Spacer(1, 0.2 * cm))
        rows = [["Link Type", "Related Case ID", "Shared Indicator", "Confidence"]]
        for s in syndicates[:15]:
            rows.append([
                s.get("link_type", "—"),
                (s.get("related_case") or "—")[:24],
                (s.get("shared_ip") or s.get("shared_cert") or "—")[:35],
                s.get("confidence", "—"),
            ])
        elements.append(make_table(rows))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 11 — Risk Assessment ──────────────────────────────────────────────

def section_risk(styles: dict, static) -> list:
    elements = [
        Paragraph("11. RISK ASSESSMENT", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    if static and static.risk_score:
        rs = static.risk_score
        tier_color = TIER_COLORS.get(str(rs.tier), colors.grey)

        elements.append(Paragraph(
            f"RISK SCORE: {rs.total:.1f} / 100",
            ParagraphStyle(
                "RiskScore", fontSize=18, fontName="Helvetica-Bold",
                textColor=tier_color, spaceAfter=4,
            ),
        ))
        elements.append(Paragraph(
            f"RISK TIER: {rs.tier}",
            ParagraphStyle(
                "RiskTier", fontSize=14, fontName="Helvetica-Bold",
                textColor=tier_color, spaceAfter=10,
            ),
        ))

        rows = [
            ["Score Component", "Score", "Max Weight"],
            ["ML Classifier (Random Forest, AUC 0.972)", f"{rs.ml_score:.2f}", "35"],
            ["Syscall Profile (strace dynamic features)", f"{rs.syscall_score:.2f}", "15"],
            ["YARA Ruleset Matches", f"{rs.yara_score:.2f}", "20"],
            ["Toxic Permission Combinations", f"{rs.permission_score:.2f}", "10"],
            ["India Fraud Pattern Matches", f"{rs.india_pattern_score:.2f}", "10"],
            ["Certificate Anomalies", f"{rs.cert_score:.2f}", "5"],
            ["Manifest Obfuscation", f"{rs.manifest_score:.2f}", "5"],
        ]
        # Cloud/evasion additions
        for flag, pts in rs.cloud_c2_additions.items():
            rows.append([f"Cloud C2: {flag}", f"+{pts:.1f}", "—"])
        for flag, pts in rs.evasion_additions.items():
            rows.append([f"Evasion: {flag}", f"+{pts:.1f}", "—"])
        rows.append(["── TOTAL ──", f"{rs.total:.2f}", "100"])
        elements.append(make_table(rows))

        # SHAP explainability
        if rs.shap_features:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph(
                "ML Explainability — Top SHAP Features (why the model flagged this APK):",
                styles["SubHeader"],
            ))
            rows2 = [["Rank", "Feature Name", "SHAP Value", "Feature Value"]]
            for f in rs.shap_features[:10]:
                rows2.append([
                    str(f.rank),
                    f.feature_name,
                    f"{f.shap_value:+.4f}",
                    f"{f.feature_value:.3f}",
                ])
            elements.append(make_table(rows2))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Section 12 — Recommended Actions ─────────────────────────────────────────

def section_actions(styles: dict, static) -> list:
    elements = [
        Paragraph("12. RECOMMENDED IMMEDIATE ACTIONS", styles["SectionHeader"]),
        *section_divider(styles),
    ]
    tier = "SUSPICIOUS"
    if static and static.risk_score:
        tier = str(static.risk_score.tier)

    for action in RECOMMENDED_ACTIONS.get(tier, []):
        elements.append(Paragraph(f"• {action}", styles["Body"]))

    elements.append(Spacer(1, 0.5 * cm))
    return elements


# ── Helper ────────────────────────────────────────────────────────────────────

def _permission_category(perm: str) -> str:
    cats = {
        "READ_SMS": "SMS / OTP Theft",
        "RECEIVE_SMS": "SMS / OTP Theft",
        "SEND_SMS": "SMS Fraud",
        "BIND_ACCESSIBILITY_SERVICE": "Keylogging / Overlay",
        "SYSTEM_ALERT_WINDOW": "Screen Overlay",
        "BIND_DEVICE_ADMIN": "Device Takeover",
        "REQUEST_INSTALL_PACKAGES": "Dropper",
        "RECORD_AUDIO": "Surveillance",
        "CAMERA": "Surveillance",
        "ACCESS_FINE_LOCATION": "Tracking",
        "ACCESS_BACKGROUND_LOCATION": "Tracking",
        "READ_CONTACTS": "Data Exfil",
        "READ_CALL_LOG": "Data Exfil",
        "USE_BIOMETRIC": "Auth Bypass",
        "PROCESS_OUTGOING_CALLS": "Call Intercept",
    }
    for k, v in cats.items():
        if k in perm:
            return v
    return "Dangerous"
