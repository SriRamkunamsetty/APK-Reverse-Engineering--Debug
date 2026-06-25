"""
RAKSHAK — PDF Forensic Report Generator
Generates dual-format reports: Executive (2-page) + Full Technical (20-50 page)
Chain-of-custody compliant, FIR-admissible
"""

import os
import re
from html import escape
from pathlib import Path
from datetime import datetime, timezone

from reportlab.lib.pagesizes  import A4
from reportlab.lib.units       import cm, mm
from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
from reportlab.lib             import colors
from reportlab.lib.enums       import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus        import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)

from config import (
    PLATFORM_NAME, PLATFORM_VERSION, ORGANISATION, CLASSIFICATION_LEVEL,
    DANGEROUS_PERMISSIONS, MITRE_TECHNIQUES, IOC_URL_ALLOWLIST_PATTERNS
)

# ─── COLOUR PALETTE ──────────────────────────────────────────────────────────
C_BG       = colors.HexColor('#040608')
C_ACCENT   = colors.HexColor('#00C896')
C_DANGER   = colors.HexColor('#FF3333')
C_WARN     = colors.HexColor('#FF9900')
C_BLUE     = colors.HexColor('#00AAFF')
C_PURPLE   = colors.HexColor('#A855F7')
C_TEXT     = colors.HexColor('#1a1a1a')
C_SUBTEXT  = colors.HexColor('#4a4a4a')
C_BORDER   = colors.HexColor('#CCCCCC')
C_ROW_ALT  = colors.HexColor('#F4F8F4')
C_HEADER   = colors.HexColor('#0A2A1A')
DEVELOPER_CREDIT = "DEVELOPED BY MOHAN SRIRAM KUNAMSETTY"

SEV_COLORS = {
    'CRITICAL': colors.HexColor('#FF3333'),
    'HIGH'    : colors.HexColor('#FF9900'),
    'MEDIUM'  : colors.HexColor('#FFD700'),
    'LOW'     : colors.HexColor('#44BB44'),
    'CLEAN'   : colors.HexColor('#00CC77'),
}


def sev_color(s: str):
    return SEV_COLORS.get(s.upper(), colors.grey)


def is_allowlisted_url(url: str) -> bool:
    clean = str(url).strip().rstrip('.,);]')
    return any(re.search(pattern, clean, re.IGNORECASE) for pattern in IOC_URL_ALLOWLIST_PATTERNS)


def clean_genai_action(action: str) -> bool:
    return "GEMINI_API_KEY" not in action and "ANTHROPIC_API_KEY" not in action


# ─── STYLE BUILDER ────────────────────────────────────────────────────────────
def build_styles():
    base = getSampleStyleSheet()
    return {
        'title'    : ParagraphStyle('title', fontName='Helvetica-Bold',
                        fontSize=26, textColor=C_TEXT, spaceAfter=4,
                        leading=30, alignment=TA_LEFT),
        'subtitle' : ParagraphStyle('subtitle', fontName='Helvetica',
                        fontSize=11, textColor=C_SUBTEXT, spaceAfter=12, leading=16),
        'h1'       : ParagraphStyle('h1', fontName='Helvetica-Bold',
                        fontSize=14, textColor=C_TEXT, spaceBefore=14, spaceAfter=6,
                        leading=18, borderPadding=(0,0,4,0)),
        'h2'       : ParagraphStyle('h2', fontName='Helvetica-Bold',
                        fontSize=11, textColor=C_ACCENT, spaceBefore=10, spaceAfter=4),
        'body'     : ParagraphStyle('body', fontName='Helvetica',
                        fontSize=9.5, textColor=C_TEXT, leading=15, spaceAfter=6,
                        alignment=TA_JUSTIFY),
        'mono'     : ParagraphStyle('mono', fontName='Courier',
                        fontSize=8.5, textColor=colors.HexColor('#333333'),
                        leading=13, spaceAfter=4, backColor=colors.HexColor('#F5F5F5'),
                        leftIndent=6, rightIndent=6),
        'badge'    : ParagraphStyle('badge', fontName='Helvetica-Bold',
                        fontSize=8, textColor=colors.white, leading=12),
        'footer'   : ParagraphStyle('footer', fontName='Helvetica',
                        fontSize=7.5, textColor=C_SUBTEXT, alignment=TA_CENTER),
        'classified': ParagraphStyle('classified', fontName='Helvetica-Bold',
                        fontSize=9, textColor=C_DANGER, alignment=TA_CENTER,
                        spaceAfter=4),
        'label'    : ParagraphStyle('label', fontName='Helvetica-Bold',
                        fontSize=8, textColor=C_SUBTEXT, spaceAfter=1),
        'value'    : ParagraphStyle('value', fontName='Helvetica',
                        fontSize=9, textColor=C_TEXT, spaceAfter=4),
    }


# ─── PAGE TEMPLATE ────────────────────────────────────────────────────────────
class ReportCanvas:
    def __init__(self, case_id: str, classification: str):
        self.case_id        = case_id
        self.classification = classification

    def on_first_page(self, canvas, doc):
        self._draw_page(canvas, doc, is_first=True)

    def on_later_pages(self, canvas, doc):
        self._draw_page(canvas, doc, is_first=False)

    def _draw_page(self, canvas, doc, is_first: bool):
        canvas.saveState()
        w, h = A4

        # Left accent bar
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, 0, 4*mm, h, stroke=0, fill=1)

        # Top classification banner
        canvas.setFillColor(C_DANGER)
        canvas.rect(0, h - 10*mm, w, 10*mm, stroke=0, fill=1)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setFillColor(colors.white)
        canvas.drawCentredString(w/2, h - 6*mm, self.classification)

        # Highlighted ownership credit, visible but separate from forensic content.
        canvas.setFillColor(colors.HexColor('#FFE066'))
        canvas.setStrokeColor(C_ACCENT)
        canvas.setLineWidth(1.2)
        canvas.rect(4*mm, 10*mm, w - 4*mm, 9*mm, stroke=1, fill=1)
        canvas.setFont('Helvetica-Bold', 11)
        canvas.setFillColor(C_HEADER)
        canvas.drawCentredString(w/2, 13.7*mm, DEVELOPER_CREDIT)

        # Bottom footer bar
        canvas.setFillColor(C_HEADER)
        canvas.rect(0, 0, w, 10*mm, stroke=0, fill=1)
        canvas.setFont('Courier', 7)
        canvas.setFillColor(colors.HexColor('#00C896'))
        canvas.drawString(6*mm, 3.5*mm, f'RAKSHAK v{PLATFORM_VERSION}')
        canvas.drawCentredString(w/2, 3.5*mm, f'CASE: {self.case_id}')
        canvas.drawRightString(w - 6*mm, 3.5*mm, f'Page {canvas.getPageNumber()}')

        canvas.restoreState()


# ─── HELPER ELEMENTS ──────────────────────────────────────────────────────────
def section_header(title: str, icon: str = '▶') -> list:
    """Styled section header with accent underline"""
    st = build_styles()
    return [
        Spacer(1, 6*mm),
        Paragraph(f'{icon}  {title.upper()}', st['h1']),
        HRFlowable(width='100%', thickness=1.5, color=C_ACCENT, spaceAfter=6),
    ]


def kv_table(pairs: list[tuple], col_widths=None) -> Table:
    """Key-value pair table"""
    col_widths = col_widths or [5*cm, 11*cm]
    data = []
    for k, v in pairs:
        data.append([
            Paragraph(f'<b>{k}</b>', ParagraphStyle('kl', fontName='Helvetica-Bold',
                      fontSize=8.5, textColor=C_SUBTEXT)),
            Paragraph(str(v)[:200], ParagraphStyle('kv', fontName='Courier',
                      fontSize=8.5, textColor=C_TEXT)),
        ])
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('GRID',        (0,0),(-1,-1), 0.3, C_BORDER),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.white, C_ROW_ALT]),
        ('VALIGN',      (0,0),(-1,-1), 'TOP'),
        ('TOPPADDING',  (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ('LEFTPADDING', (0,0),(-1,-1), 8),
    ]))
    return t


def findings_table(headers: list, rows: list, col_widths=None) -> Table:
    """Styled findings table with header row"""
    header_style = ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8,
                                  textColor=C_ACCENT, leading=10)
    cell_style = ParagraphStyle('td', fontName='Helvetica', fontSize=8,
                                textColor=C_TEXT, leading=10)
    data = [
        [Paragraph(escape(str(h)), header_style) for h in headers]
    ] + [
        [Paragraph(escape(str(cell)), cell_style) for cell in row]
        for row in rows
    ]
    cw   = col_widths or [4*cm, 2.5*cm, 9.5*cm]
    t    = Table(data, colWidths=cw, repeatRows=1)
    t.setStyle(TableStyle([
        # Header
        ('BACKGROUND',  (0,0), (-1,0), C_HEADER),
        ('TEXTCOLOR',   (0,0), (-1,0), C_ACCENT),
        ('BOTTOMPADDING',(0,0),(-1,0), 7),
        ('TOPPADDING',  (0,0),(-1,0), 7),
        ('GRID',        (0,0), (-1,-1), 0.3, C_BORDER),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, C_ROW_ALT]),
        ('VALIGN',      (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',  (0,1), (-1,-1), 6),
        ('BOTTOMPADDING',(0,1),(-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 7),
        ('RIGHTPADDING',(0,0), (-1,-1), 7),
    ]))
    return t


def score_box(score: int, severity: str) -> Table:
    """Big score display box"""
    col = sev_color(severity)
    data = [[
        Paragraph(f'<font size="32"><b>{score}</b></font><font size="12"><b>/100</b></font>',
                  ParagraphStyle('sc', fontName='Helvetica-Bold', fontSize=32,
                                 textColor=col, alignment=TA_CENTER, leading=34)),
        Paragraph(f'<b>{severity}</b>',
                  ParagraphStyle('sv', fontName='Helvetica-Bold', fontSize=18,
                                 textColor=col, alignment=TA_CENTER, leading=22)),
    ]]
    t = Table(data, colWidths=[8*cm, 8*cm])
    t.setStyle(TableStyle([
        ('BOX',      (0,0), (-1,-1), 2, col),
        ('VALIGN',   (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',(0,0),(-1,-1), 10),
        ('BOTTOMPADDING',(0,0),(-1,-1), 10),
        ('BACKGROUND',(0,0),(-1,-1), colors.HexColor('#F8FFF8')),
    ]))
    return t


# ══════════════════════════════════════════════════════════════════════════════
# FULL TECHNICAL REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
class TechnicalReportGenerator:
    """
    Generates full 20-50 page technical IOC report
    For DRDO analysts and CERT-In filing
    """

    def generate(self, analysis: dict, output_path: str) -> str:
        st    = build_styles()
        case  = analysis.get('case_id', 'UNKNOWN')
        canvas_cb = ReportCanvas(case, CLASSIFICATION_LEVEL)

        doc = SimpleDocTemplate(
            output_path,
            pagesize        = A4,
            leftMargin      = 2*cm,
            rightMargin     = 1.5*cm,
            topMargin       = 2*cm,
            bottomMargin    = 2.7*cm,
            title           = f'RAKSHAK Technical Report — {case}',
            author          = ORGANISATION,
        )

        story = []
        story += self._cover_page(analysis, st)
        story += self._chain_of_custody(analysis, st)
        story += self._executive_brief(analysis, st)
        story += self._apk_fingerprints(analysis, st)
        story += self._structure_analysis(analysis, st)
        story += self._manifest_section(analysis, st)
        story += self._static_analysis_section(analysis, st)
        story += self._vulnerability_section(analysis, st)
        story += self._crypto_section(analysis, st)
        story += self._yara_section(analysis, st)
        story += self._banking_section(analysis, st)
        story += self._ioc_section(analysis, st)
        story += self._risk_breakdown(analysis, st)
        story += self._mitre_section(analysis, st)
        story += self._recommendations(analysis, st)
        story += self._legal_section(analysis, st)

        doc.build(
            story,
            onFirstPage  = canvas_cb.on_first_page,
            onLaterPages = canvas_cb.on_later_pages,
        )
        return output_path

    # ── COVER PAGE ────────────────────────────────────────────────────────────
    def _cover_page(self, data: dict, st: dict) -> list:
        rs  = data.get('risk_score', {})
        gen = data.get('genai_analysis', {})
        sev = rs.get('severity', 'HIGH')
        col = sev_color(sev)

        story = [Spacer(1, 1.5*cm)]
        story.append(Paragraph('SENSITIVE — DRDO CYBERSECURITY DIVISION', st['classified']))
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph(f'{PLATFORM_NAME} APK Threat Intelligence', st['title']))
        story.append(Paragraph('Full Technical Forensic Report', st['subtitle']))
        story.append(HRFlowable(width='100%', thickness=2, color=C_ACCENT, spaceAfter=10))
        story.append(Spacer(1, 6*mm))
        story.append(score_box(rs.get('final_score', 0), sev))
        story.append(Spacer(1, 8*mm))

        meta = [
            ('Case ID',          data.get('case_id', '—')),
            ('APK Filename',      data.get('apk_name', '—')),
            ('Malware Family',    rs.get('primary_family', '—')),
            ('Threat Type',       gen.get('primary_threat_type', '—')),
            ('Analysis Platform', data.get('platform', f'{PLATFORM_NAME} v{PLATFORM_VERSION}')),
            ('Organisation',      ORGANISATION),
            ('Analysis Date',     data.get('analysis_start', '—')[:19].replace('T', ' ') + ' UTC'),
            ('Duration',          f"{data.get('duration_sec', '—')} seconds"),
            ('Analyst',           data.get('analyst', 'RAKSHAK-AUTO')),
            ('APT Detected',      '⚠ YES — ESCALATE IMMEDIATELY' if rs.get('apt_detected') else 'No'),
            ('Nation-State Threat', '⚠ YES — ESCALATE IMMEDIATELY' if rs.get('nation_state') else 'No'),
        ]
        story.append(kv_table(meta))
        story.append(PageBreak())
        return story

    # ── CHAIN OF CUSTODY ──────────────────────────────────────────────────────
    def _chain_of_custody(self, data: dict, st: dict) -> list:
        h = data.get('hashes', {})
        story = section_header('Chain of Custody', '🔒')
        story.append(Paragraph(
            'The following cryptographic fingerprints establish an unbroken chain of custody '
            'for this APK sample. These values are recorded at intake and are admissible '
            'as digital evidence under the Information Technology Act, 2000.',
            st['body']
        ))
        custody = [
            ('File Name',       data.get('apk_name', '—')),
            ('File Size',       h.get('size_human', '—')),
            ('MD5',             h.get('md5', '—')),
            ('SHA-1',           h.get('sha1', '—')),
            ('SHA-256',         h.get('sha256', '—')),
            ('SHA-512',         h.get('sha512', '—')[:64] + '…' if len(h.get('sha512','')) > 64 else h.get('sha512','—')),
            ('Block Hash',      h.get('block_hash', '—')),
            ('Magic Valid',     '✓ Valid ZIP/APK' if h.get('magic_valid') else '✗ Invalid'),
            ('Intake Timestamp',h.get('timestamp', '—')),
            ('Analyst',         data.get('analyst', 'RAKSHAK-AUTO')),
        ]
        story.append(kv_table(custody))
        return story

    # ── EXECUTIVE BRIEF ───────────────────────────────────────────────────────
    def _executive_brief(self, data: dict, st: dict) -> list:
        story = section_header('Executive Brief', '📋')
        gen = data.get('genai_analysis', {})
        summary = data.get('executive_summary', '') or gen.get('malicious_intent_summary', '')
        if not summary or summary.strip().startswith('{') or 'GEMINI_API_KEY' in summary:
            rs = data.get('risk_score', {})
            score = rs.get('final_score', data.get('summary', {}).get('risk_score', 'unknown'))
            severity = rs.get('severity', data.get('summary', {}).get('severity', 'unknown'))
            threat_type = gen.get('primary_threat_type', data.get('summary', {}).get('threat_type', 'Suspicious APK'))
            family = rs.get('primary_family', data.get('summary', {}).get('primary_family', 'Unknown family'))
            summary = (
                f"This APK is assessed as {severity} risk with score {score}/100. "
                f"Primary classification: {threat_type}. Malware-family intelligence indicates {family}. "
                "The assessment is based on manifest inspection, static analysis, YARA family matching, "
                "IOC extraction, dynamic/sandbox indicators, and explainable risk scoring."
            )
        story.append(Paragraph(summary, st['body']))

        caps = gen.get('key_capabilities', [])
        if caps:
            story.append(Paragraph('<b>Key Capabilities Identified:</b>', st['h2']))
            for c in caps:
                story.append(Paragraph(f'• {c}', st['body']))

        actions = [a for a in gen.get('immediate_actions', []) if clean_genai_action(str(a))]
        if actions:
            story.append(Paragraph('<b>Immediate Actions Required:</b>', st['h2']))
            for i, a in enumerate(actions, 1):
                story.append(Paragraph(f'{i}. {a}', st['body']))
        return story

    # ── APK FINGERPRINTS ──────────────────────────────────────────────────────
    def _apk_fingerprints(self, data: dict, st: dict) -> list:
        story = section_header('APK Fingerprints & Metadata')
        m = data.get('manifest', {})
        c = data.get('certificates', {})
        h = data.get('hashes', {})
        s = data.get('structure', {})
        missing = 'Not extracted'

        def val(value):
            return value if value not in (None, '') else missing

        cert_state = 'Self-signed' if c.get('self_signed') else ('CA-signed' if c else missing)
        native_archs = ', '.join(s.get('native_arch_coverage', [])) or missing
        pairs = [
            ('Package Name',    m.get('package_name', '—')),
            ('Version Code',    m.get('version_code', '—')),
            ('Version Name',    m.get('version_name', '—')),
            ('Min SDK',         m.get('min_sdk', '—')),
            ('Target SDK',      m.get('target_sdk', '—')),
            ('Certificate',     'Self-signed' if c.get('self_signed') else 'CA-signed'),
            ('Signing Scheme',  c.get('signing_scheme', '—')),
            ('Multidex',        'Yes' if data.get('structure',{}).get('multidex') else 'No'),
            ('Native Archs',    ', '.join(data.get('structure',{}).get('native_arch_coverage',[]))),
        ]
        pairs = [(label, val(value)) for label, value in pairs]
        pairs = [
            ('APK Filename', data.get('apk_name', missing)),
            ('Manifest Parser', 'OK' if m.get('package_name') or m.get('permissions') else 'Manifest metadata not extracted'),
            ('APK Size', h.get('size_human', missing)),
            ('SHA-256', h.get('sha256', missing)),
            ('Total Files', s.get('total_files', missing)),
            ('DEX Files', len(s.get('dex_files', []))),
        ] + pairs
        story.append(kv_table(pairs))
        return story

    # ── STRUCTURE ─────────────────────────────────────────────────────────────
    def _structure_analysis(self, data: dict, st: dict) -> list:
        story = section_header('APK Structure Analysis')
        s = data.get('structure', {})
        story.append(kv_table([
            ('Total Files',    s.get('total_files', 0)),
            ('DEX Files',      len(s.get('dex_files', []))),
            ('Native Libs',    len(s.get('native_libs', []))),
            ('Asset Files',    len(s.get('asset_files', []))),
            ('Embedded APKs',  len(s.get('embedded_apks', []))),
            ('Anomalies',      len(s.get('structure_anomalies', []))),
        ]))
        if s.get('suspicious_files'):
            story.append(Paragraph('<b>Suspicious Files:</b>', st['h2']))
            rows = [[f.get('name',''), f.get('reason','')]
                    for f in s['suspicious_files'][:10]]
            story.append(findings_table(['File', 'Reason'], rows, [7*cm, 9.5*cm]))
        if s.get('high_entropy_files'):
            story.append(Paragraph('<b>High-Entropy (Possibly Encrypted) Files:</b>', st['h2']))
            rows = [[f.get('name',''), f.get('type',''), str(f.get('entropy',''))]
                    for f in s['high_entropy_files'][:8]]
            story.append(findings_table(['File', 'Type', 'Entropy'], rows, [7*cm, 5*cm, 4.5*cm]))
        return story

    # ── MANIFEST ──────────────────────────────────────────────────────────────
    def _manifest_section(self, data: dict, st: dict) -> list:
        story = section_header('AndroidManifest.xml Deep Analysis')
        m = data.get('manifest', {})

        permissions = m.get('permissions', [])
        story.append(Paragraph(f'<b>Requested Android Permissions ({len(permissions)}):</b>', st['h2']))
        if permissions:
            rows = []
            dangerous_lookup = {p.get('permission'): p for p in m.get('dangerous_permissions', [])}
            for perm in permissions:
                dangerous = dangerous_lookup.get(perm)
                short = perm.split('.')[-1]
                if dangerous:
                    rows.append([short, 'Dangerous', dangerous.get('severity', ''), dangerous.get('description', '')])
                elif perm in DANGEROUS_PERMISSIONS:
                    sev, _, desc = DANGEROUS_PERMISSIONS[perm]
                    rows.append([short, 'Dangerous', sev, desc])
                else:
                    rows.append([short, 'Normal', 'INFO', 'Requested by application manifest'])
            story.append(findings_table(
                ['Permission', 'Type', 'Severity', 'Assessment'],
                rows[:40], [4.7*cm, 2.8*cm, 2*cm, 7*cm]
            ))
        else:
            story.append(Paragraph(
                'No Android permissions were extracted from this APK manifest. This can occur when the manifest is malformed, obfuscated, protected, or unreadable by the local parser.',
                st['body']
            ))

        # Dangerous permissions table
        dp = m.get('dangerous_permissions', [])
        if dp:
            story.append(Paragraph(f'<b>Dangerous Permissions ({len(dp)}):</b>', st['h2']))
            rows = [[
                p.get('permission','').split('.')[-1],
                p.get('severity',''),
                str(p.get('risk_score',0)),
                p.get('description',''),
            ] for p in dp]
            story.append(findings_table(
                ['Permission', 'Severity', 'Score', 'Description'],
                rows, [4.5*cm, 2*cm, 1.5*cm, 8.5*cm]
            ))

        # Permission combos
        combos = m.get('permission_combos', [])
        if combos:
            story.append(Paragraph('<b>Dangerous Permission Combinations:</b>', st['h2']))
            for c in combos:
                story.append(Paragraph(f'⚠ {c}', ParagraphStyle('warn', fontName='Helvetica',
                    fontSize=9, textColor=sev_color('CRITICAL'), spaceAfter=4)))

        return story

    # ── STATIC ANALYSIS ───────────────────────────────────────────────────────
    def _static_analysis_section(self, data: dict, st: dict) -> list:
        story = section_header('Dangerous API Call Analysis')
        sa = data.get('static_analysis', {})
        apis = sa.get('api_analysis', {}).get('findings', [])
        if apis:
            rows = [[
                f.get('api','')[:35],
                f.get('severity',''),
                str(f.get('occurrences',0)),
                f.get('description',''),
                f.get('mitre',''),
            ] for f in sorted(apis, key=lambda x: x.get('risk_score',0), reverse=True)]
            story.append(findings_table(
                ['API Pattern', 'Severity', 'Hits', 'Description', 'MITRE'],
                rows, [4*cm, 2*cm, 1.2*cm, 7*cm, 2.3*cm]
            ))

        # Obfuscation signals
        obf = sa.get('api_analysis', {}).get('obfuscation_signals', [])
        if obf:
            story.append(Paragraph('<b>Obfuscation Techniques Detected:</b>', st['h2']))
            for o in obf:
                story.append(Paragraph(
                    f'<b>[{o.get("severity","")}]</b> {o.get("type","")} — {o.get("evidence","")}',
                    st['body']
                ))
        return story

    # ── VULNERABILITIES ───────────────────────────────────────────────────────
    def _vulnerability_section(self, data: dict, st: dict) -> list:
        story = section_header('CVE-Mapped Vulnerability Findings')
        sa = data.get('static_analysis', {})
        vulns = sa.get('vulnerabilities', {}).get('findings', [])
        if vulns:
            rows = [[
                v.get('id',''),
                v.get('name',''),
                v.get('severity',''),
                v.get('cve',''),
                v.get('remediation',''),
            ] for v in vulns]
            story.append(findings_table(
                ['ID', 'Vulnerability', 'Severity', 'CWE/CVE', 'Remediation'],
                rows, [2.5*cm, 4*cm, 2*cm, 2.5*cm, 5.5*cm]
            ))
        else:
            story.append(Paragraph('No standard vulnerabilities detected.', st['body']))
        return story

    # ── CRYPTO ────────────────────────────────────────────────────────────────
    def _crypto_section(self, data: dict, st: dict) -> list:
        story = section_header('Cryptographic Implementation Audit')
        crypto = data.get('static_analysis', {}).get('crypto_audit', {})
        issues = crypto.get('issues', [])
        story.append(kv_table([
            ('SSL Pinning Present', 'Yes ✓' if crypto.get('ssl_pinning_present') else 'No ✗'),
            ('Android Keystore Used', 'Yes ✓' if crypto.get('keystore_used') else 'No ✗'),
            ('Total Crypto Issues', str(crypto.get('total_crypto_issues', 0))),
        ]))
        if issues:
            rows = [[i.get('pattern',''), i.get('severity',''), i.get('description','')]
                    for i in issues]
            story.append(findings_table(
                ['Pattern', 'Severity', 'Description'],
                rows, [4*cm, 2.5*cm, 10*cm]
            ))
        return story

    # ── YARA ──────────────────────────────────────────────────────────────────
    def _yara_section(self, data: dict, st: dict) -> list:
        story = section_header('YARA Malware Pattern Matching')
        y = data.get('yara_analysis', {})
        story.append(kv_table([
            ('Total Rules Scanned',  str(y.get('total_rules_scanned', 0))),
            ('Rules Matched',        str(y.get('rules_matched', 0))),
            ('Malware Families',     ', '.join(y.get('malware_families', [])) or 'None'),
            ('Primary Family',       y.get('primary_family', '—')),
            ('APT Detected',         '⚠ YES' if y.get('apt_detected') else 'No'),
            ('Nation-State Threat',  '⚠ YES' if y.get('nation_state_threat') else 'No'),
        ]))
        matches = y.get('matches', [])
        if matches:
            rows = [[
                m.get('rule_id',''),
                m.get('family',''),
                m.get('severity',''),
                m.get('description',''),
                str(m.get('pattern_hits',0)),
            ] for m in matches]
            story.append(findings_table(
                ['Rule ID', 'Family', 'Severity', 'Description', 'Hits'],
                rows, [3.5*cm, 3*cm, 2*cm, 6.5*cm, 1.5*cm]
            ))
        return story

    # ── BANKING ───────────────────────────────────────────────────────────────
    def _banking_section(self, data: dict, st: dict) -> list:
        story = section_header('Indian Banking Fraud Threat Analysis')
        bt = data.get('static_analysis', {}).get('banking_threats', {})
        story.append(kv_table([
            ('OTP Harvesting',        '⚠ DETECTED' if bt.get('otp_harvesting') else 'Not detected'),
            ('Overlay Attack',        '⚠ DETECTED' if bt.get('overlay_attack') else 'Not detected'),
            ('Accessibility Abuse',   '⚠ DETECTED' if bt.get('accessibility_abuse') else 'Not detected'),
            ('Banking Risk Score',    f"{bt.get('banking_risk_score',0)}/100"),
            ('UPI Fraud Indicators',  ', '.join(bt.get('upi_fraud_indicators', [])) or 'None'),
            ('Targeted Brands',       ', '.join(bt.get('banking_app_targeting', [])) or 'None'),
        ]))
        kc = bt.get('fraud_kill_chain', [])
        if kc:
            story.append(Paragraph('<b>Fraud Kill Chain:</b>', st['h2']))
            rows = [[k.get('stage',''), k.get('indicator',''), k.get('mitre','')]
                    for k in kc]
            story.append(findings_table(
                ['Stage', 'Indicator', 'MITRE Technique'],
                rows, [2.5*cm, 10*cm, 4*cm]
            ))
        return story

    # ── IOC SECTION ───────────────────────────────────────────────────────────
    def _ioc_section(self, data: dict, st: dict) -> list:
        story = section_header('Indicators of Compromise (IOCs)')
        s = data.get('strings', {})

        urls = [u for u in s.get('urls', []) if not is_allowlisted_url(u.get('url', u))]
        if urls:
            story.append(Paragraph(f'<b>URLs ({len(urls)}):</b>', st['h2']))
            rows = [[u.get('url','')[:70], u.get('risk','')] for u in urls[:20]]
            story.append(findings_table(['URL', 'Risk'], rows, [13*cm, 3.5*cm]))
        elif s.get('filtered_urls'):
            story.append(Paragraph(
                f"{len(s.get('filtered_urls', []))} standard framework/license/certificate URLs were filtered from IOC output.",
                st['body']
            ))

        ips = s.get('ips', [])
        if ips:
            story.append(Paragraph(f'<b>IP Addresses / C2 Candidates ({len(ips)}):</b>', st['h2']))
            rows = [[i.get('ip',''), i.get('type','')] for i in ips[:20]]
            story.append(findings_table(['IP:Port', 'Assessment'], rows, [5*cm, 11.5*cm]))

        tg = s.get('telegram_tokens', [])
        if tg:
            story.append(Paragraph(f'<b>Telegram Bot C2 Tokens ({len(tg)}):</b>', st['h2']))
            for t in tg:
                story.append(Paragraph(t, st['mono']))

        emails = s.get('emails', [])
        if emails:
            story.append(Paragraph(f'<b>Email Addresses ({len(emails)}):</b>', st['h2']))
            story.append(Paragraph(', '.join(emails[:10]), st['body']))

        return story

    # ── RISK BREAKDOWN ────────────────────────────────────────────────────────
    def _risk_breakdown(self, data: dict, st: dict) -> list:
        story = section_header('Risk Score — XAI Breakdown')
        rs = data.get('risk_score', {})
        bd = rs.get('breakdown', {})

        pairs = []
        for dim, val in bd.items():
            lbl = dim.replace('_', ' ').title()
            pairs.append((lbl, f"Score: {val.get('raw_score',0):.1f} | Weight: {val.get('weight',0)*100:.0f}% | Contribution: +{val.get('contribution',0):.2f}"))
        story.append(kv_table(pairs))

        attr = rs.get('attribution', [])
        if attr:
            story.append(Paragraph('<b>Top Risk Contributors:</b>', st['h2']))
            rows = [[a.get('factor',''), f"+{a.get('points',0):.1f}", a.get('detail','')[:80]]
                    for a in attr[:8]]
            story.append(findings_table(
                ['Factor', 'Points', 'Evidence'],
                rows, [5*cm, 2*cm, 9.5*cm]
            ))
        return story

    # ── MITRE ─────────────────────────────────────────────────────────────────
    def _mitre_section(self, data: dict, st: dict) -> list:
        story = section_header('MITRE ATT&CK Mobile Framework Mapping')
        techniques = data.get('risk_score', {}).get('mitre_techniques', [])
        if techniques:
            rows = [[t.get('id',''), MITRE_TECHNIQUES.get(t.get('id',''), t.get('name','') or 'Unknown')] for t in techniques]
            story.append(findings_table(['Technique ID', 'Name'], rows, [3.5*cm, 13*cm]))
        else:
            story.append(Paragraph('No MITRE techniques mapped.', st['body']))
        return story

    # ── RECOMMENDATIONS ───────────────────────────────────────────────────────
    def _recommendations(self, data: dict, st: dict) -> list:
        story = section_header('Recommendations & Remediation')
        rs  = data.get('risk_score', {})
        gen = data.get('genai_analysis', {})
        actions = [a for a in gen.get('immediate_actions', []) if clean_genai_action(str(a))]

        if rs.get('cert_in_report_required'):
            story.append(Paragraph(
                '⚠ CERT-In REPORTING MANDATORY: Risk score ≥85 or APT detected. '
                'File incident report with CERT-In within 6 hours per NCSP mandate.',
                ParagraphStyle('alert', fontName='Helvetica-Bold', fontSize=10,
                               textColor=C_DANGER, spaceAfter=12)
            ))

        if rs.get('immediate_block_recommended'):
            story.append(Paragraph(
                '🔴 IMMEDIATE BLOCK RECOMMENDED: Push IOC hash and domains to all '
                'organizational firewalls, EDR, and mobile MDM immediately.',
                ParagraphStyle('block', fontName='Helvetica-Bold', fontSize=10,
                               textColor=C_WARN, spaceAfter=12)
            ))

        for i, action in enumerate(actions, 1):
            story.append(Paragraph(f'{i}. {action}', st['body']))

        return story

    # ── LEGAL ─────────────────────────────────────────────────────────────────
    def _legal_section(self, data: dict, st: dict) -> list:
        story = section_header('Legal Framework & IT Act Mapping')
        story.append(Paragraph(
            'The following provisions of the Information Technology Act, 2000 '
            '(as amended by IT Amendment Act, 2008) apply to the malicious behaviours '
            'identified in this analysis:', st['body']
        ))
        it_sections = [
            ('Section 43', 'Penalty for damage to computer/systems — unauthorized access'),
            ('Section 43A', 'Compensation for failure to protect sensitive personal data'),
            ('Section 66', 'Computer related offences — imprisonment up to 3 years'),
            ('Section 66B', 'Punishment for dishonestly receiving stolen computer resource'),
            ('Section 66C', 'Identity theft — imprisonment up to 3 years, fine ₹1 lakh'),
            ('Section 66D', 'Cheating by personation using computer resource'),
            ('Section 66E', 'Violation of privacy — capturing/transmitting private images'),
            ('Section 66F', 'Cyber terrorism — imprisonment up to life'),
            ('Section 72', 'Breach of confidentiality and privacy'),
        ]
        story.append(findings_table(
            ['IT Act Section', 'Provision'],
            [[s, d] for s, d in it_sections],
            [4*cm, 12.5*cm]
        ))
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph(
            f'Report generated by {PLATFORM_NAME} v{PLATFORM_VERSION} on behalf of {ORGANISATION}. '
            f'Case Reference: {data.get("case_id","UNKNOWN")}. '
            f'This report is classified {CLASSIFICATION_LEVEL}. '
            f'Unauthorised disclosure is prohibited under Official Secrets Act, 1923.',
            ParagraphStyle('disc', fontName='Helvetica', fontSize=7.5,
                           textColor=C_SUBTEXT, alignment=TA_JUSTIFY)
        ))
        return story


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════
def generate_pdf_report(analysis: dict, output_dir: str) -> str:
    """Generate full technical PDF report. Returns path to generated file."""
    case_id = analysis.get('case_id', 'UNKNOWN')
    fname   = f"RAKSHAK-{case_id}-technical-report.pdf"
    out     = str(Path(output_dir) / fname)
    gen     = TechnicalReportGenerator()
    gen.generate(analysis, out)
    return out
