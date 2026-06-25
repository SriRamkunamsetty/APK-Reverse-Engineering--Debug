"""
RAKSHAK — Command Line Interface
Standalone APK analysis from terminal — no web server needed
"""

import sys, os, json, argparse, time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from rich.console  import Console
from rich.table    import Table
from rich.panel    import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text     import Text
from rich.columns  import Columns
from rich.rule     import Rule
from rich          import box

from core.pipeline    import RakshakPipeline
from core.report_engine import generate_pdf_report
from database.db      import save_case, list_cases, search_ioc, get_stats
from config           import PLATFORM_NAME, PLATFORM_VERSION, ORGANISATION, REPORT_DIR

console = Console()

BANNER = f"""
[bold green]██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗[/]
[bold green]██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝[/]
[bold green]██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝ [/]
[bold green]██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗ [/]
[bold green]██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗[/]
[bold green]╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝[/]

[bold white]Reverse Analysis & Knowledge System for Heuristic APK Threats[/]
[dim]v{PLATFORM_VERSION} | {ORGANISATION}[/]
[bold red]⬛  SENSITIVE — DRDO CYBERSECURITY DIVISION[/]
"""

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH"    : "bold yellow",
    "MEDIUM"  : "bold blue",
    "LOW"     : "bold green",
    "CLEAN"   : "bold cyan",
}


def print_banner():
    console.print(Panel(BANNER, border_style="green", padding=(0, 2)))


def sev_text(sev: str) -> Text:
    return Text(sev, style=SEV_COLORS.get(sev, "white"))


# ══════════════════════════════════════════════════════════════════════════════
# ANALYZE COMMAND
# ══════════════════════════════════════════════════════════════════════════════
def cmd_analyze(args):
    print_banner()
    apk_path = Path(args.apk)

    if not apk_path.exists():
        console.print(f"[bold red]✗ File not found:[/] {apk_path}")
        sys.exit(1)

    if not apk_path.suffix.lower() == ".apk":
        console.print("[bold red]✗ File must be an .apk[/]")
        sys.exit(1)

    console.print(f"\n[bold green]◆ INITIATING ANALYSIS[/]  [white]{apk_path.name}[/]")
    console.print(f"[dim]Analyst: {args.analyst}  |  Output: {args.output}[/]\n")

    with Progress(
        SpinnerColumn(spinner_name="dots", style="green"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(style="green"),
        TimeElapsedColumn(),
        console=console,
    ) as prog:
        task = prog.add_task("Running RAKSHAK analysis pipeline...", total=None)
        pipeline = RakshakPipeline()
        result   = pipeline.analyze(
            apk_path     = str(apk_path),
            analyst_name = args.analyst,
        )
        prog.update(task, description="[bold green]Analysis complete ✓")

    _print_analysis_result(result)

    # Save to DB
    try:
        save_case(result)
        console.print("[dim green]✓ Case saved to RAKSHAK database[/]")
    except Exception as e:
        console.print(f"[dim yellow]! DB save error: {e}[/]")

    # Generate reports
    if args.output or args.pdf:
        out_dir = args.output or str(REPORT_DIR)
        Path(out_dir).mkdir(exist_ok=True)

        # JSON
        json_path = Path(out_dir) / f"RAKSHAK-{result['case_id']}-report.json"
        json_path.write_text(json.dumps(result, indent=2, default=str))
        console.print(f"[bold green]✓ JSON report:[/] {json_path}")

        # PDF
        try:
            pdf_path = generate_pdf_report(result, out_dir)
            console.print(f"[bold green]✓ PDF  report:[/] {pdf_path}")
        except Exception as e:
            console.print(f"[yellow]! PDF generation error: {e}[/]")

    console.print()


def _print_analysis_result(result: dict):
    rs  = result.get("risk_score", {})
    sum = result.get("summary", {})
    gen = result.get("genai_analysis", {})
    h   = result.get("hashes", {})

    score = rs.get("final_score", 0)
    sev   = rs.get("severity", "UNKNOWN")

    # ── Score banner ─────────────────────────────────────────────────────────
    score_color = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"blue","LOW":"green","CLEAN":"cyan"}.get(sev,"white")
    console.print(Rule(f"[bold {score_color}] RISK SCORE: {score}/100 — {sev} [/]", style=score_color))

    # ── APT alert ─────────────────────────────────────────────────────────────
    if rs.get("apt_detected") or rs.get("nation_state"):
        console.print(Panel(
            "[bold red]⚠ NATION-STATE / APT THREAT DETECTED\n[/]"
            "[white]Escalate immediately to DRDO NOC, CERT-In, and NTRO.\n"
            "Do NOT execute on live systems. Quarantine all related devices.[/]",
            border_style="red", title="[bold red]CRITICAL ALERT[/]"
        ))

    # ── Summary cards ─────────────────────────────────────────────────────────
    meta_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    meta_table.add_column("Key",   style="dim", width=22)
    meta_table.add_column("Value", style="white")
    rows = [
        ("Case ID",          result.get("case_id","")),
        ("APK Name",         result.get("apk_name","")),
        ("Package",          result.get("manifest",{}).get("package_name","—")),
        ("SHA-256",          h.get("sha256","")[:32] + "…"),
        ("File Size",        h.get("size_human","—")),
        ("Malware Family",   rs.get("primary_family","Unknown")),
        ("Threat Type",      gen.get("primary_threat_type","Unknown")),
        ("APT Detected",     "[bold red]YES[/]" if rs.get("apt_detected") else "[green]No[/]"),
        ("Nation-State",     "[bold red]YES[/]" if rs.get("nation_state") else "[green]No[/]"),
        ("Block Recommended","[bold red]YES[/]" if sum.get("block_now") else "[green]No[/]"),
        ("CERT-In Report",   "[bold red]REQUIRED[/]" if sum.get("cert_in_report") else "Not required"),
        ("Duration",         f"{result.get('duration_sec','—')}s"),
    ]
    for k, v in rows:
        meta_table.add_row(k, v)
    console.print(meta_table)

    # ── XAI Breakdown ─────────────────────────────────────────────────────────
    console.print(Rule("[bold green]XAI SCORE BREAKDOWN[/]", style="green"))
    bd = rs.get("breakdown", {})
    bar_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    bar_table.add_column("Dimension",   style="dim", width=22)
    bar_table.add_column("Raw",  justify="right", width=6)
    bar_table.add_column("Contrib", justify="right", width=8)
    bar_table.add_column("Bar", width=40)
    for dim, val in bd.items():
        raw   = val.get("raw_score", 0)
        c     = val.get("contribution", 0)
        bar_w = int(raw / 100 * 38)
        bar   = f"[green]{'█' * bar_w}{'░' * (38-bar_w)}[/]"
        bar_table.add_row(dim.replace("_"," ").title(), f"{raw:.0f}", f"+{c:.2f}", bar)
    console.print(bar_table)

    # ── Key Findings ─────────────────────────────────────────────────────────
    console.print(Rule("[bold yellow]KEY FINDINGS[/]", style="yellow"))
    findings_table = Table(box=box.SIMPLE, show_header=True, padding=(0,2))
    findings_table.add_column("Engine",   width=18, style="dim")
    findings_table.add_column("Count",    width=8,  justify="right")
    findings_table.add_column("Status",   width=14)
    findings_table.add_column("Top Finding", width=60)

    sa  = result.get("static_analysis",{})
    ya  = result.get("yara_analysis",{})
    str_= result.get("strings",{})

    crit_apis = sa.get("api_analysis",{}).get("critical_apis",[])
    findings_table.add_row("Dangerous APIs", str(len(sa.get("api_analysis",{}).get("findings",[]))),
                            "[red]CRITICAL[/]" if crit_apis else "[green]CLEAN[/]",
                            crit_apis[0] if crit_apis else "None")
    v = sa.get("vulnerabilities",{})
    findings_table.add_row("Vulnerabilities", str(v.get("total_vulnerabilities",0)),
                            "[red]HIGH[/]" if v.get("critical_count",0) else "[green]LOW[/]",
                            v.get("findings",[{}])[0].get("name","None") if v.get("findings") else "None")
    families = ya.get("malware_families",[])
    findings_table.add_row("YARA Families", str(len(families)),
                            "[red]MATCHED[/]" if families else "[green]CLEAN[/]",
                            ", ".join(families[:2]) if families else "None")
    c2s = str_.get("ips",[])
    findings_table.add_row("C2 Indicators", str(len(c2s) + len(str_.get("urls",[]))),
                            "[red]DETECTED[/]" if c2s else "[green]CLEAN[/]",
                            c2s[0].get("ip","") if c2s else "None")
    bt = sa.get("banking_threats",{})
    findings_table.add_row("Banking Threats", str(bt.get("banking_risk_score",0)) + "/100",
                            "[red]DETECTED[/]" if bt.get("otp_harvesting") else "[green]CLEAN[/]",
                            "OTP harvesting" if bt.get("otp_harvesting") else "None detected")
    console.print(findings_table)

    # ── GenAI Summary ─────────────────────────────────────────────────────────
    if gen.get("malicious_intent_summary"):
        console.print(Rule("[bold cyan]AI THREAT ASSESSMENT[/]", style="cyan"))
        console.print(Panel(
            gen["malicious_intent_summary"],
            title=f"[bold cyan]{gen.get('primary_threat_type','Unknown')}[/] — Confidence: {gen.get('intelligence_confidence','')}",
            border_style="cyan"
        ))

    # ── MITRE ─────────────────────────────────────────────────────────────────
    mitre = rs.get("mitre_techniques",[])
    if mitre:
        console.print(Rule("[bold purple]MITRE ATT&CK MOBILE[/]", style="purple"))
        ids = [f"[purple]{t['id']}[/] {t['name']}" for t in mitre]
        for i in ids:
            console.print(f"  • {i}")

    # ── Immediate Actions ─────────────────────────────────────────────────────
    actions = gen.get("immediate_actions",[])
    if actions:
        console.print(Rule("[bold red]IMMEDIATE ACTIONS[/]", style="red"))
        for i, a in enumerate(actions, 1):
            console.print(f"  [bold red]{i}.[/] {a}")
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
# OTHER COMMANDS
# ══════════════════════════════════════════════════════════════════════════════
def cmd_list(args):
    print_banner()
    cases = list_cases(limit=args.limit)
    if not cases:
        console.print("[dim]No cases in database.[/]")
        return
    t = Table(box=box.ROUNDED, border_style="green", title="RAKSHAK Case Database")
    t.add_column("Case ID",   style="dim", width=26)
    t.add_column("APK Name",  width=28)
    t.add_column("Score",     justify="right", width=7)
    t.add_column("Severity",  width=10)
    t.add_column("Family",    width=20)
    t.add_column("APT",       width=5, justify="center")
    t.add_column("Date",      width=12)
    for c in cases:
        sev = c.get("severity","—")
        t.add_row(
            c.get("case_id",""),
            (c.get("apk_name","") or "")[:27],
            str(c.get("risk_score","—")),
            Text(sev, style=SEV_COLORS.get(sev,"white")),
            (c.get("primary_family","—") or "")[:20],
            "⚠" if c.get("apt_detected") else "—",
            (c.get("submitted_at","") or "")[:10],
        )
    console.print(t)


def cmd_search(args):
    print_banner()
    console.print(f"[bold green]Searching IOC:[/] {args.ioc}\n")
    results = search_ioc(args.ioc)
    if not results:
        console.print("[dim]No matches found in database.[/]")
        return
    t = Table(box=box.ROUNDED, border_style="green", title=f"IOC Search: {args.ioc}")
    t.add_column("Case ID", width=26)
    t.add_column("Type",    width=10)
    t.add_column("Value",   width=40)
    t.add_column("Risk",    width=10)
    t.add_column("APK",     width=28)
    t.add_column("Score",   width=7, justify="right")
    for r in results:
        t.add_row(r.get("case_id",""), r.get("ioc_type",""),
                  (r.get("value","") or "")[:40],
                  r.get("risk",""), (r.get("apk_name","") or "")[:28],
                  str(r.get("risk_score","")))
    console.print(t)


def cmd_stats(args):
    print_banner()
    stats = get_stats()
    console.print(Panel(
        f"[bold white]Total Cases:[/]    [green]{stats['total_cases']}[/]\n"
        f"[bold white]Critical Cases:[/] [red]{stats['critical_cases']}[/]\n"
        f"[bold white]APT Cases:[/]      [red]{stats['apt_cases']}[/]\n"
        f"[bold white]Total IOCs:[/]     [blue]{stats['total_iocs']}[/]",
        title="[bold green]RAKSHAK Platform Statistics[/]",
        border_style="green"
    ))


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        prog="rakshak",
        description="RAKSHAK — DRDO APK Threat Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze an APK file")
    p_analyze.add_argument("apk",       help="Path to .apk file")
    p_analyze.add_argument("--analyst", default="DRDO-ANALYST", help="Analyst name/ID")
    p_analyze.add_argument("--output",  default="", help="Output directory for reports")
    p_analyze.add_argument("--pdf",     action="store_true", help="Generate PDF report")
    p_analyze.set_defaults(func=cmd_analyze)

    # list
    p_list = sub.add_parser("list", help="List all analyzed cases")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.set_defaults(func=cmd_list)

    # search
    p_search = sub.add_parser("search", help="Search IOC across all cases")
    p_search.add_argument("ioc", help="IP/domain/URL to search")
    p_search.set_defaults(func=cmd_search)

    # stats
    p_stats = sub.add_parser("stats", help="Platform statistics")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    if not args.command:
        print_banner()
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
