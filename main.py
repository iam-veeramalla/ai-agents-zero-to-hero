#!/usr/bin/env python3
"""Kubernetes Log Investigation Agent CLI.

Allows running investigations on Kubernetes logs from files, stdin, or raw text,
outputting visually stunning terminal reports, markdown, or JSON with supporting evidence.
"""

import argparse
import json
import sys
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from app.k8s_forensics import LogAnalyzer, SeverityLevel


console = Console()


def render_terminal_report(report) -> None:
    """Renders a beautiful, modern terminal investigation report."""
    # 1. Header Banner with Severity Badge
    severity_badges = {
        SeverityLevel.CRITICAL: ("🔴 CRITICAL", "bold white on red"),
        SeverityLevel.HIGH: ("🟠 HIGH", "bold white on dark_orange"),
        SeverityLevel.MEDIUM: ("🟡 MEDIUM", "bold black on yellow"),
        SeverityLevel.LOW: ("🔵 LOW", "bold white on blue"),
        SeverityLevel.INFO: ("🟢 HEALTHY", "bold white on green"),
    }
    sev_text, sev_style = severity_badges.get(
        report.severity, (report.severity.value, "bold white on blue")
    )

    header_table = Table.grid(expand=True)
    header_table.add_column(ratio=3)
    header_table.add_column(ratio=2, justify="right")
    header_table.add_row(
        Text("🔍 Kubernetes Incident Investigation", style="bold bright_cyan"),
        Text.assemble(
            ("Status: ", "bold bright_black"),
            (f"{report.status}  ", "bold yellow"),
            ("Severity: ", "bold bright_black"),
            (f" {sev_text} ", sev_style),
        ),
    )

    console.print()
    console.print(
        Panel(
            header_table,
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )

    # 2. Key Metrics Tiles
    m = report.metadata
    metrics = [
        Panel(
            f"[bold cyan]{m.get('total_lines', 0)}[/bold cyan]\n[dim]Lines Ingested[/dim]",
            border_style="dim cyan",
            box=box.ROUNDED,
        ),
        Panel(
            f"[bold red]{m.get('error_count', 0)}[/bold red]\n[dim]Errors Detected[/dim]",
            border_style="dim red",
            box=box.ROUNDED,
        ),
        Panel(
            f"[bold yellow]{m.get('warning_count', 0)}[/bold yellow]\n[dim]Warnings Logged[/dim]",
            border_style="dim yellow",
            box=box.ROUNDED,
        ),
        Panel(
            f"[bold magenta]{m.get('evidence_count', 0)}[/bold magenta]\n[dim]Evidence Items[/dim]",
            border_style="dim magenta",
            box=box.ROUNDED,
        ),
    ]
    console.print(Columns(metrics, equal=True))
    console.print()

    # 3. Executive Summary
    summary_text = Text(report.summary, style="white")
    console.print(
        Panel(
            summary_text,
            title="[bold cyan]📋 Executive Incident Summary[/bold cyan]",
            title_align="left",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )
    console.print()

    # 4. Root Cause Analysis
    if report.root_causes:
        rc_table = Table(
            title="🚨 Root Cause Diagnosis",
            title_style="bold yellow",
            border_style="yellow",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        rc_table.add_column("#", style="dim", width=3)
        rc_table.add_column("Diagnosis Title", style="bold bright_white", width=36)
        rc_table.add_column("Confidence", style="bold green", justify="center", width=12)
        rc_table.add_column("Technical Findings & Contributing Factors", style="white")

        for idx, rc in enumerate(report.root_causes, start=1):
            details = f"{rc.summary}"
            if rc.technical_details:
                details += f"\n[dim italic]{rc.technical_details}[/dim italic]"
            rc_table.add_row(
                str(idx),
                rc.title,
                f"{int(rc.confidence * 100)}%",
                details,
            )
        console.print(rc_table)
        console.print()

    # 5. Supporting Evidence Table
    if report.evidence:
        ev_table = Table(
            title="🔎 Supporting Evidence (Exact Line & Signal Verification)",
            title_style="bold magenta",
            border_style="magenta",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold bright_magenta",
            expand=True,
        )
        ev_table.add_column("ID", style="bold cyan", width=8)
        ev_table.add_column("Line", style="yellow", justify="right", width=6)
        ev_table.add_column("Timestamp", style="dim", width=22)
        ev_table.add_column("Signal & Forensic Meaning", style="white", width=34)
        ev_table.add_column("Extracted Log Excerpt", style="green")

        for ev in report.evidence:
            ev_table.add_row(
                ev.id,
                f"L{ev.line_number}",
                ev.timestamp or "N/A",
                f"[bold bright_white]{ev.signal_name}[/bold bright_white]\n[dim]{ev.explanation}[/dim]",
                ev.log_excerpt,
            )
        console.print(ev_table)
        console.print()

    # 6. Chronological Incident Timeline
    if report.timeline:
        tl_table = Table(
            title="⏱️ Chronological Incident Progression",
            title_style="bold blue",
            border_style="blue",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold bright_blue",
            expand=True,
        )
        tl_table.add_column("Phase", style="bold", width=22)
        tl_table.add_column("Line", style="yellow", width=6)
        tl_table.add_column("Timestamp", style="dim", width=22)
        tl_table.add_column("Event & Log Landmark", style="white")

        phase_icons = {
            "Baseline Operation": "🟢 [bright_green]Baseline Operation[/bright_green]",
            "Initial Warning": "🟡 [bright_yellow]Early Warning[/bright_yellow]",
            "Incident Onset": "🔴 [bright_red]Incident Onset[/bright_red]",
            "Termination / Crash": "💥 [bold red]Termination / Crash[/bold red]",
        }

        for event in report.timeline:
            styled_phase = phase_icons.get(event.phase, f"🔹 {event.phase}")
            tl_table.add_row(
                styled_phase,
                f"L{event.line_number}",
                event.timestamp or "N/A",
                f"[bold]{event.description}[/bold]\n[dim italic]\"{event.log_excerpt}\"[/dim italic]",
            )
        console.print(tl_table)
        console.print()

    # 7. Actionable Remediation Plan
    if report.remediation_steps:
        console.print("[bold green]🛠️ Actionable Remediation & Prevention Plan[/bold green]\n")
        for step in report.remediation_steps:
            type_styles = {
                "immediate": ("[⚡ IMMEDIATE MITIGATION]", "bold white on dark_red"),
                "investigative": ("[🔍 INVESTIGATIVE ACTION]", "bold black on dark_orange"),
                "permanent_fix": ("[🛡️ PERMANENT FIX]", "bold white on dark_green"),
            }
            badge_text, badge_style = type_styles.get(
                step.type.lower(), (f"[{step.type.upper()}]", "bold white on blue")
            )

            step_header = Text.assemble(
                (f"{step.order}. ", "bold bright_white"),
                (f" {badge_text} ", badge_style),
                (f" {step.action}", "bold bright_white"),
            )
            console.print(step_header)
            console.print(f"   [dim]Rationale: {step.rationale}[/dim]")

            if step.command_or_yaml:
                is_yaml = "resources:" in step.command_or_yaml or "env:" in step.command_or_yaml or "apiVersion:" in step.command_or_yaml
                lang = "yaml" if is_yaml else "bash"
                syntax = Syntax(
                    step.command_or_yaml,
                    lang,
                    theme="monokai",
                    line_numbers=False,
                    padding=(0, 1),
                )
                console.print(
                    Panel(
                        syntax,
                        title=f"[dim cyan]Recommended {lang.upper()}[/dim cyan]",
                        title_align="left",
                        border_style="dim bright_black",
                        box=box.ROUNDED,
                    )
                )
            console.print()

    # 8. Footer Info
    time_info = report.metadata.get("time_range", {})
    t_start = time_info.get("start") or "N/A"
    t_end = time_info.get("end") or "N/A"
    console.print(
        f"[dim]Time Range: {t_start} ➔ {t_end} | "
        f"Investigation Engine: Google ADK / k8s_investigator[/dim]\n"
    )


def render_markdown_report(report) -> str:
    """Generates a beautifully formatted Github-flavored Markdown report."""
    md = []
    severity_emojis = {
        SeverityLevel.CRITICAL: "🔴",
        SeverityLevel.HIGH: "🟠",
        SeverityLevel.MEDIUM: "🟡",
        SeverityLevel.LOW: "🔵",
        SeverityLevel.INFO: "🟢",
    }
    sev_emoji = severity_emojis.get(report.severity, "🔍")

    md.append(f"# {sev_emoji} {report.title}\n")
    md.append(
        f"> **Severity**: `{report.severity.value}` | "
        f"**Status**: `{report.status}` | "
        f"**Analyzed Entries**: `{report.metadata.get('parsed_entries', 0)}`\n"
    )
    md.append("## 📋 Executive Summary\n")
    md.append(f"{report.summary}\n")

    if report.root_causes:
        md.append("## 🚨 Root Cause Diagnosis\n")
        for idx, rc in enumerate(report.root_causes, start=1):
            md.append(f"### {idx}. {rc.title} (`Confidence: {int(rc.confidence * 100)}%`)\n")
            md.append(f"{rc.summary}\n")
            if rc.technical_details:
                md.append(f"> **Technical Detail**: {rc.technical_details}\n")

    if report.evidence:
        md.append("## 🔎 Supporting Evidence\n")
        md.append("| Evidence ID | Line # | Timestamp | Diagnostic Signal & Context | Extracted Log Excerpt |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for ev in report.evidence:
            clean_excerpt = ev.log_excerpt.replace("\n", " ").replace("|", "\\|")
            md.append(
                f"| **`{ev.id}`** | Line {ev.line_number} | `{ev.timestamp or 'N/A'}` | "
                f"**{ev.signal_name}**<br>*{ev.explanation}* | `{clean_excerpt}` |"
            )
        md.append("")

    if report.timeline:
        md.append("## ⏱️ Chronological Incident Timeline\n")
        md.append("| Phase | Line # | Timestamp | Milestone Landmark |")
        md.append("| :--- | :--- | :--- | :--- |")
        for event in report.timeline:
            md.append(
                f"| **{event.phase}** | Line {event.line_number} | `{event.timestamp or 'N/A'}` | "
                f"{event.description}<br>`{event.log_excerpt}` |"
            )
        md.append("")

    if report.remediation_steps:
        md.append("## 🛠️ Actionable Remediation Plan\n")
        for step in report.remediation_steps:
            md.append(f"### {step.order}. [{step.type.upper()}] {step.action}\n")
            md.append(f"*{step.rationale}*\n")
            if step.command_or_yaml:
                is_yaml = "resources:" in step.command_or_yaml or "env:" in step.command_or_yaml or "apiVersion:" in step.command_or_yaml
                lang = "yaml" if is_yaml else "bash"
                md.append(f"```{lang}\n{step.command_or_yaml}\n```\n")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes Log Investigation Agent CLI"
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to log file to investigate",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to specified output file",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        help="Output report format (default: terminal)",
    )
    parser.add_argument(
        "--max-evidence",
        type=int,
        default=12,
        help="Maximum evidence items to extract (default: 12)",
    )

    args = parser.parse_args()

    # Read logs from file, stdin, or prompt
    logs_content = ""
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                logs_content = f.read()
        except Exception as e:
            console.print(f"[bold red]Error reading file {args.file}:[/bold red] {e}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        logs_content = sys.stdin.read()
    else:
        console.print("[bold yellow]No log file or piped input provided.[/bold yellow]")
        console.print("Usage:")
        console.print("  uv run python main.py -f <log_file>")
        console.print("  cat <log_file> | uv run python main.py")
        console.print("  agents-cli run \"Investigate log file <path>\"")
        sys.exit(1)

    if not logs_content.strip():
        console.print("[bold red]Input logs are empty.[/bold red]")
        sys.exit(1)

    analyzer = LogAnalyzer()
    report = analyzer.analyze(logs_content, max_evidence_items=args.max_evidence)

    # Output formatting
    if args.format == "json":
        output_str = json.dumps(report.model_dump(), indent=2)
        if args.output:
            with open(args.output, "w") as out:
                out.write(output_str)
            console.print(f"[green]Saved JSON report to {args.output}[/green]")
        else:
            print(output_str)
    elif args.format == "markdown":
        output_str = render_markdown_report(report)
        if args.output:
            with open(args.output, "w") as out:
                out.write(output_str)
            console.print(f"[green]Saved Markdown report to {args.output}[/green]")
        else:
            print(output_str)
    else:
        render_terminal_report(report)
        if args.output:
            md_content = render_markdown_report(report)
            with open(args.output, "w") as out:
                out.write(md_content)
            console.print(f"[green]Saved Markdown copy to {args.output}[/green]")


if __name__ == "__main__":
    main()
