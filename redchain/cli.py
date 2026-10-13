from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redchain.engine.orchestrator import AttackOrchestrator
from redchain.models.attack_config import AttackConfig, TargetConfig
from redchain.reporter.json_reporter import JSONReporter

app = typer.Typer(
    name="redchain",
    help="🔴 RedChain — Autonomous Multi-Turn Red-Teaming for AI Agents",
    no_args_is_help=True,
)
console = Console()


def _parse_list(items: list[str] | None) -> list[str]:
    """Split comma-separated values and flatten list of options."""
    if not items:
        return []
    result = []
    for item in items:
        for part in item.split(","):
            part = part.strip()
            if part:
                result.append(part)
    return result


@app.command()
def run(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target agent base URL (e.g. http://localhost:8001)",
    ),
    strategies: list[str] = typer.Option(
        ["direct_hijack"],
        "--strategy",
        "-s",
        help="Attack strategies to run (can pass multiple or comma-separated)",
    ),
    max_turns: int = typer.Option(
        4,
        "--max-turns",
        "-m",
        min=1,
        max=20,
        help="Maximum turns per attack strategy",
    ),
    forbidden_tools: list[str] = typer.Option(
        [],
        "--forbidden-tools",
        "-f",
        help="Sensitive tools that must not be invoked (e.g. send_email)",
    ),
    secret_markers: list[str] = typer.Option(
        [],
        "--secret-markers",
        help="Strings that indicate a prompt leak (e.g. SYSTEM:)",
    ),
    attacker_llm: str = typer.Option(
        "claude-3-5-sonnet-20241022",
        "--attacker-llm",
        help="Model for dynamic attacker planner",
    ),
    judge_llm: str = typer.Option(
        "gemini/gemini-1.5-pro",
        "--judge-llm",
        help="Model for evaluation judge scorer",
    ),
    desc: Optional[str] = typer.Option(
        None,
        "--desc",
        help="Description of what the target agent is supposed to do",
    ),
    reports_dir: Optional[str] = typer.Option(
        None,
        "--reports-dir",
        "-d",
        help="Custom directory to store audit reports",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output raw JSON report to stdout (ideal for CI/CD)",
    ),
) -> None:
    """
    Launch an automated multi-turn red-team assessment against a target AI agent.
    """
    parsed_strategies = _parse_list(strategies) or ["direct_hijack"]
    parsed_forbidden = _parse_list(forbidden_tools)
    parsed_markers = _parse_list(secret_markers)

    target_config = TargetConfig(url=target)
    attack_config = AttackConfig(
        target=target_config,
        strategies=parsed_strategies,
        max_turns=max_turns,
        attacker_llm=attacker_llm,
        judge_llm=judge_llm,
        forbidden_tools=parsed_forbidden,
        secret_markers=parsed_markers,
        target_description=desc,
    )

    orchestrator = AttackOrchestrator(attack_config)
    report = asyncio.run(orchestrator.run())

    # Optional custom directory save
    if reports_dir:
        custom_reporter = JSONReporter(reports_dir=reports_dir)
        custom_reporter.save(report)

    if json_output:
        print(report.model_dump_json(indent=2))

    # Exit with code 1 if exploited (CI/CD security gate)
    if report.status == "EXPLOITED":
        raise typer.Exit(code=1)


@app.command(name="list")
def list_reports(
    reports_dir: Optional[str] = typer.Option(
        None,
        "--reports-dir",
        "-d",
        help="Directory where reports are stored",
    ),
) -> None:
    """
    List all previous RedChain audit reports.
    """
    reporter = JSONReporter(reports_dir=reports_dir)
    reports = reporter.list_all()

    if not reports:
        console.print("[dim]No audit reports found.[/dim]")
        return

    table = Table(title="🔴 RedChain Audit Reports", header_style="bold cyan")
    table.add_column("Session ID", style="bold white")
    table.add_column("Date", style="dim")
    table.add_column("Target", style="blue")
    table.add_column("Status")
    table.add_column("Turns", justify="right")
    table.add_column("OWASP Findings", style="red")
    table.add_column("Duration", justify="right")

    for r in reports:
        status_color = (
            "bold red"
            if r.status == "EXPLOITED"
            else "bold yellow"
            if r.status == "PARTIAL"
            else "bold green"
        )
        status_str = f"[{status_color}]{r.status}[/{status_color}]"
        date_str = r.created_at.strftime("%Y-%m-%d %H:%M")
        findings_str = ", ".join(r.owasp_findings) if r.owasp_findings else "-"

        table.add_row(
            r.session_id[:8],
            date_str,
            r.config.target.url,
            status_str,
            str(len(r.turns)),
            findings_str,
            f"{r.duration_seconds:.1f}s",
        )

    console.print(table)


@app.command()
def show(
    session_id: str = typer.Argument(
        ...,
        help="Session ID or 8-character prefix (e.g. 2ff3c134)",
    ),
    reports_dir: Optional[str] = typer.Option(
        None,
        "--reports-dir",
        "-d",
        help="Directory where reports are stored",
    ),
    turns: bool = typer.Option(
        True,
        "--turns/--no-turns",
        help="Show turn-by-turn trace details",
    ),
) -> None:
    """
    Inspect a specific audit report in detail.
    """
    reporter = JSONReporter(reports_dir=reports_dir)
    try:
        report = reporter.load(session_id)
    except FileNotFoundError as err:
        console.print(f"[bold red]Error:[/bold red] {err}")
        raise typer.Exit(code=1)

    color = (
        "red"
        if report.status == "EXPLOITED"
        else "yellow"
        if report.status == "PARTIAL"
        else "green"
    )

    summary_text = (
        f"[bold]Session ID:[/bold]     {report.session_id}\n"
        f"[bold]Target URL:[/bold]     {report.config.target.url}\n"
        f"[bold]Verdict:[/bold]        [{color}]{report.status}[/{color}]\n"
        f"[bold]Date:[/bold]           {report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"[bold]Duration:[/bold]       {report.duration_seconds:.2f}s\n"
        f"[bold]OWASP Findings:[/bold] {', '.join(report.owasp_findings) or 'None'}"
    )

    console.print(
        Panel(summary_text, title="Audit Report Summary", border_style=color)
    )

    # Show Exploit Evidence if available
    if report.exploit_evidence:
        ev = report.exploit_evidence
        ev_lines = []
        if ev.forbidden_tool_called:
            ev_lines.append(f"• Forbidden Tool:  [bold red]{ev.forbidden_tool_called}[/bold red]")
        if ev.forbidden_tool_params:
            ev_lines.append(f"• Parameters:      {ev.forbidden_tool_params}")
        if ev.matched_secret_marker:
            ev_lines.append(f"• Secret Marker:   {ev.matched_secret_marker}")
        if ev.leaked_text_snippet:
            ev_lines.append(f"• Leaked Snippet:  {ev.leaked_text_snippet}")

        if ev_lines:
            console.print(
                Panel(
                    "\n".join(ev_lines),
                    title="🚨 Exploit Evidence",
                    border_style="red",
                )
            )


    # Recommendations
    if report.recommendations:
        rec_lines = [f"• {rec}" for rec in report.recommendations]
        console.print(
            Panel(
                "\n".join(rec_lines),
                title="🛡️ Remediation Advice",
                border_style="cyan",
            )
        )

    # Turn-by-Turn Trace Table
    if turns and report.turns:
        table = Table(
            title=f"Turn-by-Turn Trace ({len(report.turns)} turns)",
            header_style="bold magenta",
        )
        table.add_column("Turn", justify="right")
        table.add_column("Strategy")
        table.add_column("Payload")
        table.add_column("Response")
        table.add_column("Score")
        table.add_column("OWASP")

        for t in report.turns:
            p_snippet = (
                t.payload[:40] + "..." if len(t.payload) > 40 else t.payload
            )
            r_snippet = (
                t.response.text[:40] + "..."
                if len(t.response.text) > 40
                else t.response.text
            )
            score_str = f"{t.score.confidence * 100:.0f}%"
            if t.score.is_exploit:
                score_str = f"[bold red]{score_str} (EXPLOIT)[/bold red]"
            owasp_str = t.score.owasp_id or "-"

            table.add_row(
                str(t.turn_number),
                t.strategy,
                p_snippet,
                r_snippet,
                score_str,
                owasp_str,
            )

        console.print(table)


@app.command()
def version() -> None:
    """
    Display RedChain version information.
    """
    console.print("[bold red]🔴 RedChain[/bold red] [dim]v0.1.0[/dim]")
    console.print("Autonomous multi-turn red-teaming engine for AI agents")