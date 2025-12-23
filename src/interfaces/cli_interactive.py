"""Interactive CLI interface for BlueGuardian AI.

This module provides a rich, interactive command-line interface for security analysts
to perform malware analysis and threat intelligence operations.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from src.agents.base_agent import AnalysisResult, Verdict
from src.config.settings import get_settings
from src.core.orchestrator import Orchestrator

# Initialize Typer app and Rich console
app = typer.Typer(
    name="blueguardian",
    help="BlueGuardian AI - Advanced Blue Team Security Analysis Framework",
    add_completion=False,
)
console = Console()


class BlueGuardianCLI:
    """Interactive CLI session manager."""

    def __init__(self):
        """Initialize CLI session."""
        self.orchestrator: Optional[Orchestrator] = None
        self.current_file: Optional[str] = None
        self.last_result: Optional[AnalysisResult] = None

        # Setup logging
        logger.remove()
        logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            level="INFO",
        )

    async def initialize(self):
        """Initialize orchestrator."""
        console.print("\n[bold blue]BlueGuardian AI[/bold blue]", justify="center")
        console.print("[dim]Advanced Blue Team Security Analysis Framework[/dim]\n", justify="center")

        with console.status("[bold green]Initializing components..."):
            try:
                settings = get_settings()
                self.orchestrator = Orchestrator(settings)

                # Check API keys
                api_keys = settings.validate_api_keys()
                configured = [k for k, v in api_keys.items() if v]

                if not configured:
                    console.print("[yellow]⚠ Warning: No AI providers configured[/yellow]")
                    console.print("[dim]Please configure API keys in .env file[/dim]")
                    return False

                console.print(f"[green]✓[/green] Initialized with: {', '.join(configured)}")
                return True

            except Exception as e:
                console.print(f"[red]✗ Initialization failed: {e}[/red]")
                return False

    async def load_file(self, file_path: str):
        """Load a file for analysis."""
        path = Path(file_path)

        if not path.exists():
            console.print(f"[red]✗ File not found: {file_path}[/red]")
            return

        self.current_file = str(path.absolute())
        file_size = path.stat().st_size

        console.print(f"[green]✓[/green] Loaded: {path.name} ({file_size:,} bytes)")
        console.print(f"[dim]Path: {self.current_file}[/dim]")

    async def analyze(self, agent_type: Optional[str] = None):
        """Analyze the currently loaded file."""
        if not self.current_file:
            console.print("[yellow]No file loaded. Use 'load <path>' first.[/yellow]")
            return

        if not self.orchestrator:
            console.print("[red]Orchestrator not initialized[/red]")
            return

        console.print(f"\n[bold]Analyzing: {Path(self.current_file).name}[/bold]")

        try:
            with console.status("[bold green]Running analysis..."):
                result = await self.orchestrator.analyze_file(
                    self.current_file,
                    agent_type=agent_type,
                )

            self.last_result = result
            self._display_result(result)

        except Exception as e:
            console.print(f"[red]✗ Analysis failed: {e}[/red]")
            logger.error(f"Analysis error: {e}", exc_info=True)

    def _display_result(self, result: AnalysisResult):
        """Display analysis results in rich format."""
        # Verdict panel
        verdict_color = {
            Verdict.MALICIOUS: "red",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.CLEAN: "green",
            Verdict.UNKNOWN: "dim",
        }

        color = verdict_color.get(result.verdict, "white")

        verdict_panel = Panel(
            f"[{color}]{result.verdict.value.upper()}[/{color}]\n"
            f"Confidence: {result.confidence:.0%}\n"
            f"Duration: {result.duration_seconds:.1f}s",
            title="[bold]Analysis Result[/bold]",
            border_style=color,
        )

        console.print(verdict_panel)

        # Summary
        if result.summary:
            console.print("\n[bold]Summary:[/bold]")
            console.print(result.summary[:500])  # Truncate if too long

        # IOCs
        if result.iocs:
            console.print(f"\n[bold]Indicators of Compromise ({len(result.iocs)}):[/bold]")

            ioc_table = Table(show_header=True)
            ioc_table.add_column("Type")
            ioc_table.add_column("Value")
            ioc_table.add_column("Confidence")

            for ioc in result.iocs[:10]:  # Show top 10
                ioc_table.add_row(
                    ioc.type,
                    ioc.value[:50],  # Truncate long values
                    f"{ioc.confidence:.0%}",
                )

            console.print(ioc_table)

            if len(result.iocs) > 10:
                console.print(f"[dim]... and {len(result.iocs) - 10} more[/dim]")

        # MITRE ATT&CK
        if result.mitre_techniques:
            console.print(f"\n[bold]MITRE ATT&CK Techniques:[/bold]")
            console.print(", ".join(result.mitre_techniques))

        # Tags
        if result.tags:
            console.print(f"\n[bold]Tags:[/bold] {', '.join(result.tags)}")

        # Warnings/Errors
        if result.warnings:
            console.print(f"\n[yellow]⚠ Warnings ({len(result.warnings)}):[/yellow]")
            for warning in result.warnings[:5]:
                console.print(f"  • {warning}")

        if result.errors:
            console.print(f"\n[red]✗ Errors ({len(result.errors)}):[/red]")
            for error in result.errors[:5]:
                console.print(f"  • {error}")

    async def export_report(self, output_path: str):
        """Export last analysis result to file."""
        if not self.last_result:
            console.print("[yellow]No analysis results to export[/yellow]")
            return

        try:
            path = Path(output_path)

            if path.suffix == '.json':
                # JSON export
                with open(path, 'w') as f:
                    json.dump(self.last_result.to_dict(), f, indent=2)

                console.print(f"[green]✓[/green] Report exported to: {path}")

            else:
                console.print("[yellow]Only JSON export supported currently[/yellow]")

        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")

    def show_status(self):
        """Show system status."""
        if not self.orchestrator:
            console.print("[red]Orchestrator not initialized[/red]")
            return

        status = self.orchestrator.get_status()

        # Create status table
        table = Table(title="[bold]System Status[/bold]", show_header=False)
        table.add_column("Component", style="cyan")
        table.add_column("Status")

        # AI Providers
        providers = status['providers']
        table.add_row(
            "AI Providers",
            f"{providers['count']} configured: {', '.join(providers['models'])}"
        )

        # Consensus
        consensus = status['consensus']
        table.add_row(
            "Consensus",
            f"{'Enabled' if consensus['enabled'] else 'Disabled'} "
            f"({consensus['providers']} providers)"
        )

        # Hallucination Guard
        table.add_row(
            "Hallucination Guard",
            "Enabled" if status['hallucination_guard']['enabled'] else "Disabled"
        )

        # Threat Intel
        ti = status['threat_intel']
        table.add_row(
            "Threat Intelligence",
            f"VT: {'✓' if ti['virustotal'] else '✗'}"
        )

        # Agents
        agents = status['agents']
        table.add_row(
            "Agents",
            f"{agents['count']} available: {', '.join(agents['available'])}"
        )

        console.print(table)

        # Show costs
        costs = self.orchestrator.get_costs()
        if costs['total'] > 0:
            console.print(f"\n[bold]Total API Cost:[/bold] ${costs['total']:.4f}")


# CLI commands

@app.command()
def interactive():
    """Start interactive analysis session."""
    async def run():
        cli = BlueGuardianCLI()

        if not await cli.initialize():
            console.print("[red]Failed to initialize. Please check configuration.[/red]")
            return

        console.print("\n[dim]Type 'help' for available commands or 'exit' to quit.[/dim]\n")

        while True:
            try:
                command = console.input("[bold blue]blueguardian>[/bold blue] ")
                parts = command.strip().split()

                if not parts:
                    continue

                cmd = parts[0].lower()

                if cmd in ['exit', 'quit', 'q']:
                    console.print("[dim]Shutting down...[/dim]")
                    await cli.orchestrator.shutdown()
                    break

                elif cmd == 'help':
                    console.print("[bold]Available Commands:[/bold]")
                    console.print("  load <path>      - Load a file for analysis")
                    console.print("  analyze          - Analyze loaded file")
                    console.print("  export <path>    - Export results to JSON")
                    console.print("  status           - Show system status")
                    console.print("  help             - Show this help")
                    console.print("  exit             - Exit the program")

                elif cmd == 'load':
                    if len(parts) < 2:
                        console.print("[yellow]Usage: load <file_path>[/yellow]")
                    else:
                        await cli.load_file(' '.join(parts[1:]))

                elif cmd == 'analyze':
                    await cli.analyze()

                elif cmd == 'export':
                    if len(parts) < 2:
                        console.print("[yellow]Usage: export <output_path>[/yellow]")
                    else:
                        await cli.export_report(parts[1])

                elif cmd == 'status':
                    cli.show_status()

                else:
                    console.print(f"[yellow]Unknown command: {cmd}[/yellow]")
                    console.print("[dim]Type 'help' for available commands[/dim]")

            except KeyboardInterrupt:
                console.print("\n[dim]Use 'exit' to quit[/dim]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    asyncio.run(run())


@app.command()
def analyze_file(
    file_path: str = typer.Argument(..., help="Path to file to analyze"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output report path"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent type to use"),
):
    """Analyze a single file (non-interactive mode)."""
    async def run():
        cli = BlueGuardianCLI()

        if not await cli.initialize():
            raise typer.Exit(1)

        await cli.load_file(file_path)
        await cli.analyze(agent_type=agent)

        if output and cli.last_result:
            await cli.export_report(output)

    asyncio.run(run())


@app.command()
def status():
    """Show system status and configuration."""
    async def run():
        cli = BlueGuardianCLI()

        if not await cli.initialize():
            raise typer.Exit(1)

        cli.show_status()

    asyncio.run(run())


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
