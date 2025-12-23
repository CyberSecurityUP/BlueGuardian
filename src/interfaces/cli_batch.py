"""Batch mode CLI for BlueGuardian AI.

This module provides a non-interactive batch processing CLI for analyzing
multiple files and generating reports automatically.
"""

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

import typer
from loguru import logger
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from src.config.settings import Settings, get_settings
from src.core.orchestrator import Orchestrator
from src.utils.report_generator import ReportGenerator

app = typer.Typer(help="BlueGuardian AI - Batch Analysis Mode")
console = Console()


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Setup logging configuration.

    Args:
        verbose: Enable verbose logging
        log_file: Optional log file path
    """
    logger.remove()

    # Console logging
    if verbose:
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level="DEBUG",
        )
    else:
        logger.add(sys.stderr, format="<level>{message}</level>", level="INFO")

    # File logging
    if log_file:
        logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
            level="DEBUG",
            rotation="10 MB",
        )


@app.command()
def analyze(
    files: List[Path] = typer.Argument(..., help="Files to analyze"),
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output",
        "-o",
        help="Output directory for reports",
    ),
    report_format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Report format (json, html, markdown, pdf)",
    ),
    agent_type: Optional[str] = typer.Option(
        None,
        "--agent",
        "-a",
        help="Force specific agent type",
    ),
    skip_vt: bool = typer.Option(
        False,
        "--skip-vt",
        help="Skip VirusTotal queries",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
    log_file: Optional[Path] = typer.Option(
        None,
        "--log-file",
        "-l",
        help="Log file path",
    ),
):
    """Analyze files in batch mode and generate reports.

    Example:
        blueguardian batch analyze sample1.exe sample2.pdf -o ./reports -f html
    """
    setup_logging(verbose, str(log_file) if log_file else None)

    console.print("[bold blue]🛡️  BlueGuardian AI - Batch Analysis Mode[/bold blue]\n")

    # Validate files
    valid_files = []
    for file_path in files:
        if not file_path.exists():
            console.print(f"[red]✗[/red] File not found: {file_path}")
            continue
        if not file_path.is_file():
            console.print(f"[red]✗[/red] Not a file: {file_path}")
            continue
        valid_files.append(file_path)

    if not valid_files:
        console.print("[red]No valid files to analyze.[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Found {len(valid_files)} file(s) to analyze[/green]\n")

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run batch analysis
    asyncio.run(
        _run_batch_analysis(
            valid_files,
            output_dir,
            report_format,
            agent_type,
            skip_vt,
        )
    )


async def _run_batch_analysis(
    files: List[Path],
    output_dir: Path,
    report_format: str,
    agent_type: Optional[str],
    skip_vt: bool,
):
    """Run batch analysis.

    Args:
        files: List of files to analyze
        output_dir: Output directory
        report_format: Report format
        agent_type: Optional agent type
        skip_vt: Skip VirusTotal
    """
    # Initialize orchestrator
    console.print("[cyan]Initializing BlueGuardian AI...[/cyan]")
    settings = get_settings()
    orchestrator = Orchestrator(settings)
    report_generator = ReportGenerator()

    results_summary = []

    # Analyze files with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing files...", total=len(files))

        for file_path in files:
            progress.update(task, description=f"Analyzing {file_path.name}...")

            try:
                # Run analysis
                result = await orchestrator.analyze_file(
                    str(file_path),
                    agent_type=agent_type,
                    skip_vt=skip_vt,
                )

                # Generate report
                report_filename = f"{file_path.stem}_report"

                if report_format == "json":
                    report_path = output_dir / f"{report_filename}.json"
                    report_generator.generate_json_report(result, str(report_path))
                elif report_format == "html":
                    report_path = output_dir / f"{report_filename}.html"
                    report_generator.generate_html_report(result, str(report_path))
                elif report_format == "markdown":
                    report_path = output_dir / f"{report_filename}.md"
                    report_generator.generate_markdown_report(result, str(report_path))
                elif report_format == "pdf":
                    report_path = output_dir / f"{report_filename}.pdf"
                    report_generator.generate_pdf_report(result, str(report_path))
                else:
                    console.print(f"[red]Unsupported format: {report_format}[/red]")
                    report_path = output_dir / f"{report_filename}.json"
                    report_generator.generate_json_report(result, str(report_path))

                results_summary.append({
                    'file': file_path.name,
                    'verdict': result.verdict.value,
                    'confidence': result.confidence,
                    'iocs': len(result.iocs),
                    'report': report_path.name,
                    'status': 'success',
                })

                logger.info(
                    f"Analysis complete: {file_path.name} -> {result.verdict.value} "
                    f"(confidence: {result.confidence:.0%})"
                )

            except Exception as e:
                logger.error(f"Analysis failed for {file_path.name}: {e}")
                results_summary.append({
                    'file': file_path.name,
                    'verdict': 'ERROR',
                    'confidence': 0.0,
                    'iocs': 0,
                    'report': 'N/A',
                    'status': 'failed',
                })

            progress.advance(task)

    # Shutdown
    await orchestrator.shutdown()

    # Display summary table
    console.print("\n[bold green]✓ Batch Analysis Complete[/bold green]\n")

    table = Table(title="Analysis Results Summary")
    table.add_column("File", style="cyan")
    table.add_column("Verdict", style="magenta")
    table.add_column("Confidence", justify="right")
    table.add_column("IOCs", justify="right")
    table.add_column("Report", style="blue")

    for result in results_summary:
        verdict_style = {
            'malicious': 'bold red',
            'suspicious': 'bold yellow',
            'clean': 'bold green',
            'unknown': 'dim',
            'ERROR': 'bold red',
        }.get(result['verdict'].lower(), 'dim')

        table.add_row(
            result['file'],
            f"[{verdict_style}]{result['verdict']}[/{verdict_style}]",
            f"{result['confidence']:.0%}",
            str(result['iocs']),
            result['report'],
        )

    console.print(table)
    console.print(f"\n[green]Reports saved to: {output_dir}[/green]")

    # Calculate statistics
    total = len(results_summary)
    malicious = sum(1 for r in results_summary if r['verdict'].lower() == 'malicious')
    suspicious = sum(1 for r in results_summary if r['verdict'].lower() == 'suspicious')
    clean = sum(1 for r in results_summary if r['verdict'].lower() == 'clean')
    failed = sum(1 for r in results_summary if r['status'] == 'failed')

    console.print(f"\n[bold]Statistics:[/bold]")
    console.print(f"  Total files: {total}")
    console.print(f"  [red]Malicious: {malicious}[/red]")
    console.print(f"  [yellow]Suspicious: {suspicious}[/yellow]")
    console.print(f"  [green]Clean: {clean}[/green]")
    if failed:
        console.print(f"  [red]Failed: {failed}[/red]")


@app.command()
def scan_directory(
    directory: Path = typer.Argument(..., help="Directory to scan"),
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output",
        "-o",
        help="Output directory for reports",
    ),
    pattern: str = typer.Option(
        "*",
        "--pattern",
        "-p",
        help="File pattern (e.g., '*.exe', '*.pdf')",
    ),
    recursive: bool = typer.Option(
        False,
        "--recursive",
        "-r",
        help="Scan recursively",
    ),
    report_format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Report format (json, html, markdown, pdf)",
    ),
    max_files: int = typer.Option(
        100,
        "--max-files",
        "-m",
        help="Maximum files to analyze",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
):
    """Scan a directory and analyze all matching files.

    Example:
        blueguardian batch scan-directory /path/to/samples -p "*.exe" -r
    """
    setup_logging(verbose)

    console.print("[bold blue]🛡️  BlueGuardian AI - Directory Scan Mode[/bold blue]\n")

    # Validate directory
    if not directory.exists():
        console.print(f"[red]Directory not found: {directory}[/red]")
        raise typer.Exit(1)

    if not directory.is_dir():
        console.print(f"[red]Not a directory: {directory}[/red]")
        raise typer.Exit(1)

    # Find files
    console.print(f"[cyan]Scanning directory: {directory}[/cyan]")
    console.print(f"[cyan]Pattern: {pattern}[/cyan]")
    console.print(f"[cyan]Recursive: {recursive}[/cyan]\n")

    if recursive:
        files = list(directory.rglob(pattern))
    else:
        files = list(directory.glob(pattern))

    # Filter to only files
    files = [f for f in files if f.is_file()]

    # Limit files
    if len(files) > max_files:
        console.print(f"[yellow]Found {len(files)} files, limiting to {max_files}[/yellow]")
        files = files[:max_files]
    else:
        console.print(f"[green]Found {len(files)} file(s)[/green]")

    if not files:
        console.print("[red]No files found matching pattern.[/red]")
        raise typer.Exit(1)

    # Run batch analysis
    asyncio.run(
        _run_batch_analysis(
            files,
            output_dir,
            report_format,
            None,
            False,
        )
    )


if __name__ == "__main__":
    app()
