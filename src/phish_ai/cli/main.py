"""Typer CLI command-line forensic analysis and administration tool."""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phish_ai.config.settings import Settings
from phish_ai.db.database import DatabaseManager
from phish_ai.extractors.headers import HeaderForensicExtractor
from phish_ai.extractors.nlp import NLPExtractor
from phish_ai.extractors.urls import URLExtractor
from phish_ai.ml.classifier import PhishingEnsembleClassifier
from phish_ai.models.enums import AuthStatus, TargetType, Verdict
from phish_ai.models.schemas import FeatureVector, ScanResult

app = typer.Typer(
    name="phish-ai",
    help="AI Phishing Detection System CLI Forensic Analyst Tool.",
    no_args_is_help=True,
)
console = Console()


def get_db(db_path: Path | None = None) -> DatabaseManager:
    path = db_path or Settings().db_path
    db = DatabaseManager(path)
    db.init_db()
    return db


@app.command("scan-email")
def scan_email(
    file_path: Path = typer.Argument(..., help="Path to raw .eml RFC 5322 email file"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Analyze raw .eml email file for spoofing, deceptive headers, and phishing lures."""
    if not file_path.exists():
        console.print(f"[bold red]Error:[/] File '{file_path}' does not exist.")
        raise typer.Exit(code=1)

    raw_content = file_path.read_text(encoding="utf-8", errors="replace")

    headers = HeaderForensicExtractor.extract_from_raw_headers(raw_content)
    nlp = NLPExtractor.extract_features(raw_content)
    urls = URLExtractor.extract_urls_from_text(raw_content)
    url_records = [URLExtractor.analyze_url(u) for u in urls]

    spf_fail = 1.0 if headers.spf_status == AuthStatus.FAIL else 0.0
    dkim_fail = 1.0 if headers.dkim_status == AuthStatus.FAIL else 0.0
    dmarc_fail = 1.0 if headers.dmarc_status == AuthStatus.FAIL else 0.0
    max_entropy = max((u.shannon_entropy for u in url_records), default=0.0)
    has_ip = 1.0 if any(u.has_ip_host for u in url_records) else 0.0
    has_homoglyph = 1.0 if any(u.has_homoglyphs for u in url_records) else 0.0
    has_bad_tld = 1.0 if any(u.suspicious_tld for u in url_records) else 0.0

    features = FeatureVector(
        spf_fail=spf_fail,
        dkim_fail=dkim_fail,
        dmarc_fail=dmarc_fail,
        display_name_spoof=1.0 if headers.has_display_name_spoof else 0.0,
        return_path_mismatch=1.0 if headers.return_path_mismatch else 0.0,
        urgency_score=nlp.urgency_score,
        financial_lure_score=nlp.financial_lure_score,
        threat_score=nlp.threat_intimidation_score,
        uppercase_ratio=nlp.uppercase_ratio,
        call_to_action=1.0 if nlp.call_to_action_detected else 0.0,
        max_url_entropy=max_entropy,
        has_ip_url=has_ip,
        has_homoglyph_url=has_homoglyph,
        has_suspicious_tld=has_bad_tld,
        url_count=float(len(url_records)),
    )

    clf = PhishingEnsembleClassifier()
    verdict, risk, prob, conf = clf.classify(features)
    threats = clf.explain(features)

    db = get_db(db_path)
    result = ScanResult(
        target_type=TargetType.EMAIL,
        target_identifier=headers.subject or str(file_path.name),
        verdict=verdict,
        risk_level=risk,
        phishing_probability=prob,
        confidence_score=conf,
        header_features=headers,
        nlp_features=nlp,
        url_records=url_records,
        top_threat_indicators=threats,
    )
    db.save_scan(result)

    # Render summary panel
    verdict_color = "red" if verdict == Verdict.PHISHING else "green"
    console.print(
        Panel.fit(
            f"[bold {verdict_color}]VERDICT: {verdict.value}[/] | "
            f"Risk: [bold]{risk.value}[/] | "
            f"Phishing Probability: {prob * 100:.1f}% (Confidence: {conf * 100:.1f}%)",
            title=f"Forensic Assessment: {file_path.name}",
        )
    )

    if threats:
        table = Table(title="Top Contributing Threat Indicators")
        table.add_column("Indicator", style="bold cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Weight", justify="right")

        for t in threats:
            table.add_row(t.indicator_name, t.category, t.description, f"{t.weight:.2f}")
        console.print(table)


@app.command("scan-url")
def scan_url(
    url: str = typer.Argument(..., help="Target HTTP/HTTPS URL to analyze"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Analyze single target URL for deceptive homoglyphs, Punycode, or raw IP."""
    url_record = URLExtractor.analyze_url(url)
    features = FeatureVector(
        max_url_entropy=url_record.shannon_entropy,
        has_ip_url=1.0 if url_record.has_ip_host else 0.0,
        has_homoglyph_url=1.0 if url_record.has_homoglyphs else 0.0,
        has_suspicious_tld=1.0 if url_record.suspicious_tld else 0.0,
        url_count=1.0,
    )

    clf = PhishingEnsembleClassifier()
    verdict, risk, prob, conf = clf.classify(features)
    threats = clf.explain(features)

    db = get_db(db_path)
    result = ScanResult(
        target_type=TargetType.URL,
        target_identifier=url,
        verdict=verdict,
        risk_level=risk,
        phishing_probability=prob,
        confidence_score=conf,
        url_records=[url_record],
        top_threat_indicators=threats,
    )
    db.save_scan(result)

    verdict_color = "red" if verdict == Verdict.PHISHING else "green"
    console.print(
        Panel.fit(
            f"[bold {verdict_color}]VERDICT: {verdict.value}[/] | "
            f"Risk: [bold]{risk.value}[/] | "
            f"Phishing Probability: {prob * 100:.1f}%\n"
            f"Domain: {url_record.domain} | Entropy: {url_record.shannon_entropy} | "
            f"Homoglyph: {url_record.has_homoglyphs} | Raw IP: {url_record.has_ip_host}",
            title=f"URL Assessment: {url}",
        )
    )


@app.command("scans")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of recent scans to display"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """List historical scan results recorded in the local database."""
    db = get_db(db_path)
    records = db.list_scans(limit=limit)
    if not records:
        console.print("[dim]No scans recorded in database.[/]")
        return

    table = Table(title=f"Historical Phishing Scans ({len(records)})")
    table.add_column("Scan ID", style="dim", no_wrap=True)
    table.add_column("Type", style="cyan")
    table.add_column("Target", style="white")
    table.add_column("Verdict", style="bold")
    table.add_column("Risk", style="yellow")
    table.add_column("Probability", justify="right")

    for s in records:
        v_color = "red" if s.verdict == Verdict.PHISHING else "green"
        table.add_row(
            s.scan_id,
            s.target_type.value,
            s.target_identifier[:40],
            f"[{v_color}]{s.verdict.value}[/{v_color}]",
            s.risk_level.value,
            f"{s.phishing_probability * 100:.1f}%",
        )

    console.print(table)


if __name__ == "__main__":
    app()
