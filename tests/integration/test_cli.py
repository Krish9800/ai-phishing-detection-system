"""Integration tests for Typer CLI tool."""

from pathlib import Path

from typer.testing import CliRunner

from phish_ai.cli.main import app

runner = CliRunner()


def test_cli_help() -> None:
    """Test CLI help menu."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AI Phishing Detection System" in result.output
    assert "scan-email" in result.output
    assert "scan-url" in result.output
    assert "scans" in result.output


def test_cli_scan_email(tmp_path: Path) -> None:
    """Test scanning .eml file via CLI."""
    db_file = tmp_path / "cli_test.db"
    eml_file = tmp_path / "phish.eml"
    eml_file.write_text(
        "From: PayPal Support <security@paypa1-update.xyz>\r\n"
        "Subject: Urgent Account Suspension\r\n\r\n"
        "Your account is compromised. Immediate action required. "
        "Click here: http://198.51.100.22/verify",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan-email", str(eml_file), "--db-path", str(db_file)],
    )
    assert result.exit_code == 0
    assert "VERDICT: PHISHING" in result.output
    assert "DISPLAY_NAME_SPOOF" in result.output


def test_cli_scan_email_nonexistent() -> None:
    """Test error handling when email file does not exist."""
    result = runner.invoke(app, ["scan-email", "/non/existent/file.eml"])
    assert result.exit_code == 1
    assert "does not exist" in result.output


def test_cli_scan_url_and_list(tmp_path: Path) -> None:
    """Test scanning URL and querying scan history via CLI."""
    db_file = tmp_path / "cli_url_test.db"

    # Scan URL
    res_url = runner.invoke(
        app,
        ["scan-url", "https://paypa1-update.xyz/login", "--db-path", str(db_file)],
    )
    assert res_url.exit_code == 0
    assert "URL Assessment" in res_url.output
    assert "paypa1-update.xyz" in res_url.output

    # List scans
    res_list = runner.invoke(app, ["scans", "--db-path", str(db_file)])
    assert res_list.exit_code == 0
    assert "Historical Phishing Scans" in res_list.output
    assert "URL" in res_list.output
