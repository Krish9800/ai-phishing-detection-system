"""Unit tests for URL forensics and lexical feature extractor."""

from phish_ai.extractors.urls import URLExtractor


def test_shannon_entropy() -> None:
    """Verify Shannon entropy computation for low and high randomness strings."""
    # Low entropy (repetitive)
    low_ent = URLExtractor.calculate_shannon_entropy("aaaaaaa")
    assert low_ent == 0.0

    # High entropy (random algorithmic DGA domain string)
    high_ent = URLExtractor.calculate_shannon_entropy("x8f72q9zm1b4v0pk")
    assert high_ent > 3.5


def test_extract_urls_from_text() -> None:
    """Verify extraction of URLs from email text."""
    body = (
        "Check this out: https://secure-login.xyz/auth?user=victim and "
        "also visit www.bank-verify.com/login for updates."
    )
    urls = URLExtractor.extract_urls_from_text(body)
    assert len(urls) == 2
    assert "https://secure-login.xyz/auth?user=victim" in urls
    assert "http://www.bank-verify.com/login" in urls


def test_analyze_suspicious_ip_and_tld_url() -> None:
    """Verify detection of IP-based host, suspicious TLD, and long query string."""
    ip_url = "http://198.51.100.22:8080/login.php?session=abc&token=xyz"
    rec = URLExtractor.analyze_url(ip_url)

    assert rec.has_ip_host is True
    assert rec.domain == "198.51.100.22"
    assert rec.query_param_count == 2
    assert rec.length == len(ip_url)


def test_analyze_homoglyph_and_punycode_url() -> None:
    """Verify detection of homoglyph spoofing and Punycode domains."""
    homoglyph_url = "https://paypa1-security-check.xyz/login"
    rec = URLExtractor.analyze_url(homoglyph_url)

    assert rec.has_homoglyphs is True
    assert rec.suspicious_tld is True
    assert rec.tld == ".xyz"

    punycode_url = "https://xn--pple-43d.com/support"
    rec_puny = URLExtractor.analyze_url(punycode_url)
    assert rec_puny.is_punycode is True


def test_clean_benign_url() -> None:
    """Verify benign enterprise domain properties."""
    legit_url = "https://www.github.com/explore"
    rec = URLExtractor.analyze_url(legit_url)

    assert rec.has_ip_host is False
    assert rec.is_punycode is False
    assert rec.has_homoglyphs is False
    assert rec.suspicious_tld is False
    assert rec.domain == "www.github.com"
    assert rec.tld == ".com"
