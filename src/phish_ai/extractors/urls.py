"""Lexical, structural, and reputation URL forensic analyzer."""

import math
import re
from urllib.parse import urlparse

from phish_ai.models.schemas import UrlForensicRecord


class URLExtractor:
    """Extracts forensic signals, entropy, homoglyphs, and redirection cues from URLs."""

    # High-risk TLDs commonly abused for fast-flux phishing campaigns
    SUSPICIOUS_TLDS: set[str] = {
        ".zip",
        ".mov",
        ".top",
        ".xyz",
        ".work",
        ".gq",
        ".cf",
        ".tk",
        ".ml",
        ".ga",
        ".loan",
        ".click",
        ".country",
        ".stream",
        ".download",
    }

    # Characters often substituted in homograph/typosquatting attacks
    HOMOGLYPH_CHARS: set[str] = {
        "0",  # O substitution
        "1",  # l or I substitution
        "vv",  # w substitution
        "rn",  # m substitution
    }

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy for a string (measures algorithmic randomness)."""
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)
        freq_map: dict[str, int] = {}
        for char in data:
            freq_map[char] = freq_map.get(char, 0) + 1

        for count in freq_map.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)

        return round(entropy, 3)

    @classmethod
    def extract_urls_from_text(cls, text: str) -> list[str]:
        """Extract HTTP/HTTPS URLs and bare domain patterns from text block."""
        url_pattern = r"https?://[^\s<>\"'()]+|www\.[^\s<>\"'()]+"
        matches = re.findall(url_pattern, text)
        clean_urls = []
        for m in matches:
            u = m.rstrip(".,;!?:")
            if u.startswith("www."):
                u = f"http://{u}"
            clean_urls.append(u)
        return clean_urls

    @classmethod
    def analyze_url(cls, raw_url: str) -> UrlForensicRecord:
        """Perform comprehensive lexical forensics on target URL."""
        parsed = urlparse(raw_url)
        netloc = parsed.netloc.lower()
        host = netloc.split(":")[0] if ":" in netloc else netloc

        # Check for IP address host
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))

        # TLD extraction
        parts = host.split(".")
        tld = f".{parts[-1]}" if len(parts) > 1 and not is_ip else ""
        suspicious_tld = tld in cls.SUSPICIOUS_TLDS

        # Subdomain depth
        subdomain_depth = max(0, len(parts) - 2) if not is_ip else 0

        # Punycode / IDN detection
        is_punycode = host.startswith("xn--") or ".xn--" in host

        # Homoglyph heuristic (checks for known deceptive token combinations)
        has_homoglyphs = any(combo in host for combo in ["paypal-", "paypa1", "micros0ft", "app1e"])

        # Shannon entropy of hostname + path
        entropy = cls.calculate_shannon_entropy(host + parsed.path)

        # Path and parameter characteristics
        path = parsed.path
        query = parsed.query
        query_param_count = len(query.split("&")) if query else 0

        # Deceptive redirection cues
        has_at_symbol = "@" in raw_url
        has_double_slash_redirect = "//" in path

        return UrlForensicRecord(
            url=raw_url,
            domain=host,
            tld=tld,
            length=len(raw_url),
            shannon_entropy=entropy,
            has_ip_host=is_ip,
            is_punycode=is_punycode,
            has_homoglyphs=has_homoglyphs,
            suspicious_tld=suspicious_tld,
            subdomain_depth=subdomain_depth,
            path_length=len(path),
            query_param_count=query_param_count,
            has_at_symbol=has_at_symbol,
            has_double_slash_redirect=has_double_slash_redirect,
        )
