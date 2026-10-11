"""Unit tests for RFC 5322 email header forensics extractor."""

from phish_ai.extractors.headers import HeaderForensicExtractor
from phish_ai.models.enums import AuthStatus


def test_parse_auth_results() -> None:
    """Test SPF, DKIM, and DMARC status parsing."""
    auth_hdr = (
        "mx.google.com; dkim=pass header.i=@legit.com; "
        "spf=pass (google.com: domain of support@legit.com designates 198.51.100.1); "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legit.com"
    )
    spf, dkim, dmarc = HeaderForensicExtractor.parse_auth_results(auth_hdr)
    assert spf == AuthStatus.PASS
    assert dkim == AuthStatus.PASS
    assert dmarc == AuthStatus.PASS

    fail_hdr = "mx.google.com; spf=fail (ip=1.2.3.4); dkim=fail; dmarc=fail"
    spf_f, dkim_f, dmarc_f = HeaderForensicExtractor.parse_auth_results(fail_hdr)
    assert spf_f == AuthStatus.FAIL
    assert dkim_f == AuthStatus.FAIL
    assert dmarc_f == AuthStatus.FAIL


def test_display_name_spoofing() -> None:
    """Test detection of display name brand spoofing."""
    spoofed = "PayPal Support Team <attacker@evil-phish.ru>"
    assert HeaderForensicExtractor.check_display_name_spoofing(spoofed) is True

    legit = "PayPal Support <support@paypal.com>"
    assert HeaderForensicExtractor.check_display_name_spoofing(legit) is False

    generic = "John Doe <johndoe@gmail.com>"
    assert HeaderForensicExtractor.check_display_name_spoofing(generic) is False


def test_extract_from_raw_headers() -> None:
    """Test parsing complete raw email header block."""
    raw_email = (
        "From: Microsoft Security <alert@fake-ms-portal.xyz>\r\n"
        "To: victim@company.com\r\n"
        "Subject: Urgent: Verify your Microsoft 365 Password\r\n"
        "Return-Path: <bounce@unrelated-server.net>\r\n"
        "Authentication-Results: mail.company.com; spf=fail; dkim=none; dmarc=fail\r\n"
        "Received: from attacker.xyz (attacker.xyz [203.0.113.55]) by mail.company.com;\r\n"
        "Received: from relay.internal ([10.0.0.1]) by mail.company.com;\r\n"
        "\r\n"
        "Please update your password immediately."
    )

    features = HeaderForensicExtractor.extract_from_raw_headers(raw_email)
    assert features.from_domain == "fake-ms-portal.xyz"
    assert features.has_display_name_spoof is True
    assert features.return_path_mismatch is True
    assert features.spf_status == AuthStatus.FAIL
    assert features.dmarc_status == AuthStatus.FAIL
    assert features.received_hop_count == 2
    assert features.client_ip == "203.0.113.55"
