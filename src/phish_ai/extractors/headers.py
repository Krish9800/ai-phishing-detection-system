"""RFC 5322 Email Header Forensics & Sender Authentication Extractor."""

import email
import email.policy
import re
from email.message import EmailMessage

from phish_ai.models.enums import AuthStatus
from phish_ai.models.schemas import HeaderFeatures


class HeaderForensicExtractor:
    """Extracts forensic metadata, SPF/DKIM/DMARC status, and spoofing cues from headers."""

    # Well-known enterprise domains frequently targeted for display-name spoofing
    IMPERSONATION_TARGETS: set[str] = {
        "paypal.com",
        "microsoft.com",
        "apple.com",
        "google.com",
        "amazon.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "chase.com",
        "netflix.com",
        "dhl.com",
        "fedex.com",
        "irs.gov",
    }

    @staticmethod
    def parse_auth_results(header_value: str | None) -> tuple[AuthStatus, AuthStatus, AuthStatus]:
        """Parse Authentication-Results header to determine SPF, DKIM, and DMARC status."""
        spf = AuthStatus.NONE
        dkim = AuthStatus.NONE
        dmarc = AuthStatus.NONE

        if not header_value:
            return spf, dkim, dmarc

        val_lower = header_value.lower()

        # Check SPF
        spf_match = re.search(r"spf=([a-z]+)", val_lower)
        if spf_match:
            status_str = spf_match.group(1).upper()
            try:
                spf = AuthStatus(status_str)
            except ValueError:
                spf = AuthStatus.NONE

        # Check DKIM
        dkim_match = re.search(r"dkim=([a-z]+)", val_lower)
        if dkim_match:
            status_str = dkim_match.group(1).upper()
            try:
                dkim = AuthStatus(status_str)
            except ValueError:
                dkim = AuthStatus.NONE

        # Check DMARC
        dmarc_match = re.search(r"dmarc=([a-z]+)", val_lower)
        if dmarc_match:
            status_str = dmarc_match.group(1).upper()
            try:
                dmarc = AuthStatus(status_str)
            except ValueError:
                dmarc = AuthStatus.NONE

        return spf, dkim, dmarc

    @classmethod
    def check_display_name_spoofing(cls, from_header: str) -> bool:
        """Detect display-name impersonation (e.g., 'PayPal Support <attacker@evil.com>')."""
        # Format usually: Display Name <address@domain.tld>
        match = re.search(r"^([^<]+)<([^>]+)>", from_header.strip())
        if not match:
            return False

        display_name = match.group(1).strip().lower()
        actual_addr = match.group(2).strip().lower()

        actual_domain = actual_addr.split("@")[-1] if "@" in actual_addr else ""

        for target in cls.IMPERSONATION_TARGETS:
            brand_name = target.split(".")[0]
            if brand_name in display_name and not actual_domain.endswith(target):
                return True

        return False

    @staticmethod
    def extract_domain(address: str) -> str:
        """Extract clean domain from email address."""
        clean = address.strip().strip("<>").lower()
        if "@" in clean:
            return clean.split("@")[-1].strip()
        return clean

    @classmethod
    def extract_from_raw_headers(cls, raw_email_or_headers: str) -> HeaderFeatures:
        """Parse raw RFC 5322 email string or header block into HeaderFeatures."""
        msg: EmailMessage = email.message_from_string(
            raw_email_or_headers, policy=email.policy.default
        )

        from_raw = str(msg.get("From", "unknown@unknown.local"))
        subject = str(msg.get("Subject", ""))
        reply_to = msg.get("Reply-To")
        return_path = msg.get("Return-Path")
        auth_results = msg.get("Authentication-Results")
        received_headers = msg.get_all("Received") or []

        # Client IP extraction from earliest originating Received header
        client_ip = None
        for r_hdr in received_headers:
            ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", str(r_hdr))
            if ip_match:
                client_ip = ip_match.group(1)
                break

        from_domain = cls.extract_domain(from_raw)
        return_path_domain = cls.extract_domain(str(return_path)) if return_path else None

        # Return-Path mismatch: sender domain differs from bounce envelope domain
        return_path_mismatch = bool(
            return_path_domain
            and from_domain != "unknown.local"
            and return_path_domain != from_domain
        )

        spf, dkim, dmarc = cls.parse_auth_results(auth_results)
        display_name_spoof = cls.check_display_name_spoofing(from_raw)

        return HeaderFeatures(
            from_address=from_raw,
            from_domain=from_domain,
            reply_to=str(reply_to) if reply_to else None,
            return_path=str(return_path) if return_path else None,
            subject=subject,
            spf_status=spf,
            dkim_status=dkim,
            dmarc_status=dmarc,
            has_display_name_spoof=display_name_spoof,
            return_path_mismatch=return_path_mismatch,
            received_hop_count=len(received_headers),
            client_ip=client_ip,
        )
