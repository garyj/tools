#!/usr/bin/env -S uv run
"""
Email domain configuration checker.

Validates DNS records and server configuration for email deliverability.
Checks MX, SPF, DKIM, DMARC, PTR, MTA-STS, TLS-RPT, BIMI, STARTTLS, and blacklists.

Usage:
    uv run py/emailcheck.py example.com
    uv run py/emailcheck.py --json example.com
    uv run py/emailcheck.py -s myselector example.com
    uv run py/emailcheck.py user@example.com
"""
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "click>=8.0.0",
#   "dnspython>=2.4.0",
#   "checkdmarc>=5.0.0",
#   "pydnsbl>=1.0.0",
#   "tabulate>=0.9.0",
# ]
# ///

import json
import re
import smtplib
import socket
import ssl
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

import click
import dns.resolver
import dns.reversename
from tabulate import tabulate

# Lazy imports for optional heavy dependencies
checkdmarc = None
pydnsbl = None


def _import_checkdmarc():
    global checkdmarc
    if checkdmarc is None:
        import checkdmarc as _checkdmarc
        checkdmarc = _checkdmarc
    return checkdmarc


def _import_pydnsbl():
    global pydnsbl
    if pydnsbl is None:
        import pydnsbl as _pydnsbl
        pydnsbl = _pydnsbl
    return pydnsbl


class Status(Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    name: str
    status: Status
    details: str
    sub_results: list["CheckResult"] = field(default_factory=list)


DEFAULT_DKIM_SELECTORS = [
    "google",      # Google Workspace
    "selector1",   # Microsoft 365
    "selector2",   # Microsoft 365
    "default",     # Common default
    "s1", "s2",    # Generic
    "k1",          # Mailchimp
    "mail",        # Common
]

DNSBL_LIST = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
]

# DNS Provider patterns (from NS records)
DNS_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "awsdns": "Amazon Route 53",
    "google": "Google Cloud DNS",
    "domaincontrol": "GoDaddy",
    "registrar-servers": "Namecheap",
    "azure-dns": "Azure DNS",
    "digitalocean": "DigitalOcean",
    "linode": "Linode",
    "vultr": "Vultr",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "dnsimple": "DNSimple",
    "ns1": "NS1",
    "ultradns": "Neustar UltraDNS",
}

# Email Provider patterns (from MX records)
EMAIL_PROVIDERS = {
    "outlook": "Microsoft 365",
    "protection.outlook": "Microsoft 365",
    "google": "Google Workspace",
    "googlemail": "Google Workspace",
    "aspmx": "Google Workspace",
    "zoho": "Zoho Mail",
    "protonmail": "ProtonMail",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
    "pphosted": "Proofpoint",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "amazonses": "Amazon SES",
    "mailchimp": "Mailchimp/Mandrill",
    "mandrillapp": "Mailchimp/Mandrill",
    "postmarkapp": "Postmark",
    "sparkpost": "SparkPost",
    "messagelabs": "Symantec Email Security",
    "mxlogic": "McAfee Email Security",
    "ppe-hosted": "Cisco Email Security",
}


def extract_domain(input_str: str) -> str:
    """Extract domain from email address, URL, or plain domain."""
    input_str = input_str.strip().lower()

    # Remove trailing dot (FQDN format)
    if input_str.endswith('.'):
        input_str = input_str[:-1]

    # Check if it's an email address
    if '@' in input_str:
        domain = input_str.split('@')[-1]
    # Check if it's a URL
    elif '://' in input_str:
        parsed = urlparse(input_str)
        domain = parsed.netloc or parsed.path.split('/')[0]
    else:
        domain = input_str

    # Strip www. prefix
    if domain.startswith('www.'):
        domain = domain[4:]

    return domain


def check_mx(domain: str) -> CheckResult:
    """Check MX records for domain."""
    sub_results = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])

        if not mx_records:
            return CheckResult("MX Records", Status.FAIL, "No MX records found")

        # Check for null MX (RFC 7505)
        if len(mx_records) == 1 and mx_records[0][1] == '':
            return CheckResult("MX Records", Status.INFO, "Null MX - domain does not accept email")

        for priority, exchange in mx_records:
            # Try to resolve the MX hostname
            try:
                a_records = dns.resolver.resolve(exchange, 'A')
                ips = [str(r) for r in a_records]
                sub_results.append(CheckResult(
                    f"  {exchange}",
                    Status.PASS,
                    f"Priority {priority}, {', '.join(ips)}"
                ))
            except dns.resolver.NXDOMAIN:
                sub_results.append(CheckResult(
                    f"  {exchange}",
                    Status.FAIL,
                    f"Priority {priority}, hostname does not resolve"
                ))
            except dns.resolver.NoAnswer:
                sub_results.append(CheckResult(
                    f"  {exchange}",
                    Status.WARN,
                    f"Priority {priority}, no A record (IPv6 only?)"
                ))
            except Exception as e:
                sub_results.append(CheckResult(
                    f"  {exchange}",
                    Status.WARN,
                    f"Priority {priority}, lookup error: {e}"
                ))

        failed = sum(1 for r in sub_results if r.status == Status.FAIL)
        if failed == len(sub_results):
            status = Status.FAIL
        elif failed > 0:
            status = Status.WARN
        else:
            status = Status.PASS

        return CheckResult(
            "MX Records",
            status,
            f"{len(mx_records)} record(s) found",
            sub_results
        )

    except dns.resolver.NXDOMAIN:
        return CheckResult("MX Records", Status.FAIL, "Domain does not exist")
    except dns.resolver.NoAnswer:
        # Try A record fallback
        try:
            dns.resolver.resolve(domain, 'A')
            return CheckResult("MX Records", Status.WARN, "No MX records, using A record fallback")
        except Exception:
            return CheckResult("MX Records", Status.FAIL, "No MX or A records found")
    except Exception as e:
        return CheckResult("MX Records", Status.ERROR, f"Error: {e}")


def check_common_records(domain: str) -> CheckResult:
    """Check common infrastructure records and identify providers."""
    sub_results = []
    dns_provider = None
    email_provider = None

    # Check NS records for DNS provider
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        ns_hosts = [str(r).rstrip('.').lower() for r in ns_answers]

        for ns in ns_hosts:
            for pattern, provider in DNS_PROVIDERS.items():
                if pattern in ns:
                    dns_provider = provider
                    break
            if dns_provider:
                break

        if dns_provider:
            sub_results.append(CheckResult(
                "  DNS Provider",
                Status.INFO,
                dns_provider
            ))
    except Exception:
        pass

    # Check MX records for email provider
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip('.').lower() for r in mx_answers]

        for mx in mx_hosts:
            for pattern, provider in EMAIL_PROVIDERS.items():
                if pattern in mx:
                    email_provider = provider
                    break
            if email_provider:
                break

        if email_provider:
            sub_results.append(CheckResult(
                "  Email Provider",
                Status.INFO,
                email_provider
            ))
    except Exception:
        pass

    # Check A record for website
    try:
        a_answers = dns.resolver.resolve(domain, 'A')
        if a_answers:
            sub_results.append(CheckResult(
                "  Website (A)",
                Status.PASS,
                "Present"
            ))
    except dns.resolver.NXDOMAIN:
        sub_results.append(CheckResult(
            "  Website (A)",
            Status.INFO,
            "Not present"
        ))
    except dns.resolver.NoAnswer:
        sub_results.append(CheckResult(
            "  Website (A)",
            Status.INFO,
            "No A record"
        ))
    except Exception:
        pass

    if not sub_results:
        return CheckResult("Common Records", Status.INFO, "No infrastructure identified")

    identified = []
    if dns_provider:
        identified.append(f"DNS: {dns_provider}")
    if email_provider:
        identified.append(f"Email: {email_provider}")

    if identified:
        return CheckResult("Common Records", Status.PASS, "Infrastructure identified", sub_results)
    else:
        return CheckResult("Common Records", Status.INFO, "Records present", sub_results)


def check_spf(domain: str) -> CheckResult:
    """Check SPF record for domain using checkdmarc."""
    try:
        cd = _import_checkdmarc()
        result = cd.check_domains([domain], skip_tls=True)

        if isinstance(result, list):
            result = result[0] if result else {}

        spf_data = result.get('spf', {})

        if not spf_data or not spf_data.get('record'):
            return CheckResult("SPF Record", Status.FAIL, "No SPF record found")

        record = spf_data.get('record', '')
        valid = spf_data.get('valid', False)
        dns_lookups = spf_data.get('dns_lookups', 0)

        if not valid:
            errors = spf_data.get('error', 'Invalid syntax')
            return CheckResult("SPF Record", Status.FAIL, f"Invalid: {errors}")

        sub_results = []

        # Parse and explain the "all" mechanism
        all_mechanisms = {
            '-all': (Status.PASS, "Hard fail - unauthorized senders rejected"),
            '~all': (Status.WARN, "Soft fail - unauthorized treated as suspicious"),
            '?all': (Status.WARN, "Neutral - no policy on unauthorized senders"),
            '+all': (Status.FAIL, "Pass all - dangerous, allows any sender"),
        }

        all_match = re.search(r'([+\-~?]all)\s*$', record)
        if all_match:
            all_mech = all_match.group(1)
            if all_mech in all_mechanisms:
                status, explanation = all_mechanisms[all_mech]
                sub_results.append(CheckResult(
                    "  All Mechanism",
                    status,
                    f"{all_mech}: {explanation}"
                ))

        # Add DNS lookup info
        if dns_lookups >= 8:
            sub_results.append(CheckResult(
                "  DNS Lookups",
                Status.WARN,
                f"{dns_lookups}/10 (approaching limit)"
            ))
        else:
            sub_results.append(CheckResult(
                "  DNS Lookups",
                Status.PASS,
                f"{dns_lookups}/10"
            ))

        # Determine overall status
        if dns_lookups > 10:
            return CheckResult(
                "SPF Record",
                Status.FAIL,
                f"Too many DNS lookups: {dns_lookups}/10",
                sub_results
            )

        # Check for dangerous +all
        if '+all' in record:
            return CheckResult(
                "SPF Record",
                Status.FAIL,
                "Dangerous: +all allows any sender",
                sub_results
            )

        # Check for weak policies
        if '?all' in record:
            return CheckResult(
                "SPF Record",
                Status.WARN,
                f"Valid but weak (?all), {dns_lookups}/10 lookups",
                sub_results
            )

        if '~all' in record:
            return CheckResult(
                "SPF Record",
                Status.WARN if dns_lookups >= 8 else Status.PASS,
                f"Valid (~all), {dns_lookups}/10 lookups",
                sub_results
            )

        return CheckResult(
            "SPF Record",
            Status.PASS if dns_lookups < 8 else Status.WARN,
            f"Valid, {dns_lookups}/10 DNS lookups",
            sub_results
        )

    except Exception as e:
        return CheckResult("SPF Record", Status.ERROR, f"Error: {e}")


def check_dkim(domain: str, selectors: list[str]) -> CheckResult:
    """Check DKIM records for domain with multiple selectors."""
    sub_results = []
    found_count = 0

    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            txt_records = [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]

            for txt in txt_records:
                if 'v=DKIM1' in txt or ('k=' in txt and 'p=' in txt):
                    # Parse key info
                    key_type = "RSA"
                    key_size = "unknown"

                    # Try to determine key size from p= tag
                    p_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                    if p_match:
                        key_data = p_match.group(1)
                        # Rough estimate: base64 length * 6 / 8 = bytes, * 8 = bits
                        estimated_bits = len(key_data) * 6
                        if estimated_bits > 3000:
                            key_size = "2048-bit"
                        elif estimated_bits > 1500:
                            key_size = "1024-bit"
                        elif estimated_bits > 500:
                            key_size = "512-bit"

                    found_count += 1
                    sub_results.append(CheckResult(
                        f"  {selector}",
                        Status.PASS,
                        f"{key_type} {key_size} key found"
                    ))
                    break
            else:
                sub_results.append(CheckResult(
                    f"  {selector}",
                    Status.INFO,
                    "TXT record exists but no DKIM data"
                ))

        except dns.resolver.NXDOMAIN:
            sub_results.append(CheckResult(
                f"  {selector}",
                Status.INFO,
                "Not found"
            ))
        except dns.resolver.NoAnswer:
            sub_results.append(CheckResult(
                f"  {selector}",
                Status.INFO,
                "No TXT record"
            ))
        except Exception as e:
            sub_results.append(CheckResult(
                f"  {selector}",
                Status.ERROR,
                f"Error: {e}"
            ))

    if found_count == 0:
        status = Status.FAIL
        details = "No DKIM selectors found"
    elif found_count < len(selectors) // 2:
        status = Status.WARN
        details = f"{found_count} selector(s) found"
    else:
        status = Status.PASS
        details = f"{found_count} selector(s) found"

    return CheckResult("DKIM Records", status, details, sub_results)


def check_dmarc(domain: str) -> CheckResult:
    """Check DMARC record for domain using checkdmarc."""
    try:
        cd = _import_checkdmarc()
        result = cd.check_domains([domain], skip_tls=True)

        if isinstance(result, list):
            result = result[0] if result else {}

        dmarc_data = result.get('dmarc', {})

        if not dmarc_data or not dmarc_data.get('record'):
            return CheckResult("DMARC Record", Status.FAIL, "No DMARC record found")

        record = dmarc_data.get('record', '')
        valid = dmarc_data.get('valid', False)

        if not valid:
            errors = dmarc_data.get('error', 'Invalid syntax')
            return CheckResult("DMARC Record", Status.FAIL, f"Invalid: {errors}")

        sub_results = []

        # Parse all DMARC tags from the record
        # Policy (p=)
        p_match = re.search(r'p=(none|quarantine|reject)', record, re.IGNORECASE)
        policy = p_match.group(1).lower() if p_match else 'none'

        policy_details = {
            'reject': (Status.PASS, "p=reject (unauthorized emails rejected)"),
            'quarantine': (Status.PASS, "p=quarantine (unauthorized emails quarantined)"),
            'none': (Status.WARN, "p=none (monitoring only, no enforcement)"),
        }
        p_status, p_detail = policy_details.get(policy, (Status.WARN, f"p={policy}"))
        sub_results.append(CheckResult("  Policy", p_status, p_detail))

        # Percentage (pct=)
        pct_match = re.search(r'pct=(\d+)', record)
        pct = int(pct_match.group(1)) if pct_match else 100
        if pct == 100:
            sub_results.append(CheckResult("  Percentage", Status.PASS, f"pct={pct} (all emails)"))
        elif pct >= 50:
            sub_results.append(CheckResult("  Percentage", Status.WARN, f"pct={pct} (gradual rollout)"))
        else:
            sub_results.append(CheckResult("  Percentage", Status.WARN, f"pct={pct} (low coverage)"))

        # Aggregate Reports (rua=)
        rua_match = re.search(r'rua=([^;]+)', record)
        if rua_match:
            rua = rua_match.group(1).strip()
            # Check if it's self-only (only the domain's own address)
            rua_addresses = re.findall(r'mailto:([^,;\s]+)', rua)
            if rua_addresses:
                self_only = all(addr.endswith(f'@{domain}') for addr in rua_addresses)
                if self_only and len(rua_addresses) == 1:
                    sub_results.append(CheckResult(
                        "  Aggregate Reports",
                        Status.WARN,
                        f"rua={rua_addresses[0]} (self-only)"
                    ))
                else:
                    # Truncate if too long
                    rua_display = ', '.join(rua_addresses[:2])
                    if len(rua_addresses) > 2:
                        rua_display += f" (+{len(rua_addresses)-2} more)"
                    sub_results.append(CheckResult(
                        "  Aggregate Reports",
                        Status.PASS,
                        f"rua configured: {rua_display}"
                    ))
            else:
                sub_results.append(CheckResult("  Aggregate Reports", Status.PASS, "rua configured"))
        else:
            sub_results.append(CheckResult(
                "  Aggregate Reports",
                Status.WARN,
                "rua not configured (no visibility into failures)"
            ))

        # Failure Reports (ruf=)
        ruf_match = re.search(r'ruf=([^;]+)', record)
        if ruf_match:
            ruf = ruf_match.group(1).strip()
            ruf_addresses = re.findall(r'mailto:([^,;\s]+)', ruf)
            if ruf_addresses:
                sub_results.append(CheckResult(
                    "  Failure Reports",
                    Status.INFO,
                    f"ruf configured: {ruf_addresses[0]}"
                ))
            else:
                sub_results.append(CheckResult("  Failure Reports", Status.INFO, "ruf configured"))
        else:
            sub_results.append(CheckResult(
                "  Failure Reports",
                Status.INFO,
                "ruf not configured (optional)"
            ))

        # Determine overall status based on policy and pct
        if policy == 'reject' and pct == 100:
            return CheckResult("DMARC Record", Status.PASS, "p=reject, pct=100 (strongest)", sub_results)
        elif policy == 'reject':
            return CheckResult("DMARC Record", Status.PASS, f"p=reject, pct={pct}", sub_results)
        elif policy == 'quarantine':
            return CheckResult("DMARC Record", Status.PASS, f"p=quarantine, pct={pct}", sub_results)
        elif policy == 'none':
            return CheckResult("DMARC Record", Status.WARN, "p=none (monitoring only)", sub_results)
        else:
            return CheckResult("DMARC Record", Status.WARN, f"Policy: {policy or 'unknown'}", sub_results)

    except Exception as e:
        return CheckResult("DMARC Record", Status.ERROR, f"Error: {e}")


def check_ptr(domain: str) -> CheckResult:
    """Check PTR records for MX server IPs."""
    sub_results = []

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip('.') for r in mx_answers]
    except Exception:
        return CheckResult("PTR Records", Status.INFO, "No MX records to check")

    checked_ips = set()

    for mx_host in mx_hosts[:3]:  # Limit to first 3 MX hosts
        try:
            a_answers = dns.resolver.resolve(mx_host, 'A')
            for a_record in a_answers:
                ip = str(a_record)
                if ip in checked_ips:
                    continue
                checked_ips.add(ip)

                # Reverse DNS lookup
                try:
                    rev_name = dns.reversename.from_address(ip)
                    ptr_answers = dns.resolver.resolve(rev_name, 'PTR')
                    ptr_hostname = str(ptr_answers[0]).rstrip('.')

                    # Verify FCrDNS (Forward-Confirmed reverse DNS)
                    try:
                        fwd_answers = dns.resolver.resolve(ptr_hostname, 'A')
                        fwd_ips = [str(r) for r in fwd_answers]

                        if ip in fwd_ips:
                            sub_results.append(CheckResult(
                                f"  {ip}",
                                Status.PASS,
                                f"{ptr_hostname} (FCrDNS OK)"
                            ))
                        else:
                            sub_results.append(CheckResult(
                                f"  {ip}",
                                Status.WARN,
                                f"{ptr_hostname} (FCrDNS mismatch)"
                            ))
                    except Exception:
                        sub_results.append(CheckResult(
                            f"  {ip}",
                            Status.WARN,
                            f"{ptr_hostname} (FCrDNS check failed)"
                        ))

                except dns.resolver.NXDOMAIN:
                    sub_results.append(CheckResult(
                        f"  {ip}",
                        Status.FAIL,
                        "No PTR record"
                    ))
                except Exception as e:
                    sub_results.append(CheckResult(
                        f"  {ip}",
                        Status.ERROR,
                        f"PTR lookup error: {e}"
                    ))

        except Exception:
            continue

    if not sub_results:
        return CheckResult("PTR Records", Status.INFO, "Could not resolve MX IPs")

    failed = sum(1 for r in sub_results if r.status == Status.FAIL)
    if failed == len(sub_results):
        status = Status.FAIL
    elif failed > 0:
        status = Status.WARN
    else:
        status = Status.PASS

    return CheckResult("PTR Records", status, f"Checked {len(sub_results)} IP(s)", sub_results)


def check_mta_sts(domain: str) -> CheckResult:
    """Check MTA-STS DNS record and policy."""
    # Check DNS record
    sts_domain = f"_mta-sts.{domain}"
    try:
        answers = dns.resolver.resolve(sts_domain, 'TXT')
        txt_records = [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]

        sts_record = None
        for txt in txt_records:
            if txt.startswith('v=STSv1'):
                sts_record = txt
                break

        if not sts_record:
            return CheckResult("MTA-STS", Status.INFO, "No MTA-STS record found")

        # Try to fetch policy file
        import urllib.request
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

        try:
            req = urllib.request.Request(policy_url, headers={'User-Agent': 'emailcheck/1.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                policy = response.read().decode('utf-8')

                # Parse mode from policy
                mode_match = re.search(r'mode:\s*(enforce|testing|none)', policy, re.IGNORECASE)
                mode = mode_match.group(1).lower() if mode_match else 'unknown'

                max_age_match = re.search(r'max_age:\s*(\d+)', policy)
                max_age = int(max_age_match.group(1)) if max_age_match else 0

                if mode == 'enforce':
                    return CheckResult("MTA-STS", Status.PASS, f"mode={mode}, max_age={max_age}")
                elif mode == 'testing':
                    return CheckResult("MTA-STS", Status.WARN, f"mode={mode} (not enforcing)")
                else:
                    return CheckResult("MTA-STS", Status.INFO, f"mode={mode}")

        except Exception as e:
            return CheckResult("MTA-STS", Status.WARN, f"DNS record exists but policy fetch failed: {e}")

    except dns.resolver.NXDOMAIN:
        return CheckResult("MTA-STS", Status.INFO, "Not configured")
    except dns.resolver.NoAnswer:
        return CheckResult("MTA-STS", Status.INFO, "Not configured")
    except Exception as e:
        return CheckResult("MTA-STS", Status.ERROR, f"Error: {e}")


def check_tls_rpt(domain: str) -> CheckResult:
    """Check TLS-RPT DNS record."""
    rpt_domain = f"_smtp._tls.{domain}"
    try:
        answers = dns.resolver.resolve(rpt_domain, 'TXT')
        txt_records = [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]

        for txt in txt_records:
            if txt.startswith('v=TLSRPTv1'):
                # Extract rua
                rua_match = re.search(r'rua=([^;]+)', txt)
                if rua_match:
                    rua = rua_match.group(1).strip()
                    return CheckResult("TLS-RPT", Status.PASS, f"Reports to {rua[:50]}")
                return CheckResult("TLS-RPT", Status.PASS, "Configured")

        return CheckResult("TLS-RPT", Status.INFO, "No TLS-RPT record found")

    except dns.resolver.NXDOMAIN:
        return CheckResult("TLS-RPT", Status.INFO, "Not configured")
    except dns.resolver.NoAnswer:
        return CheckResult("TLS-RPT", Status.INFO, "Not configured")
    except Exception as e:
        return CheckResult("TLS-RPT", Status.ERROR, f"Error: {e}")


def check_bimi(domain: str) -> CheckResult:
    """Check BIMI DNS record with logo and VMC details."""
    bimi_domain = f"default._bimi.{domain}"
    try:
        answers = dns.resolver.resolve(bimi_domain, 'TXT')
        txt_records = [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]

        for txt in txt_records:
            if txt.startswith('v=BIMI1'):
                sub_results = []

                # Extract logo URL (l=)
                logo_match = re.search(r'l=([^;]+)', txt)
                logo = logo_match.group(1).strip() if logo_match else None

                # Extract authority/VMC URL (a=)
                auth_match = re.search(r'a=([^;]+)', txt)
                auth = auth_match.group(1).strip() if auth_match else None

                # Logo sub-result
                if logo:
                    # Truncate long URLs for display
                    logo_display = logo[:50] + '...' if len(logo) > 50 else logo
                    if logo.endswith('.svg') or 'svg' in logo.lower():
                        sub_results.append(CheckResult(
                            "  Logo",
                            Status.PASS,
                            f"SVG: {logo_display}"
                        ))
                    else:
                        sub_results.append(CheckResult(
                            "  Logo",
                            Status.WARN,
                            f"URL: {logo_display} (should be SVG)"
                        ))
                else:
                    sub_results.append(CheckResult(
                        "  Logo",
                        Status.WARN,
                        "No logo URL specified"
                    ))

                # VMC sub-result
                if auth:
                    auth_display = auth[:50] + '...' if len(auth) > 50 else auth
                    sub_results.append(CheckResult(
                        "  VMC Certificate",
                        Status.PASS,
                        f"Present: {auth_display}"
                    ))
                else:
                    sub_results.append(CheckResult(
                        "  VMC Certificate",
                        Status.INFO,
                        "Not configured (optional, enhances trust)"
                    ))

                # Determine overall status
                if logo and auth:
                    return CheckResult("BIMI", Status.PASS, "Logo + VMC configured", sub_results)
                elif logo:
                    return CheckResult("BIMI", Status.INFO, "Logo configured (no VMC)", sub_results)
                else:
                    return CheckResult("BIMI", Status.WARN, "Record exists but no logo", sub_results)

        return CheckResult("BIMI", Status.INFO, "Not configured")

    except dns.resolver.NXDOMAIN:
        return CheckResult("BIMI", Status.INFO, "Not configured")
    except dns.resolver.NoAnswer:
        return CheckResult("BIMI", Status.INFO, "Not configured")
    except Exception as e:
        return CheckResult("BIMI", Status.ERROR, f"Error: {e}")


def check_starttls(domain: str, timeout: int = 10) -> CheckResult:
    """Check STARTTLS support on MX servers."""
    sub_results = []

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in mx_answers])
    except Exception:
        return CheckResult("STARTTLS", Status.INFO, "No MX records to check")

    for priority, mx_host in mx_hosts[:2]:  # Limit to first 2 MX hosts
        try:
            # Try to connect and check STARTTLS
            with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
                smtp.ehlo()

                if smtp.has_extn('STARTTLS'):
                    # Upgrade to TLS
                    context = ssl.create_default_context()
                    smtp.starttls(context=context)
                    smtp.ehlo()

                    # Get TLS info
                    tls_version = smtp.sock.version() if hasattr(smtp.sock, 'version') else 'unknown'

                    if tls_version in ('TLSv1', 'TLSv1.0', 'TLSv1.1'):
                        sub_results.append(CheckResult(
                            f"  {mx_host}",
                            Status.WARN,
                            f"{tls_version} (deprecated)"
                        ))
                    else:
                        # Get cert info
                        cert = smtp.sock.getpeercert() if hasattr(smtp.sock, 'getpeercert') else None
                        cert_info = ""
                        if cert:
                            not_after = cert.get('notAfter', '')
                            if not_after:
                                cert_info = f", cert expires {not_after[:12]}"

                        sub_results.append(CheckResult(
                            f"  {mx_host}",
                            Status.PASS,
                            f"{tls_version}{cert_info}"
                        ))
                else:
                    sub_results.append(CheckResult(
                        f"  {mx_host}",
                        Status.FAIL,
                        "STARTTLS not offered"
                    ))

        except socket.timeout:
            sub_results.append(CheckResult(
                f"  {mx_host}",
                Status.WARN,
                "Connection timeout"
            ))
        except ssl.SSLError as e:
            sub_results.append(CheckResult(
                f"  {mx_host}",
                Status.WARN,
                f"TLS error: {e}"
            ))
        except (socket.error, smtplib.SMTPException) as e:
            sub_results.append(CheckResult(
                f"  {mx_host}",
                Status.WARN,
                f"Connection failed: {e}"
            ))
        except Exception as e:
            sub_results.append(CheckResult(
                f"  {mx_host}",
                Status.ERROR,
                f"Error: {e}"
            ))

    if not sub_results:
        return CheckResult("STARTTLS", Status.INFO, "Could not check MX servers")

    failed = sum(1 for r in sub_results if r.status == Status.FAIL)
    if failed == len(sub_results):
        status = Status.FAIL
    elif failed > 0:
        status = Status.WARN
    else:
        status = Status.PASS

    return CheckResult("STARTTLS", status, f"Checked {len(sub_results)} server(s)", sub_results)


def check_blacklists(domain: str) -> CheckResult:
    """Check if MX IPs are on any DNS blacklists."""
    try:
        pd = _import_pydnsbl()
    except ImportError:
        return CheckResult("Blacklists", Status.ERROR, "pydnsbl not installed")

    # Get MX IPs
    ips_to_check = set()
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        for mx in mx_answers:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                a_answers = dns.resolver.resolve(mx_host, 'A')
                for a in a_answers:
                    ips_to_check.add(str(a))
            except Exception:
                continue
    except Exception:
        pass

    if not ips_to_check:
        return CheckResult("Blacklists", Status.INFO, "No IPs to check")

    sub_results = []
    blacklisted_count = 0

    checker = pd.DNSBLIpChecker()

    for ip in list(ips_to_check)[:3]:  # Limit to 3 IPs
        try:
            result = checker.check(ip)
            if result.blacklisted:
                blacklisted_count += 1
                lists = list(result.detected_by.keys())[:3]
                sub_results.append(CheckResult(
                    f"  {ip}",
                    Status.FAIL,
                    f"Listed on: {', '.join(lists)}"
                ))
            else:
                sub_results.append(CheckResult(
                    f"  {ip}",
                    Status.PASS,
                    f"Clean ({len(result.providers)} lists checked)"
                ))
        except Exception as e:
            sub_results.append(CheckResult(
                f"  {ip}",
                Status.WARN,
                f"Check failed: {e}"
            ))

    if blacklisted_count > 0:
        status = Status.FAIL
        details = f"{blacklisted_count} IP(s) blacklisted"
    else:
        status = Status.PASS
        details = f"Clean ({len(ips_to_check)} IP(s) checked)"

    return CheckResult("Blacklists", status, details, sub_results)


# Scoring System Constants
SCORING_CONFIG = {
    "impersonation": {
        "max": 50,
        "checks": {
            "DMARC Record": 20,
            "SPF Record": 15,
            "DKIM Records": 15,
        }
    },
    "privacy": {
        "max": 25,
        "checks": {
            "MTA-STS": 10,
            "TLS-RPT": 5,
            "STARTTLS": 10,
        }
    },
    "deliverability": {
        "max": 25,
        "checks": {
            "MX Records": 10,
            "PTR Records": 10,
            "Blacklists": 5,
        }
    },
}


def get_risk_level(score: int) -> str:
    """Get risk level based on overall score."""
    if score >= 80:
        return "Low Risk"
    elif score >= 60:
        return "Moderate Risk"
    else:
        return "High Risk"


def calculate_scores(results: list[CheckResult]) -> dict:
    """Calculate category and overall scores from check results.

    Scoring: PASS = full points, WARN = half points, FAIL/ERROR = 0, INFO = neutral
    """
    # Build lookup of results by name
    result_map = {r.name.strip(): r for r in results}

    category_scores = {}

    for category, config in SCORING_CONFIG.items():
        category_score = 0
        category_max = config["max"]
        checks_found = []

        for check_name, points in config["checks"].items():
            result = result_map.get(check_name)
            if result:
                checks_found.append(check_name)
                if result.status == Status.PASS:
                    category_score += points
                elif result.status == Status.WARN:
                    category_score += points // 2
                # FAIL, ERROR = 0 points
                # INFO is neutral, we still count it as 0

        category_scores[category] = {
            "score": category_score,
            "max": category_max,
            "checks": checks_found,
        }

    overall = sum(cat["score"] for cat in category_scores.values())

    return {
        "overall": overall,
        "max": 100,
        "risk_level": get_risk_level(overall),
        "categories": category_scores,
    }


def format_status(status: Status, no_color: bool = False) -> str:
    """Format status with color."""
    if no_color:
        return status.value

    colors = {
        Status.PASS: 'green',
        Status.WARN: 'yellow',
        Status.FAIL: 'red',
        Status.INFO: 'cyan',
        Status.ERROR: 'magenta',
    }
    return click.style(status.value, fg=colors.get(status, 'white'), bold=True)


def format_results_table(results: list[CheckResult], domain: str, no_color: bool = False) -> str:
    """Format results as a table with scoring."""
    lines = []

    # Calculate scores
    scores = calculate_scores(results)

    # Header with overall score
    lines.append("═" * 55)
    lines.append(f"Email Configuration Report: {domain}")
    lines.append("═" * 55)
    lines.append("")

    # Overall Score
    score_str = f"{scores['overall']}/{scores['max']}"
    risk_level = scores['risk_level']

    # Color the risk level
    risk_colors = {
        'Low Risk': 'green',
        'Moderate Risk': 'yellow',
        'High Risk': 'red',
    }
    risk_color = risk_colors.get(risk_level, 'white') if not no_color else None
    risk_styled = click.style(risk_level, fg=risk_color, bold=True) if risk_color else risk_level

    lines.append(f"Overall Score: {score_str} - {risk_styled}")
    lines.append("")

    # Category Scores
    lines.append("Category Scores:")
    category_display = {
        'impersonation': 'Impersonation',
        'privacy': 'Privacy',
        'deliverability': 'Deliverability',
    }
    for cat_key, cat_data in scores['categories'].items():
        cat_name = category_display.get(cat_key, cat_key.title())
        checks_str = ', '.join(cat_data['checks'])
        lines.append(f"  {cat_name:15} {cat_data['score']:2}/{cat_data['max']} ({checks_str})")

    lines.append("")
    lines.append("─" * 55)

    # Build table data
    table_data = []
    for result in results:
        status_str = format_status(result.status, no_color)
        table_data.append([result.name, status_str, result.details])

        for sub in result.sub_results:
            sub_status = format_status(sub.status, no_color)
            table_data.append([sub.name, sub_status, sub.details])

    lines.append(tabulate(table_data, headers=['Check', 'Status', 'Details'], tablefmt='simple'))

    # Summary
    lines.append("")
    lines.append("─" * 55)
    passed = sum(1 for r in results if r.status == Status.PASS)
    warned = sum(1 for r in results if r.status == Status.WARN)
    failed = sum(1 for r in results if r.status == Status.FAIL)
    info = sum(1 for r in results if r.status == Status.INFO)

    summary_parts = []
    if passed:
        summary_parts.append(click.style(f"{passed} passed", fg='green' if not no_color else None))
    if warned:
        summary_parts.append(click.style(f"{warned} warnings", fg='yellow' if not no_color else None))
    if failed:
        summary_parts.append(click.style(f"{failed} failed", fg='red' if not no_color else None))
    if info:
        summary_parts.append(f"{info} info")

    lines.append(f"Summary: {', '.join(summary_parts)}")

    return '\n'.join(lines)


def format_results_json(results: list[CheckResult], domain: str) -> str:
    """Format results as JSON with scoring."""
    def result_to_dict(r: CheckResult) -> dict:
        d = {
            'name': r.name.strip(),
            'status': r.status.value,
            'details': r.details,
        }
        if r.sub_results:
            d['sub_results'] = [result_to_dict(sub) for sub in r.sub_results]
        return d

    # Calculate scores
    scores = calculate_scores(results)

    output = {
        'domain': domain,
        'score': {
            'overall': scores['overall'],
            'max': scores['max'],
            'risk_level': scores['risk_level'],
            'categories': {
                cat: {
                    'score': data['score'],
                    'max': data['max'],
                }
                for cat, data in scores['categories'].items()
            }
        },
        'results': [result_to_dict(r) for r in results],
        'summary': {
            'passed': sum(1 for r in results if r.status == Status.PASS),
            'warnings': sum(1 for r in results if r.status == Status.WARN),
            'failed': sum(1 for r in results if r.status == Status.FAIL),
            'info': sum(1 for r in results if r.status == Status.INFO),
        }
    }

    return json.dumps(output, indent=2)


@click.command()
@click.argument('domain')
@click.option('-s', '--dkim-selector', 'dkim_selectors', multiple=True,
              help='Additional DKIM selector(s) to check')
@click.option('--timeout', default=10, type=int, show_default=True,
              help='Connection timeout in seconds')
@click.option('--no-network', is_flag=True,
              help='Skip network checks (STARTTLS, blacklists)')
@click.option('--no-color', is_flag=True,
              help='Disable colored output')
@click.option('--json', 'output_json', is_flag=True,
              help='Output as JSON')
@click.option('-v', '--verbose', is_flag=True,
              help='Show verbose output')
@click.option('-q', '--quiet', is_flag=True,
              help='Only output exit code')
def main(domain: str, dkim_selectors: tuple, timeout: int, no_network: bool,
         no_color: bool, output_json: bool, verbose: bool, quiet: bool):
    """Check email configuration for a DOMAIN.

    Validates MX, SPF, DKIM, DMARC, PTR, MTA-STS, TLS-RPT, BIMI,
    STARTTLS support, and blacklist status.

    DOMAIN can be a domain name, email address, or URL.

    Examples:

        emailcheck.py example.com

        emailcheck.py user@example.com

        emailcheck.py https://example.com

        emailcheck.py -s google -s mailchimp example.com

        emailcheck.py --json example.com

        emailcheck.py --no-network example.com
    """
    # Extract domain from input
    domain = extract_domain(domain)

    if not domain or '.' not in domain:
        click.echo("Error: Invalid domain", err=True)
        sys.exit(2)

    # Combine default and custom selectors
    selectors = list(DEFAULT_DKIM_SELECTORS)
    for s in dkim_selectors:
        if s not in selectors:
            selectors.insert(0, s)

    results = []

    # Infrastructure identification
    results.append(check_common_records(domain))

    # DNS checks (always run)
    results.append(check_mx(domain))
    results.append(check_spf(domain))
    results.append(check_dkim(domain, selectors))
    results.append(check_dmarc(domain))
    results.append(check_ptr(domain))
    results.append(check_mta_sts(domain))
    results.append(check_tls_rpt(domain))
    results.append(check_bimi(domain))

    # Network checks (optional)
    if not no_network:
        results.append(check_starttls(domain, timeout))
        results.append(check_blacklists(domain))

    # Output
    if quiet:
        pass  # No output
    elif output_json:
        click.echo(format_results_json(results, domain))
    else:
        click.echo(format_results_table(results, domain, no_color))

    # Exit code
    failed = sum(1 for r in results if r.status == Status.FAIL)
    if failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
