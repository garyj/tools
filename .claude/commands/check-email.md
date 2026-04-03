---
description: Check email configuration for a domain and provide actionable fixes
arguments:
  - name: domain
    description: Domain name, email address, or URL to check
    required: true
---

# Check Email Configuration

Analyze email deliverability configuration for a domain and provide actionable recommendations.

## Workflow

1. **Run the email checker script**

   ```bash
   uv run py/emailcheck.py --json $ARGUMENTS
   ```

2. **Parse the JSON output and analyze results**
   - Check the overall score and risk level (Low ≥80, Moderate 60-79, High <60)
   - Review category scores: Impersonation (50 pts), Privacy (25 pts), Deliverability (25 pts)
   - Note the detected DNS and email providers for context-specific recommendations
   - Identify all checks with FAIL or WARN status

3. **Generate actionable recommendations**

   For each issue found, provide specific remediation steps:

   ### MX Records Issues

   - **FAIL: No MX records** → Add MX record pointing to your mail server: `example.com. IN MX 10 mail.example.com.`
   - **FAIL: MX doesn't resolve** → Ensure MX hostname has valid A record
   - **WARN: A record fallback** → Add explicit MX record for proper mail routing

   ### SPF Issues

   - **FAIL: No SPF record** → Add TXT record: `v=spf1 include:_spf.yourprovider.com -all`
   - **FAIL: Too many DNS lookups** → Flatten SPF record by replacing `include:` with IP ranges, or use SPF flattening service
   - **FAIL: Invalid syntax** → Check SPF record syntax at dmarcian.com/spf-syntax-table/
   - **FAIL: +all mechanism** → CRITICAL: Change `+all` to `-all` immediately. `+all` allows anyone to send as your domain.
   - **WARN: ~all (soft fail)** → Upgrade to `-all` (hard fail) for stronger protection once you've verified all legitimate senders are included
   - **WARN: ?all (neutral)** → Change to `-all` or at minimum `~all` to provide some protection
   - **WARN: Approaching lookup limit** → Consider consolidating `include:` mechanisms

   ### DKIM Issues

   - **FAIL: No DKIM selectors found** → Enable DKIM signing in your email provider and publish the public key
   - **WARN: Some selectors missing** → This is often OK if at least one valid selector exists
   - **WARN: Weak key (512-bit)** → Rotate to 2048-bit DKIM key for stronger security

   ### DMARC Issues

   - **FAIL: No DMARC record** → Add TXT record at `_dmarc.domain.com`: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`
   - **WARN: p=none policy** → After monitoring reports (2-4 weeks), upgrade to `p=quarantine` then `p=reject`
   - **WARN: pct < 100** → Gradual rollout is OK, but plan to increase to `pct=100` once stable
   - **WARN: rua self-only** → Consider adding a third-party DMARC monitoring service (e.g., Valimail, Postmark DMARC) to the `rua` tag for better visibility
   - **INFO: ruf not configured** → Optional: Add `ruf=mailto:...` for forensic failure reports (note: many providers don't send these)

   ### PTR/Reverse DNS Issues

   - **FAIL: No PTR record** → Contact your hosting provider to set up reverse DNS for mail server IP
   - **WARN: FCrDNS mismatch** → Ensure PTR hostname resolves back to the same IP (Forward-Confirmed reverse DNS)

   ### MTA-STS Issues

   - **INFO: Not configured** → Optional but recommended for enforcing TLS:
     1. Add DNS TXT record: `_mta-sts.domain.com` → `v=STSv1; id=YYYYMMDDHHMMSS`
     2. Host policy file at `https://mta-sts.domain.com/.well-known/mta-sts.txt`
   - **WARN: mode=testing** → Change policy mode to `enforce` after testing

   ### TLS-RPT Issues

   - **INFO: Not configured** → Optional: Add TXT record at `_smtp._tls.domain.com`: `v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com`

   ### STARTTLS Issues

   - **FAIL: Not offered** → Configure mail server to support STARTTLS
   - **WARN: Old TLS version** → Upgrade server to support TLS 1.2 or 1.3, disable TLS 1.0/1.1

   ### Blacklist Issues

   - **FAIL: IP blacklisted** → Check the specific blacklist for delisting instructions. Common delisting URLs:
     - Spamhaus: <https://check.spamhaus.org/>
     - Barracuda: <https://www.barracudacentral.org/lookups/lookup-reputation>
     - SpamCop: <https://www.spamcop.net/bl.shtml>

   ### BIMI Issues

   - **INFO: Not configured** → Optional brand enhancement. Requires DMARC p=quarantine or p=reject first.
   - **WARN: No logo URL** → Add `l=https://example.com/logo.svg` to BIMI record
   - **WARN: Logo not SVG** → BIMI requires SVG Tiny PS format logos
   - **INFO: No VMC** → Verified Mark Certificate is optional but increases trust (Gmail requires VMC)

## Output Format

```text
## Email Configuration Analysis: {domain}

### Score: XX/100 - {Risk Level}

| Category | Score | Checks |
|----------|-------|--------|
| Impersonation | XX/50 | DMARC, SPF, DKIM |
| Privacy | XX/25 | MTA-STS, TLS-RPT, STARTTLS |
| Deliverability | XX/25 | MX, PTR, Blacklists |

### Infrastructure
- **DNS Provider**: {provider or "Unknown"}
- **Email Provider**: {provider or "Unknown"}

### Critical Issues (Must Fix)
- [ ] **Issue 1**: Description
  - **Action**: Specific steps to fix

### Warnings (Should Fix)
- [ ] **Issue 2**: Description
  - **Action**: Specific steps to fix

### Recommendations (Nice to Have)
- [ ] **Issue 3**: Description
  - **Action**: Specific steps to fix

### DNS Records to Add/Modify

```dns
; SPF Record (if needed)
domain.com. IN TXT "v=spf1 ... -all"

; DMARC Record (if needed)
_dmarc.domain.com. IN TXT "v=DMARC1; p=none; rua=mailto:..."
```
```

## Priority Order

1. **Critical** (blocks email delivery): Missing MX, SPF syntax errors, +all in SPF, blacklisted IPs
2. **High** (causes spam filtering): Missing DMARC, p=none DMARC, missing DKIM, PTR issues, ~all or ?all in SPF
3. **Medium** (security/compliance): No MTA-STS, old TLS versions, pct<100, self-only rua
4. **Low** (optional enhancements): BIMI, TLS-RPT, ruf configuration

## Score Interpretation

- **80-100 (Low Risk)**: Excellent configuration, well-protected against spoofing
- **60-79 (Moderate Risk)**: Good foundation but improvements needed for full protection
- **0-59 (High Risk)**: Significant gaps, domain is vulnerable to spoofing/phishing
