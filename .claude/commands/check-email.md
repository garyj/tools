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
   - Identify all checks with FAIL or WARN status
   - Group issues by category (DNS records, server config, reputation)

3. **Generate actionable recommendations**

   For each issue found, provide specific remediation steps:

   ### MX Records Issues
   - **FAIL: No MX records** → Add MX record pointing to your mail server: `example.com. IN MX 10 mail.example.com.`
   - **FAIL: MX doesn't resolve** → Ensure MX hostname has valid A record
   - **WARN: A record fallback** → Add explicit MX record for proper mail routing

   ### SPF Issues
   - **FAIL: No SPF record** → Add TXT record: `v=spf1 include:_spf.yourprovider.com ~all`
   - **FAIL: Too many DNS lookups** → Flatten SPF record by replacing `include:` with IP ranges, or use SPF flattening service
   - **FAIL: Invalid syntax** → Check SPF record syntax at dmarcian.com/spf-syntax-table/
   - **WARN: Approaching lookup limit** → Consider consolidating `include:` mechanisms

   ### DKIM Issues
   - **FAIL: No DKIM selectors found** → Enable DKIM signing in your email provider and publish the public key
   - **WARN: Some selectors missing** → This is often OK if at least one valid selector exists
   - **WARN: Weak key (512-bit)** → Rotate to 2048-bit DKIM key

   ### DMARC Issues
   - **FAIL: No DMARC record** → Add TXT record at `_dmarc.domain.com`: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com`
   - **WARN: p=none policy** → After monitoring reports, upgrade to `p=quarantine` then `p=reject`

   ### PTR/Reverse DNS Issues
   - **FAIL: No PTR record** → Contact your hosting provider to set up reverse DNS for mail server IP
   - **WARN: FCrDNS mismatch** → Ensure PTR hostname resolves back to the same IP

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
     - Spamhaus: https://check.spamhaus.org/
     - Barracuda: https://www.barracudacentral.org/lookups/lookup-reputation
     - SpamCop: https://www.spamcop.net/bl.shtml

   ### BIMI Issues
   - **INFO: Not configured** → Optional brand enhancement. Requires DMARC p=quarantine or p=reject first.

## Output Format

```
## Email Configuration Analysis: {domain}

### Summary
- X passed, Y warnings, Z failures

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
domain.com. IN TXT "v=spf1 ... ~all"

; DMARC Record (if needed)
_dmarc.domain.com. IN TXT "v=DMARC1; p=none; rua=mailto:..."
```
```

## Priority Order

1. **Critical** (blocks email delivery): Missing MX, SPF syntax errors, blacklisted IPs
2. **High** (causes spam filtering): Missing DMARC, weak DMARC policy, missing DKIM, PTR issues
3. **Medium** (security/compliance): No MTA-STS, old TLS versions
4. **Low** (optional enhancements): BIMI, TLS-RPT
