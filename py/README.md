# Python scripts

These scripts can be run on their own or using `uv run`. Scripts should use inline metadata [PEP 723](https://peps.python.org/pep-0723/)

## emailcheck.py

Email domain configuration checker that validates DNS records and server configuration for email deliverability. Checks MX, SPF, DKIM, DMARC, PTR, MTA-STS, TLS-RPT, BIMI, STARTTLS support, and blacklist status.

```bash
# Basic usage - check a domain
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/emailcheck.py example.com

# Check from email address (extracts domain)
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/emailcheck.py user@example.com

# Check from URL (extracts domain)
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/emailcheck.py https://example.com

# DNS-only checks (skip STARTTLS and blacklist network checks)
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/emailcheck.py --no-network example.com

# JSON output for scripting
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/emailcheck.py --json example.com

# Custom DKIM selectors
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/emailcheck.py -s customselector example.com
```

**Key Features:**

- Validates MX records (existence, resolution, priority)
- SPF validation with DNS lookup count
- DKIM record checks for common selectors (google, selector1, selector2, default, etc.)
- DMARC policy validation (none/quarantine/reject)
- PTR/reverse DNS with FCrDNS verification
- MTA-STS policy fetch and validation
- TLS-RPT record check
- BIMI record check
- STARTTLS support and TLS version on mail servers
- Blacklist/DNSBL checking for MX IPs
- Supports domain, email address, or URL input
- Table or JSON output formats

## genimg.py

Generate images from text prompts using Google Gemini's image generation model.

```bash
# Set your API key
export GOOGLE_API_KEY="your-api-key"

# Basic usage
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/genimg.py \
    "A cat wearing a tiny hat"

# Custom output file
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/genimg.py \
    "A sunset over mountains" -o sunset.png

# Specify aspect ratio (1:1, 3:4, 4:3, 9:16, 16:9)
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/genimg.py \
    "A wide landscape" --aspect-ratio 16:9
```

**Key Features:**

- Uses Google Gemini's "Nano Banana" image generation (`gemini-2.5-flash-image`)
- Supports multiple aspect ratios
- Reads API key from `GOOGLE_API_KEY` or `NANOBANANA_GEMINI_API_KEY`
- Saves as PNG with customizable output path

## images2pdf.py

Convert JPEG/JPG images to PDF with 4 images per page arranged in a 2x2 grid, with filename captions. Useful if you need to present photos at VCAT 🤦‍♂️

```bash
# Process current directory
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/images2pdf.py

# Specify output file
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/images2pdf.py \
    -o photo_album.pdf

# Specify image directory
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/images2pdf.py \
    -d /path/to/images -o output.pdf

# Custom page size and margins
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/images2pdf.py \
    --page-size letter --margin 1.0 --spacing 0.5
```

**Key Features:**

- Processes images alphabetically with 4 per page in 2x2 grid
- Maintains aspect ratios while fitting images to page
- Supports multiple JPEG formats (.jpg/.jpeg in any case)
- Configurable page sizes (letter/A4), margins, and spacing
- Progress bar and filename captions for each image
- Automatic RGB conversion for RGBA/palette images

## mail.py

Simple script that can replace the linux `mail` command to send emails. Useful in shell scripts on servers where it's not practical to install postfix/sendmail.

```bash
# short version (no auth)
echo "email body" | uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mail.py \
    --subject "Subject is here" \
    --host smtp.example.com \
    --from sender@example.com \
    --to recipient@example.com

# long version
echo "email body" | uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mail.py \
    --subject "Subject is here" \
    --host smtp.example.com \
    --from sender@example.com \
    --to recipient@example.com \
    --tls \
    -u USER \
    -pw PASSWORD
```

## mfields.py

MongoDB field analysis tool that scans collections for top-level field coverage statistics. Helps understand schema patterns and field usage across documents.

```bash
# Analyze a specific collection
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mfields.py \
    --mongouri mongodb://localhost:27017/mydb --collection users

# Analyze ALL collections in the database
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mfields.py \
    --mongouri mongodb://localhost:27017/mydb

# Custom sample size and sorting options
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mfields.py \
    -c products -n 5000 --sort name --mongouri $MONGO_URI

# Using environment variable for MongoDB URI
export MONGO_URI=mongodb://localhost:27017/mydb
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mfields.py \
    -c inventory -n 2000 --sort name

# JSON output for version control/automation
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/mfields.py \
    --mongouri $MONGO_URI --format json > field_analysis.json
```

**Key Features:**

- Sample-based analysis for performance on large collections
- Sort by field name or coverage percentage
- Table or JSON output formats
- Support for environment variables
- Analysis of single collection or entire database
