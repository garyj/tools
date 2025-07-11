# Python scripts

These scripts can be run on their own or using `uv run`. Scripts should use inline metadata [PEP 723](https://peps.python.org/pep-0723/)

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
