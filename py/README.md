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
