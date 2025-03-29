#!/usr/bin/env -S uv run
# A simple Python mail tool similar to Linux mail command
#
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "click",
# ]
# ///

import sys
import smtplib
import click
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

@click.command()
@click.option('-s', '--subject', default='', help='Subject of the email')
@click.option('-h', '--host', required=True, help='SMTP server hostname')
@click.option('-p', '--port', default=25, type=int, help='SMTP server port')
@click.option('-f', '--from', 'from_addr', required=True, help='From email address')
@click.option('-t', '--to', 'to_addr', required=True, help='To email address')
@click.option('--ssl', is_flag=True, help='Use SSL connection')
@click.option('--tls', is_flag=True, help='Use TLS connection')
@click.option('-u', '--username', help='SMTP username for authentication')
@click.option('-pw', '--password', help='SMTP password for authentication')
def mail(subject, host, port, from_addr, to_addr, ssl, tls, username, password):
    """A simple mail command line tool to send emails, similar to the Linux mail command."""
    # Read email body from stdin
    body = sys.stdin.read()

    # Create email message
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        if ssl:
            server = smtplib.SMTP_SSL(host, port)
        else:
            server = smtplib.SMTP(host, port)

        server.ehlo()

        if tls:
            server.starttls()
            server.ehlo()

        # Login if credentials are provided
        if username and password:
            server.login(username, password)

        # Send email
        server.sendmail(from_addr, to_addr.split(','), msg.as_string())
        server.quit()

        click.echo(f"Email sent successfully to {to_addr}")
    except Exception as e:
        click.echo(f"Failed to send email: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    mail()
