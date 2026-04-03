#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "click",
#     "telethon",
# ]
# ///
"""Delete all 'X joined Telegram' service messages."""

import asyncio
import os

import click
from telethon import TelegramClient
from telethon.tl.types import MessageActionContactSignUp, MessageService, User


SESSION_DIR = os.path.join(click.get_app_dir("tgcleanup"), "session")


async def run(api_id: int, api_hash: str, dry_run: bool) -> None:
    os.makedirs(os.path.dirname(SESSION_DIR), exist_ok=True)
    client = TelegramClient(SESSION_DIR, api_id, api_hash)
    await client.start()

    click.echo("Loading dialogs…")
    dialogs = await client.get_dialogs()
    user_dialogs = [d for d in dialogs if isinstance(d.entity, User)]
    click.echo(f"Scanning {len(user_dialogs)} user chats (skipping groups/channels)…")

    found = []
    for i, dialog in enumerate(user_dialogs, 1):
        if i % 50 == 0 or i == len(user_dialogs):
            click.echo(f"  [{i}/{len(user_dialogs)}] scanned…", nl=False)
            click.echo()

        async for msg in client.iter_messages(dialog, limit=None):
            if isinstance(msg, MessageService) and isinstance(
                msg.action, MessageActionContactSignUp
            ):
                found.append((dialog, msg))
                break  # only one per contact

    if not found:
        click.echo("No 'joined Telegram' messages found.")
        await client.disconnect()
        return

    click.echo(f"\nFound {len(found)} 'joined Telegram' message(s):")
    for dialog, _msg in found:
        click.echo(f"  • {dialog.name}")

    if dry_run:
        click.echo("\n(dry run — nothing deleted)")
    else:
        click.echo()
        for dialog, msg in found:
            try:
                await msg.delete()
                click.echo(f"  ✓ Deleted in {dialog.name}")
            except Exception as e:
                click.echo(f"  ✗ Failed in {dialog.name}: {e}")
        click.echo(f"\nDone — deleted {len(found)} message(s).")

    await client.disconnect()


@click.command()
@click.option(
    "--api-id",
    type=int,
    envvar="TELEGRAM_API_ID",
    required=True,
    help="Telegram API ID (or set TELEGRAM_API_ID env var).",
)
@click.option(
    "--api-hash",
    envvar="TELEGRAM_API_HASH",
    required=True,
    help="Telegram API hash (or set TELEGRAM_API_HASH env var).",
)
@click.option("--dry-run", is_flag=True, help="Show what would be deleted without deleting.")
def main(api_id: int, api_hash: str, dry_run: bool) -> None:
    """Delete all 'X joined Telegram' service messages."""
    asyncio.run(run(api_id, api_hash, dry_run))


if __name__ == "__main__":
    main()
