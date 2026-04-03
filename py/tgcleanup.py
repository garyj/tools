#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "click",
#     "telethon",
#     "questionary",
# ]
# ///
"""Bulk unsubscribe from Telegram channels and supergroups."""

import asyncio
import os

import click
import questionary
from telethon import TelegramClient
from telethon.tl.functions.channels import LeaveChannelRequest
from telethon.tl.types import Channel


SESSION_DIR = os.path.join(click.get_app_dir("tgcleanup"), "session")


async def run(api_id: int, api_hash: str, dry_run: bool) -> None:
    os.makedirs(os.path.dirname(SESSION_DIR), exist_ok=True)
    client = TelegramClient(SESSION_DIR, api_id, api_hash)
    await client.start()

    click.echo("Fetching your channels…")
    dialogs = await client.get_dialogs()
    channels = [
        d for d in dialogs if isinstance(d.entity, Channel) and not d.entity.creator
    ]

    if not channels:
        click.echo("No channels found (you're already clean!).")
        await client.disconnect()
        return

    channels.sort(key=lambda d: d.name.lower())

    choices = []
    for d in channels:
        parts = [d.name]
        if d.entity.username:
            parts.append(f"@{d.entity.username}")
        members = d.entity.participants_count
        parts.append(f"{members:,} members" if members else "? members")
        if d.date:
            parts.append(f"last active: {d.date.strftime('%Y-%m-%d')}")
        choices.append(questionary.Choice(title="  |  ".join(parts), value=d))

    selected = await questionary.checkbox(
        "Select channels to LEAVE (space = toggle, enter = confirm):",
        choices=choices,
    ).ask_async()

    if not selected:
        click.echo("Nothing selected — no changes made.")
        await client.disconnect()
        return

    click.echo(f"\nYou selected {len(selected)} channel(s) to leave:")
    for d in selected:
        click.echo(f"  • {d.name}")

    if not dry_run:
        if not await questionary.confirm("Proceed?", default=False).ask_async():
            click.echo("Aborted.")
            await client.disconnect()
            return

        for d in selected:
            try:
                await client(LeaveChannelRequest(d.entity))
                click.echo(f"  ✓ Left {d.name}")
            except Exception as e:
                click.echo(f"  ✗ Failed to leave {d.name}: {e}")
    else:
        click.echo("(dry run — no channels were left)")

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
@click.option("--dry-run", is_flag=True, help="Show what would be left without actually leaving.")
def main(api_id: int, api_hash: str, dry_run: bool) -> None:
    """Bulk unsubscribe from Telegram channels."""
    asyncio.run(run(api_id, api_hash, dry_run))


if __name__ == "__main__":
    main()
