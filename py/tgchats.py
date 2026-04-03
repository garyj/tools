#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "click",
#     "telethon",
#     "questionary",
# ]
# ///
"""Clean up empty and dead Telegram chats."""

import asyncio
import os

import click
import questionary
from telethon import TelegramClient
from telethon.tl.types import MessageService, User


SESSION_DIR = os.path.join(click.get_app_dir("tgcleanup"), "session")


async def run(api_id: int, api_hash: str, dry_run: bool, empty_only: bool) -> None:
    os.makedirs(os.path.dirname(SESSION_DIR), exist_ok=True)
    client = TelegramClient(SESSION_DIR, api_id, api_hash)
    await client.start()

    click.echo("Loading chats…")
    dialogs = await client.get_dialogs()
    user_dialogs = [d for d in dialogs if isinstance(d.entity, User) and not d.entity.bot]

    empty = []
    deleted_accts = []
    other = []

    click.echo("Checking chat histories…")
    for i, d in enumerate(user_dialogs, 1):
        if i % 50 == 0:
            click.echo(f"  [{i}/{len(user_dialogs)}] checked…")

        if d.entity.deleted:
            deleted_accts.append(d)
            continue

        # Check if chat has any real (non-service) messages
        has_real_message = False
        async for msg in client.iter_messages(d, limit=5):
            if not isinstance(msg, MessageService):
                has_real_message = True
                break

        if not has_real_message:
            empty.append(d)
        else:
            other.append(d)

    click.echo(f"\nFound {len(user_dialogs)} user chats:")
    click.echo(f"  • {len(deleted_accts)} deleted accounts")
    click.echo(f"  • {len(empty)} empty chats (no messages)")
    click.echo(f"  • {len(other)} active chats")

    # Auto-select deleted accounts and empty chats
    auto_selected = deleted_accts + empty

    if auto_selected:
        click.echo(f"\n--- Deleted accounts & empty chats ({len(auto_selected)}) ---")
        for d in auto_selected:
            tag = "[deleted]" if d.entity.deleted else "[empty]"
            name = d.name or f"User #{d.entity.id}"
            click.echo(f"  {tag} {name}")

    if empty_only:
        to_delete = auto_selected
    else:
        # Let user also pick from remaining chats
        if other:
            other.sort(key=lambda d: d.name.lower())
            choices = [
                questionary.Choice(
                    title=f"{d.name}  |  last: {d.date.strftime('%Y-%m-%d') if d.date else '?'}",
                    value=d,
                )
                for d in other
            ]
            click.echo(f"\n--- Other chats ({len(other)}) ---")
            extra = await questionary.checkbox(
                "Also delete any of these? (space = toggle, enter = confirm):",
                choices=choices,
            ).ask_async()
            to_delete = auto_selected + (extra or [])
        else:
            to_delete = auto_selected

    if not to_delete:
        click.echo("\nNothing to clean up.")
        await client.disconnect()
        return

    click.echo(f"\nWill delete {len(to_delete)} chat(s).")

    if not dry_run:
        if not await questionary.confirm("Proceed?", default=False).ask_async():
            click.echo("Aborted.")
            await client.disconnect()
            return

        for d in to_delete:
            try:
                await client.delete_dialog(d)
                name = d.name or f"User #{d.entity.id}"
                click.echo(f"  ✓ Deleted chat with {name}")
            except Exception as e:
                click.echo(f"  ✗ Failed for {d.name}: {e}")

        click.echo(f"\nDone — cleaned up {len(to_delete)} chat(s).")
    else:
        click.echo("(dry run — nothing deleted)")

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
@click.option("--empty-only", is_flag=True, help="Only delete empty chats and deleted accounts, skip interactive selection.")
def main(api_id: int, api_hash: str, dry_run: bool, empty_only: bool) -> None:
    """Clean up empty and dead Telegram chats."""
    asyncio.run(run(api_id, api_hash, dry_run, empty_only))


if __name__ == "__main__":
    main()
