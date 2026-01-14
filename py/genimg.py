#!/usr/bin/env -S uv run
"""
Generate images from text prompts using Google Gemini.

Usage:
    uv run genimg.py "A cat wearing a tiny hat"
    uv run genimg.py "A sunset" -o sunset.png
    uv run genimg.py "A landscape" --aspect-ratio 16:9
"""
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "click",
#   "google-genai>=1.0.0",
#   "pillow",
#   "python-dotenv",
# ]
# ///

import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from google import genai
from google.genai import types


def get_api_key():
    """Get API key from environment, trying multiple sources."""
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get(
        "NANOBANANA_GEMINI_API_KEY"
    )
    if not api_key:
        click.secho(
            "Error: No API key found. Set GEMINI_API_KEY or NANOBANANA_GEMINI_API_KEY.",
            fg="red",
        )
        sys.exit(1)
    return api_key


@click.command()
@click.argument("prompt")
@click.option(
    "-o",
    "--output",
    default="generated_image.png",
    help="Output filename (default: generated_image.png)",
)
@click.option(
    "--aspect-ratio",
    type=click.Choice(["1:1", "3:4", "4:3", "9:16", "16:9"]),
    default="1:1",
    help="Image aspect ratio (default: 1:1)",
)
def generate(prompt, output, aspect_ratio):
    """Generate an image from a text PROMPT using Google Gemini."""
    api_key = get_api_key()

    click.echo("Generating image...")
    click.echo(f"Prompt: {prompt[:80]}{'...' if len(prompt) > 80 else ''}")
    click.echo(f"Aspect ratio: {aspect_ratio}")
    click.echo()

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-2.5-flash-image",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_modalities=["IMAGE"],
                image_config=types.ImageConfig(
                    aspect_ratio=aspect_ratio,
                ),
            ),
        )

        # Process response
        image_saved = False
        for part in response.parts:
            if part.text is not None:
                click.echo(f"Model response: {part.text}")
            elif part.inline_data is not None:
                image = part.as_image()
                output_path = Path(output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                image.save(output_path)
                image_saved = True
                click.secho(f"Image saved: {output_path}", fg="green")

        if not image_saved:
            click.secho("Error: No image was generated.", fg="red")
            sys.exit(1)

    except Exception as e:
        click.secho(f"Error: {e}", fg="red")
        sys.exit(1)


if __name__ == "__main__":
    generate()
