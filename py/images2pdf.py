#!/usr/bin/env -S uv run
"""
Convert JPEG/JPG images to PDF with 4 images per page.

Usage:
    uv run images2pdf.py                     # Process current directory
    uv run images2pdf.py -o output.pdf       # Specify output file
    uv run images2pdf.py -d /path/to/images  # Specify image directory
    uv run images2pdf.py --help              # Show all options

Images are arranged alphabetically, 4 per page in a 2x2 grid.
Supports .jpg/.jpeg files in any case (JPG, JPEG, jpg, jpeg).
"""
#
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "Pillow",
#   "reportlab",
#   "click",
#   "tqdm",
# ]
# ///

import os
import sys
from pathlib import Path
import click
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from tqdm import tqdm
import tempfile


def get_image_files(directory):
    """Get all JPEG/JPG image files in the directory, sorted alphabetically."""
    extensions = [".jpg", ".jpeg", ".JPG", ".JPEG", ".Jpg", ".Jpeg"]
    image_files = []

    for file in sorted(os.listdir(directory)):
        if any(file.endswith(ext) for ext in extensions):
            image_files.append(os.path.join(directory, file))

    return sorted(image_files)


def resize_image_to_fit(img, max_width, max_height):
    """Calculate dimensions to fit image within max bounds while maintaining aspect ratio."""
    img_width, img_height = img.size

    # Calculate scale factor to fit within bounds
    width_scale = max_width / img_width
    height_scale = max_height / img_height
    scale = min(width_scale, height_scale)

    new_width = img_width * scale
    new_height = img_height * scale

    return new_width, new_height


@click.command()
@click.option(
    "-d",
    "--directory",
    default=".",
    help="Directory containing images (default: current directory)",
)
@click.option(
    "-o",
    "--output",
    default="output.pdf",
    help="Output PDF filename (default: output.pdf)",
)
@click.option(
    "--page-size",
    type=click.Choice(["letter", "a4"]),
    default="a4",
    help="Page size (default: a4)",
)
@click.option(
    "--margin", default=0.5, type=float, help="Page margin in inches (default: 0.5)"
)
@click.option(
    "--spacing",
    default=0.25,
    type=float,
    help="Spacing between images in inches (default: 0.25)",
)
def create_pdf(directory, output, page_size, margin, spacing):
    """Convert JPEG/JPG images in a directory to PDF with 4 images per page."""

    # Get all image files
    image_files = get_image_files(directory)

    if not image_files:
        click.echo(f"❌ No JPEG/JPG images found in {directory}", err=True)
        click.echo("   Looking for: *.jpg, *.jpeg, *.JPG, *.JPEG", err=True)
        sys.exit(1)

    click.echo(f"📸 Found {len(image_files)} images to process")
    click.echo(f"📄 Output: {output}")
    click.echo(f"📐 Page size: {page_size}, Margin: {margin}″, Spacing: {spacing}″")
    click.echo()

    # Set page size
    if page_size == "letter":
        page_width, page_height = letter
    else:
        page_width, page_height = A4

    # Calculate layout dimensions
    margin_pts = margin * inch
    spacing_pts = spacing * inch

    # 2x2 grid layout
    usable_width = page_width - (2 * margin_pts)
    usable_height = page_height - (2 * margin_pts)

    img_max_width = (usable_width - spacing_pts) / 2
    img_max_height = (usable_height - spacing_pts) / 2

    # Create PDF
    c = canvas.Canvas(output, pagesize=(page_width, page_height))

    # Calculate total pages
    total_pages = (len(image_files) + 3) // 4

    # Process images with progress bar
    with tqdm(total=len(image_files), desc="Processing images", unit="img") as pbar:
        # Process images in groups of 4
        for page_num, i in enumerate(range(0, len(image_files), 4)):
            if page_num > 0:
                c.showPage()

            page_images = image_files[i : i + 4]

            # Update progress bar description with page info
            pbar.set_description(f"Creating page {page_num + 1}/{total_pages}")

            for idx, img_path in enumerate(page_images):
                try:
                    # Open and process image
                    img = Image.open(img_path)

                    # Convert RGBA to RGB if necessary
                    if img.mode in ("RGBA", "P"):
                        rgb_img = Image.new("RGB", img.size, (255, 255, 255))
                        if img.mode == "RGBA":
                            rgb_img.paste(img, mask=img.split()[3])
                        else:
                            rgb_img.paste(img)
                        img = rgb_img

                    # Calculate position in grid (0=top-left, 1=top-right, 2=bottom-left, 3=bottom-right)
                    col = idx % 2
                    row = idx // 2

                    # Calculate image dimensions to fit in the cell
                    new_width, new_height = resize_image_to_fit(
                        img, img_max_width, img_max_height
                    )

                    # Calculate position (origin is bottom-left in reportlab)
                    x = margin_pts + col * (img_max_width + spacing_pts)
                    y = (
                        page_height
                        - margin_pts
                        - (row + 1) * (img_max_height + spacing_pts)
                        + (img_max_height - new_height)
                    )

                    # Save image to temporary file for reportlab
                    with tempfile.NamedTemporaryFile(
                        suffix=".jpg", delete=False
                    ) as tmp:
                        img.save(tmp.name, "JPEG", quality=85)
                        tmp_path = tmp.name

                    # Draw image using file path instead of PIL object
                    c.drawImage(tmp_path, x, y, width=new_width, height=new_height)

                    # Clean up temp file
                    os.unlink(tmp_path)

                    # Add filename as caption (optional, small text below image)
                    c.setFont("Helvetica", 8)
                    caption = os.path.basename(img_path)
                    if len(caption) > 30:
                        caption = caption[:27] + "..."
                    c.drawString(x, y - 10, caption)

                    # Update progress bar
                    pbar.update(1)

                except Exception as e:
                    click.echo(f"\n⚠️  Error processing {img_path}: {str(e)}", err=True)
                    pbar.update(1)
                    continue

            # Add page number
            c.setFont("Helvetica", 10)
            page_text = f"Page {page_num + 1}"
            c.drawString(page_width / 2 - 20, margin_pts / 2, page_text)

    # Save PDF with progress indication
    pbar.set_description("Saving PDF")
    c.save()

    click.echo()
    click.echo(f"✅ PDF created successfully: {output}")
    click.echo(f"📊 Total pages: {total_pages}")
    click.echo(f"🖼️  Images processed: {len(image_files)}")


if __name__ == "__main__":
    create_pdf()
