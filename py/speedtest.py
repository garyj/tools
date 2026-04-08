#!/usr/bin/env -S uv run
"""
Run internet speed tests (download/upload) using Cloudflare's speed test endpoints.

Usage:
    uv run speedtest.py
    uv run speedtest.py --download-only
    uv run speedtest.py --upload-only
    uv run speedtest.py --json
"""
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "click",
#   "requests",
# ]
# ///

import json as json_lib
import time

import click
import requests

CLOUDFLARE_DOWN = "https://speed.cloudflare.com/__down"
CLOUDFLARE_UP = "https://speed.cloudflare.com/__up"


def measure_download(size_bytes=50_000_000):
    """Download from Cloudflare and return speed in bits per second."""
    start = time.perf_counter()
    resp = requests.get(CLOUDFLARE_DOWN, params={"bytes": size_bytes}, stream=True)
    received = 0
    for chunk in resp.iter_content(chunk_size=65536):
        received += len(chunk)
    elapsed = time.perf_counter() - start
    return (received * 8) / elapsed


def measure_upload(size_bytes=10_000_000):
    """Upload to Cloudflare and return speed in bits per second."""
    data = b"0" * size_bytes
    start = time.perf_counter()
    requests.post(CLOUDFLARE_UP, data=data, headers={"Content-Type": "application/octet-stream"})
    elapsed = time.perf_counter() - start
    return (size_bytes * 8) / elapsed


def measure_latency(samples=5):
    """Measure latency to Cloudflare in milliseconds."""
    times = []
    for _ in range(samples):
        start = time.perf_counter()
        requests.get(CLOUDFLARE_DOWN, params={"bytes": 0})
        times.append((time.perf_counter() - start) * 1000)
    return min(times)


def format_speed(bps):
    """Format bits per second as human-readable string."""
    mbps = bps / 1_000_000
    mbytes = mbps / 8
    if mbps >= 1000:
        return f"{mbps / 1000:.2f} Gbps ({mbytes:.2f} MB/s)"
    return f"{mbps:.2f} Mbps ({mbytes:.2f} MB/s)"


@click.command()
@click.option("--download-only", is_flag=True, help="Only test download speed.")
@click.option("--upload-only", is_flag=True, help="Only test upload speed.")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.option("--size", default=50, help="Download test size in MB (default: 50, max: 50).")
@click.option("--upload-size", default=10, help="Upload test size in MB (default: 10).")
def main(download_only, upload_only, as_json, size, upload_size):
    """Run internet speed tests using Cloudflare's network."""
    results = {}

    click.echo("Testing latency...", nl=False)
    latency = measure_latency()
    click.echo(f"\rLatency:  {latency:.2f} ms")
    results["latency_ms"] = round(latency, 2)

    if not upload_only:
        click.echo("Testing download...", nl=False)
        down = measure_download(size * 1_000_000)
        click.echo(f"\rDownload: {format_speed(down)}")
        results["download_mbps"] = round(down / 1_000_000, 2)

    if not download_only:
        click.echo("Testing upload...", nl=False)
        up = measure_upload(upload_size * 1_000_000)
        click.echo(f"\rUpload:   {format_speed(up)}")
        results["upload_mbps"] = round(up / 1_000_000, 2)

    if as_json:
        click.echo(json_lib.dumps(results, indent=2))


if __name__ == "__main__":
    main()
