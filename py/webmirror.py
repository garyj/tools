#!/usr/bin/env -S uv run
# Download an entire JS/SPA website for offline browsing with Playwright.
#
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "playwright>=1.43.0",
#   "click>=8.0.0",
#   "tqdm>=4.0.0",
#   "beautifulsoup4>=4.0.0",
# ]
# ///

import os
import re
import urllib.parse

import click
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from tqdm import tqdm


def parse_proxy(proxy_str):
    """Return dict for Playwright proxy config from a proxy URL."""
    parsed = urllib.parse.urlparse(proxy_str)
    proxy_cfg = {
        "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
    }
    if parsed.username:
        proxy_cfg["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password:
        proxy_cfg["password"] = urllib.parse.unquote(parsed.password)
    print(f"Proxy config: {proxy_cfg}")
    return proxy_cfg


def url_to_path(url, outdir):
    parts = urllib.parse.urlparse(url)
    path = parts.path
    if path.endswith("/"):
        path += "index.html"
    elif "." not in os.path.basename(path):
        path += "/index.html"
    path = path.lstrip("/")
    fs_path = os.path.join(outdir, parts.netloc, path)
    return fs_path


def path_from_url_for_rel(base_url, target_url, outdir):
    src_file = url_to_path(base_url, outdir)
    dst_file = url_to_path(target_url, outdir)
    rel_path = os.path.relpath(dst_file, os.path.dirname(src_file))
    return rel_path


def save_file(url, content, outdir):
    filepath = url_to_path(url, outdir)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(content)
    click.echo(f"Saved {filepath}")


def is_internal(url, allowed_domains):
    parsed = urllib.parse.urlparse(url)
    return (
        parsed.scheme in ("http", "https")
        and parsed.hostname is not None
        and any(
            parsed.hostname == d or parsed.hostname.endswith("." + d)
            for d in allowed_domains
        )
    )


def absolute_url(base, url):
    return urllib.parse.urljoin(base, url)


def crawl(start_urls, outdir, allowed_domains, proxy=None):
    visited_pages = set()
    to_visit = list(start_urls)
    asset_urls = set()
    downloaded_assets = set()
    url_map = {}

    playwright_launch_kwargs = {}
    if proxy:
        proxy_cfg = parse_proxy(proxy)
        playwright_launch_kwargs["proxy"] = proxy_cfg

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, **playwright_launch_kwargs)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        pbar = tqdm(total=0, desc="Pages visited", unit="pages")
        while to_visit:
            url = to_visit.pop(0)
            if url in visited_pages:
                continue
            click.echo(f"==> Visiting {url}")
            try:
                page.goto(url, timeout=30000)
                page.wait_for_load_state("networkidle", timeout=30000)
            except Exception as e:
                click.echo(f"ERROR: {url} {e}", err=True)
                continue
            visited_pages.add(url)
            pbar.total = len(visited_pages)
            htmlbytes = page.content().encode("utf-8")
            save_file(url, htmlbytes, outdir)
            url_map[url] = url_to_path(url, outdir)

            # Discover and queue links to crawl
            anchors = page.query_selector_all("a[href]")
            for a in anchors:
                href = a.get_attribute("href")
                if href and not href.startswith("mailto:"):
                    full = absolute_url(url, href)
                    if (
                        is_internal(full, allowed_domains)
                        and full not in visited_pages
                        and full not in to_visit
                    ):
                        to_visit.append(full)

            # Asset tags
            for tag, attr in [("img", "src"), ("script", "src"), ("link", "href")]:
                for elem in page.query_selector_all(f"{tag}[{attr}]"):
                    ref = elem.get_attribute(attr)
                    if ref:
                        full = absolute_url(url, ref)
                        if full.startswith("http") and is_internal(
                            full, allowed_domains
                        ):
                            asset_urls.add(full)

            # --- Handle srcset in <img> and <source>
            for tag in ["img", "source"]:
                for elem in page.query_selector_all(f"{tag}[srcset]"):
                    srcset = elem.get_attribute("srcset")
                    if srcset:
                        for entry in srcset.split(","):
                            url_part = entry.strip().split()[0]
                            if url_part:
                                full = absolute_url(url, url_part)
                                if full.startswith("http") and is_internal(
                                    full, allowed_domains
                                ):
                                    asset_urls.add(full)

        pbar.close()

        click.echo(f"Downloading {len(asset_urls)} asset files...")
        for asset_url in tqdm(asset_urls, desc="Assets", unit="files"):
            if asset_url in downloaded_assets:
                continue
            try:
                asset_page = context.new_page()
                resp = asset_page.goto(asset_url, timeout=20000)
                if resp and resp.status == 200:
                    body = resp.body()
                    save_file(asset_url, body, outdir)
                else:
                    click.echo(f"Asset download failed: {asset_url}")
                asset_page.close()
            except Exception as e:
                click.echo(f"Asset error: {asset_url} {e}", err=True)
            downloaded_assets.add(asset_url)

        browser.close()
    return url_map


def offline_link_rewrite(url_map, outdir, allowed_domains):
    click.echo("Rewriting internal links for offline navigation...")
    for url, page_path in tqdm(url_map.items(), desc="Rewriting links"):
        if page_path.endswith(".html"):
            with open(page_path, "rb") as f:
                soup = BeautifulSoup(f.read(), "html.parser")

            changed = False
            for tag in soup.find_all(["a", "link", "form", "script", "img"]):
                for attr in ("href", "src", "action"):
                    val = tag.get(attr)
                    if not val or not isinstance(val, str):
                        continue
                    # Ignore non-internal/non-absolute
                    if not val.startswith("/"):
                        continue
                    abs_url = absolute_url(url, val)
                    if is_internal(abs_url, allowed_domains) and abs_url in url_map:
                        rel_path = path_from_url_for_rel(url, abs_url, outdir)
                        tag[attr] = rel_path.replace(os.sep, "/")
                        changed = True
            for tag in soup.find_all(["img", "source"]):
                srcset = tag.get("srcset")
                if srcset:
                    new_entries = []
                    for entry in srcset.split(","):
                        pieces = entry.strip().split()
                        if not pieces:
                            continue
                        url_part = pieces[0]
                        abs_url = absolute_url(url, url_part)
                        if is_internal(abs_url, allowed_domains) and abs_url in url_map:
                            rel_path = path_from_url_for_rel(url, abs_url, outdir)
                            pieces[0] = rel_path.replace(os.sep, "/")
                            changed = True
                        new_entries.append(" ".join(pieces))
                    tag["srcset"] = ", ".join(new_entries)

            if changed:
                with open(page_path, "wb") as f:
                    f.write(soup.encode())
                click.echo(f"Rewrote links in {page_path}")

    click.echo("Rewriting CSS asset links for offline navigation...")
    for asset_url, css_path in tqdm(url_map.items(), desc="CSS rewrite"):
        if not css_path.endswith(".css"):
            continue
        css_rewrite_offline(url_map, css_path, asset_url, outdir, allowed_domains)


def css_rewrite_offline(url_map, css_path, css_url, outdir, allowed_domains):
    url_pattern = re.compile(r'url\(\s*([\'"]?)([^)\'"]+)\1\s*\)')
    try:
        with open(css_path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8")
    except Exception:
        return
    changed = False

    def replacer(m):
        orig_url = m.group(2)
        if orig_url.startswith("data:"):
            return m.group(0)
        abs_url = absolute_url(css_url, orig_url)
        if is_internal(abs_url, allowed_domains) and abs_url in url_map:
            rel_path = os.path.relpath(
                url_map[abs_url], os.path.dirname(css_path)
            ).replace(os.sep, "/")
            nonlocal changed
            changed = True
            return "url('%s')" % rel_path
        else:
            return m.group(0)

    text2 = url_pattern.sub(replacer, text)
    if changed:
        with open(css_path, "w", encoding="utf-8") as f:
            f.write(text2)
        click.echo(f"Rewrote CSS asset links in {css_path}")


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "-d",
    "--domain",
    multiple=True,
    required=True,
    help="Allowed domain for crawling (can repeat).",
)
@click.option(
    "-o",
    "--output",
    default="offline_site",
    show_default=True,
    help="Output directory.",
)
@click.option(
    "-p",
    "--proxy",
    default=None,
    help="Proxy server (http://host:port, socks5://host:port, etc).",
)
@click.argument("start_urls", nargs=-1)
def main(domain, output, proxy, start_urls):
    """
    Download a JS-heavy (SPA) website for offline browsing using Playwright.
    Converts links for file:// navigation.
    """
    allowed_domains = list(domain)
    os.makedirs(output, exist_ok=True)
    if start_urls:
        start_urls = list(start_urls)
    else:
        start_urls = [f"https://{allowed_domains[0]}/"]
    click.echo(f"Allowed domains: {allowed_domains}")
    click.echo(f"Start URLs: {start_urls}")
    click.echo(f"Output directory: {output}")
    if proxy:
        click.echo(f"Using proxy: {proxy}")

    url_map = crawl(start_urls, output, allowed_domains, proxy)
    offline_link_rewrite(url_map, output, allowed_domains)
    click.echo("All done.")


if __name__ == "__main__":
    main()
