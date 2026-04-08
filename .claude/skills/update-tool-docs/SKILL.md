---
name: update-tool-docs
description: Update README documentation when tools are added, removed, or modified. Use when the user adds a new script to py/, removes a script, or asks to update/regenerate docs. Updates py/README.md with per-tool documentation and README.md with an alphabetical table of contents.
---

# Update Docs

Update the two README files in this repo to reflect the current set of tools.

## Files to update

1. **`py/README.md`** — detailed per-tool documentation
2. **`README.md`** — project overview with a TOC linking to all tools

## Process

1. Read every `py/*.py` script to extract: name, docstring, PEP 723 metadata, Click options/arguments, and key features.
2. Read the current `py/README.md` and `README.md`.
3. For each new or modified script, generate or update its section in `py/README.md` following the existing format (see below).
4. Remove sections for scripts that no longer exist.
5. Sort all tool sections in `py/README.md` alphabetically by script name.
6. Regenerate the TOC in `README.md` with alphabetical links to each tool's section in `py/README.md`.

## py/README.md format

Keep the existing header and intro, then one section per tool in this format:

```markdown
## scriptname.py

One-line description from the script's docstring.

\`\`\`bash
# Example usage commands using the remote uv run URL pattern:
uv run https://raw.githubusercontent.com/garyj/tools/refs/heads/master/py/scriptname.py [args]
\`\`\`

**Key Features:**

- Feature bullet points derived from the script's capabilities
```

Use the remote `uv run` URL pattern for all example commands. Derive examples from the script's Click options and arguments.

## README.md format

Keep the existing header line, then add an alphabetical tool listing:

```markdown
# Tools

Python, shell, and other tools for day to day tasks, mostly developed with LLMs.

## Python tools

| Tool | Description |
|------|-------------|
| [scriptname.py](py/README.md#scriptnamepy) | One-line description |
```

## Rules

- **Alphabetical order is mandatory** for both the TOC in README.md and the sections in py/README.md.
- Preserve existing documentation style and formatting conventions.
- Do not invent features — only document what the script actually does.
- Use the script's docstring and Click help text as the source of truth.
