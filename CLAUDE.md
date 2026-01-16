# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A collection of standalone Python utility scripts for day-to-day tasks. Scripts are designed to be runnable both locally and remotely via `uv run <github-url>`.

## Development Commands

```bash
# Sync all dependencies for local development
uv sync

# Run a script locally
uv run py/<script>.py --help

# Check dependency synchronization between pyproject.toml and scripts
/sync-deps
```

## Architecture

**Dual dependency management**: Each script contains PEP 723 inline metadata for remote execution, while `pyproject.toml` consolidates all dependencies for local development. Both must be kept in sync.

**Script structure**: All scripts live in `py/` and follow this pattern:

- Shebang: `#!/usr/bin/env -S uv run`
- PEP 723 metadata block with `requires-python` and `dependencies`
- Click-based CLI interface

## Adding New Scripts

1. Create script in `py/` with PEP 723 inline metadata
2. Add any new dependencies to `pyproject.toml`
3. Run `uv sync` to update lock file
4. Document usage in `py/README.md`
