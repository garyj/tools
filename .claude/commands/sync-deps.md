# Sync Dependencies

Ensure dependencies are synchronized between `pyproject.toml` and PEP 723 inline script metadata.

## Workflow

1. **Extract PEP 723 dependencies from all scripts**
   - Read all Python files in `py/` directory
   - Parse the `# /// script` metadata blocks
   - Extract the `dependencies` list from each script

2. **Read pyproject.toml dependencies**
   - Parse the `[project]` section
   - Extract the `dependencies` list

3. **Compare and report**
   - List all unique dependencies across all scripts
   - Compare with pyproject.toml dependencies
   - Report any discrepancies:
     - Dependencies in scripts but missing from pyproject.toml
     - Dependencies in pyproject.toml but not used by any script
     - Version mismatches between script and pyproject.toml

4. **Fix discrepancies**
   - If there are missing dependencies in pyproject.toml, add them
   - Preserve version constraints from scripts (use the most restrictive)
   - Run `uv sync` after updating pyproject.toml

## Output Format

```
=== Dependency Sync Check ===

Scripts analyzed:
  - py/genimg.py: click, google-genai>=1.0.0, pillow, python-dotenv
  - py/images2pdf.py: click, pillow, reportlab, tqdm
  - py/mail.py: click
  - py/mfields.py: click, pymongo, python-dotenv, tabulate

Combined script dependencies:
  click, google-genai>=1.0.0, pillow, pymongo, python-dotenv, reportlab, tabulate, tqdm

pyproject.toml dependencies:
  click, google-genai>=1.0.0, pillow, pymongo, python-dotenv, reportlab, tabulate, tqdm

Status: ✓ In sync / ✗ Out of sync

[If out of sync, list specific issues and offer to fix]
```
