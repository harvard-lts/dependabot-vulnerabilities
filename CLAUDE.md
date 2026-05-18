# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

Single-script tool that queries the GitHub Dependabot Alerts API across every repo in an organization and emits a CSV of open `critical`/`high` vulnerabilities, one row per repo. Targets either github.com (`harvard-lts` org) or the Harvard HUIT Enterprise GitHub instance (`LTS` org) via the `--huit` flag.

## Commands

```bash
# Setup (one-time)
python3.11 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
cp env-example .env   # then populate tokens

# Run against github.com / harvard-lts
source myenv/bin/activate
python dependabot_vulnerabilities.py > YYYY-MM-DD-lts.csv

# Run against HUIT Enterprise / LTS
python dependabot_vulnerabilities.py --huit > YYYY-MM-DD-huit.csv
```

There are no tests, lint config, or build step.

## Architecture

`dependabot_vulnerabilities.py` defines `DependabotFinder(org)`. The `org` string (`harvard-lts` or `LTS`) is used as a **prefix into `.env`** — the class reads `{org}.GITHUB_TOKEN`, `{org}.URL_REPOS`, `{org}.URL_ALERTS`, `{org}.URL_PROPS`. This is how a single codebase targets two different GitHub hosts (api.github.com vs. github.huit.harvard.edu/api/v3) with different token formats. Adding a new org means adding a new prefixed block to `.env`, not changing code.

URL templates use positional `{}` placeholders that get filled with `org` and (for alerts/props) `repo`. `do_work()` walks all repos, paginates Dependabot alerts via the `Link` header, filters to open critical/high, looks up the repo's `Portfolio` custom property, and prints one CSV row per repo with vulnerabilities.

## Tokens

- github.com: fine-grained PAT with read access to Dependabot alerts, administration, metadata.
- HUIT Enterprise: classic PAT with `repo:all`, `admin:read:org`, `admin:read:enterprise`.
