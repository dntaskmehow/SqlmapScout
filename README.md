# SQLMap Scout

> A terminal-first crawler that collects candidate parameterized URLs and form inputs for **authorized security assessments**.

SQLMap Scout follows links on a supplied origin, records query parameters and dynamic-looking paths, and presents crawl activity in a Rich terminal interface. It can export candidate URLs or include command-line suggestions for manual review.

> [!IMPORTANT]
> **Authorization required:** Use SQLMap Scout only on systems you own or have explicit written permission to assess. Crawling sends HTTP requests to the supplied origin. Confirm the approved scope and rate limits before running it.

## What it does

- **Crawls same-origin links** to a configurable depth and page limit.
- **Collects candidate inputs** from query strings and HTML forms; it does not submit form requests.
- **Filters common static assets** such as images, stylesheets, fonts, and media.
- **Shows progress in a terminal UI** with crawl counts, HTTP statuses, and candidate signals.
- **Exports results** as text or JSON, either as links only or with generated SQLMap command suggestions.

These are heuristic candidates, not confirmed vulnerabilities. SQLMap Scout does not run SQLMap or verify that a target is vulnerable. Review all results and generated commands before any further testing.

## Requirements

- Python 3.9 or newer
- [`rich`](https://pypi.org/project/rich/)

## Installation

```bash
git clone https://github.com/dntaskmehow/SqlmapScout.git
cd SqlmapScout
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install rich
```

## Run in an authorized environment

Start with a local lab or another explicitly approved target. Replace the example URL with an origin in your authorized scope:

```bash
python sqlmap_scout.py --url http://127.0.0.1:8000 --max-depth 2 --max-pages 80 --concurrency 6 --auto-export
```

The default export file is `sqlmap_targets.txt`. To choose another output file or JSON format:

```bash
python sqlmap_scout.py --url http://127.0.0.1:8000 --max-pages 40 --out findings.json --auto-export
```

Without `--auto-export`, the interactive terminal waits for Enter after crawling before it exports. Use `--auto-export` for unattended runs.

## Options

| Option | Description |
|---|---|
| `-u`, `--url` | Starting URL; required |
| `--max-depth` | Maximum link depth (default: `2`) |
| `--max-pages` | Maximum pages to crawl (default: `80`) |
| `-c`, `--concurrency` | Concurrent page workers (default: `6`) |
| `-t`, `--timeout` | Request timeout in seconds (default: `6`) |
| `--links-only` | Export candidate links only (default mode) |
| `--with-commands` | Include generated SQLMap command suggestions in the export |
| `-o`, `--out` | Output path; use `.json` for JSON (default: `sqlmap_targets.txt`) |
| `--auto-export` | Export automatically when crawling finishes |

## Output modes

- **Links only** — writes candidate URLs to a text file, or a `links` array in JSON.
- **With commands** — adds candidate details and generated command suggestions to the export. These suggestions are not executed; verify scope and inspect each command before use.

The crawler uses GET requests to fetch pages. It parses forms to identify named inputs but does not submit them. Crawl depth, page count, concurrency, and timeout are operational settings—not authorization or rate-limit safeguards.

## Existing screenshot

<img width="653" height="1104" alt="SQLMap Scout terminal interface" src="https://github.com/user-attachments/assets/258c9fb2-dd62-40cb-9b41-f8a0d2d75eef" />

## Responsible use

1. Confirm written authorization and the exact host and path scope.
2. Check the program's rules for automated crawling and request limits.
3. Prefer a local, disposable test application when learning.
4. Review the source and exported results; treat candidate signals as unverified leads.
5. Stop if the target behaves unexpectedly or the activity exceeds the approved scope.
6. Protect exported files, which may contain sensitive URLs or application details.

## Project status

SQLMap Scout is an early-stage Python CLI project. Its path and form heuristics may miss relevant inputs or produce false positives. Results require manual review; they are not evidence of a vulnerability.

## Source and support

- **Source:** [`sqlmap_scout.py`](sqlmap_scout.py)
- **Issues:** [Report a problem or suggest an improvement](https://github.com/dntaskmehow/SqlmapScout/issues)
- **License:** [MIT](LICENSE)
