# SQLMap Scout

A terminal-based, signal-only web crawler that identifies parameterized URLs and dynamic forms in an authorized target.

## Preview the landing page

Open `index.html` directly in a browser, or serve the branch locally:

```bash
python -m http.server 4173
```

Then visit `http://localhost:4173`.

## Run the crawler

```bash
pip install rich
python sqlmap_scout.py -u https://example.com --max-pages 80 --auto-export
```

Use SQLMap Scout only against systems you own or have explicit permission to test.
