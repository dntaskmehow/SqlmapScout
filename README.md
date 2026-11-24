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

```bash

python sqlmap_scout.py -u https://example.com --max-pages 80 --auto-export

python sqlmap_scout.py -u https://example.com --max-pages 80 --links-only

python sqlmap_scout.py -u https://example.com --max-pages 80 --with-commands


```
<img width="653" height="1104" alt="image" src="https://github.com/user-attachments/assets/258c9fb2-dd62-40cb-9b41-f8a0d2d75eef" />

Use SQLMap Scout only against systems you own or have explicit permission to test.
