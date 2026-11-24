# SQLMap Scout

A terminal-first reconnaissance crawler that finds parameterized URLs and dynamic forms on an authorized target.

## Landing page

Open `index.html` directly or serve it locally:

```bash
python -m http.server 4173
```

Visit `http://localhost:4173`.

## Install

```bash
pip install rich
```

## Run

```bash
python sqlmap_scout.py -u https://example.com --max-depth 2 --max-pages 80 --concurrency 6 --auto-export
python sqlmap_scout.py -u https://example.com --max-pages 80 --auto-export

```

```bash

python sqlmap_scout.py -u https://example.com --max-pages 80 --auto-export

python sqlmap_scout.py -u https://example.com --max-pages 80 --links-only

python sqlmap_scout.py -u https://example.com --max-pages 80 --with-commands


```
<img width="653" height="1104" alt="image" src="https://github.com/user-attachments/assets/258c9fb2-dd62-40cb-9b41-f8a0d2d75eef" />

Use SQLMap Scout only against systems you own or have explicit permission to test.
