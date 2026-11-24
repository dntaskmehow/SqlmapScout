import argparse
import asyncio
import json
import re
import sys
from collections import Counter, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

STATIC_EXTS: Tuple[str, ...] = (
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov", ".webm", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
)

DYNAMIC_PATH_HINTS: Tuple[str, ...] = (
    "/api/", "/graphql", "/search", "/item", "/items", "/product", "/products",
    "/user", "/users", "/profile", "/order", "/orders", "/post", "/posts",
    "/article", "/articles", "/category", "/categories", "/auth", "/login",
)


class PageExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, object]] = []
        self._current_form: Optional[Dict[str, object]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs if k}
        t = tag.lower()
        if t == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"].strip())
        elif t == "form":
            self._current_form = {
                "action": attr_map.get("action", "").strip(),
                "method": (attr_map.get("method", "GET") or "GET").upper(),
                "inputs": [],
            }
        elif t in ("input", "select", "textarea") and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                inputs_list = self._current_form["inputs"]
                if isinstance(inputs_list, list) and name not in inputs_list:
                    inputs_list.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


@dataclass
class SignalTarget:
    url: str
    method: str
    params: List[str]
    post_data: str
    signal_reason: str
    status: str


class SQLMapScoutTUI:
    def __init__(
        self,
        start_url: str,
        max_depth: int = 2,
        max_pages: int = 80,
        concurrency: int = 6,
        timeout: float = 6.0,
        export_mode: str = "links-only",
        out_path: str = "sqlmap_targets.txt",
    ) -> None:
        parsed = urlparse(start_url.strip())
        self.origin_host = (parsed.netloc or "").lower()
        self.origin_scheme = (parsed.scheme or "http").lower()
        self.start_url = self._normalize_url(start_url.strip())
        self.max_depth = max(0, max_depth)
        self.max_pages = max(1, max_pages)
        self.concurrency = max(1, concurrency)
        self.timeout = max(2.0, timeout)
        self.export_mode = export_mode
        self.out_path = out_path

        self.visited: Set[str] = set()
        self.queued: Set[str] = {self.start_url}
        self.queue: deque[Tuple[str, int]] = deque([(self.start_url, 0)])
        self.signals: Dict[str, SignalTarget] = {}
        self.status_counts: Counter[str] = Counter()
        self.recent_log: List[Tuple[str, str, str]] = []
        self.crawled_count = 0
        self.filtered_noise_count = 0
        self.done_event = asyncio.Event()
        self.export_status = "Not exported"

    def _normalize_url(self, raw_url: str) -> str:
        p = urlparse(raw_url)
        pairs = sorted(parse_qsl(p.query, keep_blank_values=True))
        clean_q = urlencode(pairs)
        clean_path = p.path or "/"
        return urlunparse((p.scheme.lower(), p.netloc.lower(), clean_path, "", clean_q, ""))

    def _is_static_noise(self, url: str) -> bool:
        path_lower = urlparse(url).path.lower()
        return any(path_lower.endswith(ext) for ext in STATIC_EXTS)

    def _is_in_scope(self, url: str) -> bool:
        p = urlparse(url)
        if p.scheme.lower() not in ("http", "https"):
            return False
        if self.origin_host and p.netloc.lower() != self.origin_host:
            return False
        return not self._is_static_noise(url)

    def _fetch_page(self, url: str) -> Tuple[str, str]:
        req = Request(
            url,
            method="GET",
            headers={
                "User-Agent": "SQLMapScout/1.1",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
        )
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                code = str(resp.status)
                ctype = resp.headers.get("Content-Type", "").lower()
                if any(skip in ctype for skip in ("image/", "audio/", "video/", "font/", "application/octet-stream")):
                    return code, ""
                raw = resp.read(524288)
                return code, raw.decode("utf-8", errors="ignore")
        except HTTPError as exc:
            body = exc.read(65536).decode("utf-8", errors="ignore") if exc.fp else ""
            return str(exc.code), body
        except URLError:
            return "NET_ERR", ""
        except Exception:
            return "ERR", ""

    def _record_signal(
        self,
        target_url: str,
        method: str,
        params: List[str],
        post_data: str,
        reason: str,
        status: str,
    ) -> None:
        key = f"{method}:{target_url}:{post_data}"
        if key not in self.signals:
            self.signals[key] = SignalTarget(
                url=target_url,
                method=method,
                params=sorted(set(params)),
                post_data=post_data,
                signal_reason=reason,
                status=status,
            )

    def _process_page(self, url: str, depth: int) -> None:
        status, body = self._fetch_page(url)
        self.crawled_count += 1
        self.status_counts[status] += 1

        parsed = urlparse(url)
        q_keys = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        path_lower = parsed.path.lower()
        has_dynamic_path = any(h in path_lower for h in DYNAMIC_PATH_HINTS) or bool(
            re.search(r"/(?:[0-9]+|[a-f0-9-]{8,})(?:/|$)", path_lower)
        )

        if q_keys:
            self._record_signal(url, "GET", q_keys, "", f"query-params({','.join(q_keys[:4])})", status)
            self.recent_log.append((status, "SIGNAL", f"GET params on {url}"))
        elif has_dynamic_path and status.startswith("2"):
            self._record_signal(url, "GET", [], "", "dynamic-endpoint", status)
            self.recent_log.append((status, "SIGNAL", f"Dynamic path {url}"))
        else:
            self.filtered_noise_count += 1
            self.recent_log.append((status, "FILTERED", url))

        if not body or depth >= self.max_depth:
            return

        parser = PageExtractor()
        try:
            parser.feed(body)
        except Exception:
            return

        for href in parser.links:
            if len(self.visited) + len(self.queued) >= self.max_pages * 3:
                break
            joined = urljoin(url, href)
            norm = self._normalize_url(joined)
            if self._is_in_scope(norm) and norm not in self.visited and norm not in self.queued:
                self.queued.add(norm)
                self.queue.append((norm, depth + 1))

        for form in parser.forms:
            action_raw = str(form.get("action") or url)
            method = str(form.get("method") or "GET").upper()
            inputs_raw = form.get("inputs")
            input_names = [str(x) for x in inputs_raw] if isinstance(inputs_raw, list) else []
            if not input_names:
                continue
            form_url = self._normalize_url(urljoin(url, action_raw))
            if not self._is_in_scope(form_url):
                continue
            if method == "POST":
                encoded_body = urlencode({k: "1" for k in input_names})
                self._record_signal(
                    form_url,
                    "POST",
                    input_names,
                    encoded_body,
                    f"post-form({','.join(input_names[:4])})",
                    status,
                )
            else:
                existing_pairs = dict(parse_qsl(urlparse(form_url).query, keep_blank_values=True))
                for k in input_names:
                    existing_pairs.setdefault(k, "1")
                p = urlparse(form_url)
                get_target = urlunparse((p.scheme, p.netloc, p.path or "/", "", urlencode(existing_pairs), ""))
                self._record_signal(
                    get_target,
                    "GET",
                    list(existing_pairs.keys()),
                    "",
                    f"get-form({','.join(input_names[:4])})",
                    status,
                )

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        while self.queue and self.crawled_count < self.max_pages:
            batch: List[Tuple[str, int]] = []
            while self.queue and len(batch) < self.concurrency and (self.crawled_count + len(batch)) < self.max_pages:
                u, d = self.queue.popleft()
                if u in self.visited:
                    continue
                self.visited.add(u)
                batch.append((u, d))
            if not batch:
                break
            await asyncio.gather(
                *[loop.run_in_executor(None, self._process_page, u, d) for u, d in batch],
                return_exceptions=True,
            )
        self.done_event.set()

    def build_sqlmap_command(self, item: SignalTarget) -> str:
        cmd = f'sqlmap -u "{item.url}" --batch'
        if item.method == "POST" and item.post_data:
            cmd += f' --data="{item.post_data}"'
        return cmd

    def export_findings(self) -> str:
        items = list(self.signals.values())
        if self.out_path.lower().endswith(".json"):
            if self.export_mode == "links-only":
                data_obj: object = {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "mode": "links-only",
                    "count": len(items),
                    "links": [it.url for it in items],
                }
            else:
                data_obj = {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "mode": "with-commands",
                    "count": len(items),
                    "targets": [
                        {
                            **asdict(it),
                            "sqlmap_command": self.build_sqlmap_command(it),
                        }
                        for it in items
                    ],
                }
            with open(self.out_path, "w", encoding="utf-8") as fh:
                json.dump(data_obj, fh, indent=2)
        else:
            lines: List[str] = []
            for it in items:
                if self.export_mode == "links-only":
                    lines.append(it.url)
                else:
                    lines.append(f"# {it.url} [{it.method} | {it.signal_reason}]")
                    lines.append(self.build_sqlmap_command(it))
            with open(self.out_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + ("\n" if lines else ""))

        self.export_status = f"Exported ({self.export_mode}) -> {self.out_path}"
        return self.export_status

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="top", size=4),
            Layout(name="body"),
            Layout(name="bottom", size=3),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=2),
        )
        layout["left"].split_column(
            Layout(name="stats", size=11),
            Layout(name="codes"),
        )

        header = Text.assemble(
            ("SQLMAP SCOUT TUI  ", "bold bright_cyan"),
            ("CRAWLED: ", "bold gold1"),
            (f"{self.crawled_count}/{self.max_pages}  ", "bold bright_white"),
            ("SIGNAL: ", "bold gold1"),
            (f"{len(self.signals)}  ", "bold bright_green"),
            ("NOISE DROPPED: ", "bold gold1"),
            (f"{self.filtered_noise_count}  ", "grey70"),
            ("MODE: ", "bold gold1"),
            (f"{self.export_mode}  ", "bold medium_purple1"),
            ("EXPORT: ", "bold gold1"),
            (self.export_status, "bold bright_green" if "Exported" in self.export_status else "bold gold1"),
        )
        layout["top"].update(Panel(header, border_style="bright_cyan", title="SIGNAL CRAWLER"))

        stat_lines = (
            f"Origin: {self.origin_scheme}://{self.origin_host}\n"
            f"Queue Remaining: {len(self.queue)}\n"
            f"Signal Targets: {len(self.signals)}\n"
            f"Filtered Noise: {self.filtered_noise_count}\n"
            f"Export Mode: {self.export_mode}\n"
            f"Output File: {self.out_path}"
        )
        layout["stats"].update(Panel(Text(stat_lines, style="bright_white"), border_style="gold1", title="TELEMETRY"))

        code_tbl = Table(box=box.SIMPLE_HEAVY, expand=True, border_style="bright_cyan", header_style="bold gold1")
        code_tbl.add_column("STATUS", style="bold gold1")
        code_tbl.add_column("COUNT", justify="right", style="bold bright_green", width=7)
        for k, v in sorted(self.status_counts.items()):
            code_tbl.add_row(k, str(v))
        if not self.status_counts:
            code_tbl.add_row("INIT", "0")
        layout["codes"].update(Panel(code_tbl, border_style="bright_cyan", title="HTTP STATUS"))

        sig_tbl = Table(box=box.SIMPLE_HEAVY, expand=True, border_style="bright_green", header_style="bold gold1")
        sig_tbl.add_column("METH", style="bold gold1", width=6)
        sig_tbl.add_column("CODE", style="bold bright_cyan", width=6)
        sig_tbl.add_column("SIGNAL", style="bold bright_green", width=24)
        sig_tbl.add_column("TARGET URL", style="bright_white")

        signal_rows = list(self.signals.values())[-22:]
        for item in signal_rows:
            sig_tbl.add_row(item.method, item.status, item.signal_reason[:24], item.url)
        if not signal_rows:
            sig_tbl.add_row("-", "-", "Scanning for parameterized/dynamic targets...", self.start_url)

        layout["right"].update(Panel(sig_tbl, border_style="bright_green", title="VERIFIED SIGNAL LINKS"))

        foot_msg = (
            "Crawl complete. Press Enter to export & exit, or Ctrl+C to quit without exporting."
            if self.done_event.is_set()
            else "Crawling until all queued relevant targets are inspected... Press Ctrl+C to stop."
        )
        layout["bottom"].update(Panel(Text(foot_msg, style="bold gold1"), border_style="grey50"))
        return layout


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SQLMap Scout - Signal-Only URL & Form Crawler TUI")
    parser.add_argument("-u", "--url", required=True, help="Starting target URL")
    parser.add_argument("--max-depth", type=int, default=2, help="Crawl link depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=80, help="Maximum pages to crawl (default: 80)")
    parser.add_argument("-c", "--concurrency", type=int, default=6, help="Concurrent workers (default: 6)")
    parser.add_argument("-t", "--timeout", type=float, default=6.0, help="Request timeout in seconds")
    export_group = parser.add_mutually_exclusive_group()
    export_group.add_argument(
        "--links-only",
        action="store_true",
        help="Export only the signal URLs",
    )
    export_group.add_argument(
        "--with-commands",
        action="store_true",
        help="Export generated sqlmap commands alongside each target link",
    )
    parser.add_argument(
        "-o",
        "--out",
        default="sqlmap_targets.txt",
        help="Output path (.txt or .json; default: sqlmap_targets.txt)",
    )
    parser.add_argument(
        "--auto-export",
        action="store_true",
        help="Export automatically when crawling finishes without waiting for Enter",
    )
    return parser.parse_args()


async def wait_for_export(
    done_event: asyncio.Event,
    scout: SQLMapScoutTUI,
    auto_export: bool,
) -> None:
    await done_event.wait()
    if auto_export:
        scout.export_findings()
        return
    loop = asyncio.get_running_loop()
    if sys.stdin and sys.stdin.isatty():
        await loop.run_in_executor(None, sys.stdin.readline)
        scout.export_findings()
    else:
        await asyncio.Event().wait()


async def main() -> None:
    args = parse_args()
    mode = "with-commands" if args.with_commands else "links-only"
    scout = SQLMapScoutTUI(
        start_url=args.url,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        timeout=args.timeout,
        export_mode=mode,
        out_path=args.out,
    )

    console = Console()
    crawl_task = asyncio.create_task(scout.run())
    export_task = asyncio.create_task(wait_for_export(scout.done_event, scout, args.auto_export))

    try:
        with Live(scout.render(), console=console, refresh_per_second=10, screen=True) as live:
            while not export_task.done():
                live.update(scout.render())
                await asyncio.sleep(0.1)
            live.update(scout.render())
            await asyncio.sleep(0.4)
    except KeyboardInterrupt:
        pass
    finally:
        crawl_task.cancel()
        export_task.cancel()
        await asyncio.gather(crawl_task, export_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
