#!/usr/bin/env python3
"""
Matryoshka VPN — Stability Checker

Identifies and maintains the most stable VPN configs from russia_whitelist.txt.

Outputs:
  configs/stable_pool.json   — pool of verified configs with metadata (up to 60)
  configs/stable_top15.txt   — top-15 subscription-ready configs

Usage:
  python3 scripts/stability_checker.py           # full run (recheck pool + scan for new)
  python3 scripts/stability_checker.py --quick   # recheck stable pool only (run every 30-60min)
  python3 scripts/stability_checker.py --scan    # force scan even if pool is full
  python3 scripts/stability_checker.py --no-xray # TCP-only mode (no xray binary required)
  python3 scripts/stability_checker.py --top 20  # export top-20 instead of 15

Requirements:
  - Python 3.8+
  - curl (for proxy HTTP tests)
  - xray binary in PATH or ./bin/xray (optional but strongly recommended)
"""

from __future__ import annotations
import argparse
import base64
import concurrent.futures
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS_DIR = REPO_ROOT / "configs"
MAIN_CONFIGS = CONFIGS_DIR / "russia_whitelist.txt"
STABLE_POOL_FILE = CONFIGS_DIR / "stable_pool.json"
STABLE_TOP_FILE = CONFIGS_DIR / "stable_top15.txt"

# Domains blocked in Russia — from gfwlist, ACL4SSR, v2fly, loyalsoldier/v2ray-rules-dat
# A working proxy must successfully reach MIN_PASS_URLS of these.
TEST_URLS = [
    "https://www.youtube.com",
    "https://x.com",
    "https://www.reddit.com",
    "https://discord.com",
    "https://telegram.org",
    "https://www.instagram.com",
    "https://www.spotify.com",
]

TCP_TIMEOUT = 4.0       # seconds for TCP connect test
PROXY_TIMEOUT = 20.0    # seconds per URL inside proxy test
MAX_POOL = 60           # max configs in stable pool
TOP_N = 15              # configs to export to stable_top15.txt
EVICT_AFTER = 3         # consecutive failures before eviction from pool
TCP_WORKERS = 50        # parallel TCP tests
PROXY_WORKERS = 5       # parallel xray proxy tests (each spawns a process)
TCP_CANDIDATES = 120    # top TCP results to proxy-test when scanning
MIN_PASS_URLS = 2       # URLs that must succeed to count a config as working


# ---------- Data model ----------

@dataclass
class ConfigRecord:
    uri: str
    host: str
    port: int
    protocol: str
    name: str = ""
    latency_ms: float = 9999.0
    success_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    last_checked: str = ""
    last_success: str = ""

    @property
    def score(self) -> float:
        """
        Composite score for ranking (higher = better).
        Weights: success_rate 50%, recency 30%, latency 20%.
        """
        if self.success_count == 0:
            return 0.0
        total = self.success_count + self.failure_count
        rate = self.success_count / total

        recency = 0.0
        if self.last_success:
            try:
                dt = datetime.fromisoformat(self.last_success.replace("Z", "+00:00"))
                age_h = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
                recency = max(0.0, 1.0 - age_h / 24)
            except Exception:
                pass

        lat_score = max(0.0, 1.0 - self.latency_ms / 2000)

        return rate * 0.50 + recency * 0.30 + lat_score * 0.20

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = round(self.score, 4)
        return d


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- Config URI parsing ----------

def parse_config(uri: str) -> Optional[ConfigRecord]:
    uri = uri.strip()
    if not uri or uri.startswith("#"):
        return None
    try:
        if uri.startswith("vmess://"):
            raw = uri[8:] + "=" * ((-len(uri[8:])) % 4)
            d = json.loads(base64.b64decode(raw).decode("utf-8", errors="replace"))
            return ConfigRecord(
                uri=uri, host=str(d.get("add", "")), port=int(d.get("port", 0)),
                protocol="vmess", name=str(d.get("ps", "")),
            )
        for proto in ("vless", "trojan", "hysteria2", "tuic", "ss"):
            if uri.startswith(f"{proto}://"):
                rest = uri[len(proto) + 3:]
                name = ""
                if "#" in rest:
                    rest, frag = rest.rsplit("#", 1)
                    name = urllib.parse.unquote(frag)
                parsed = urllib.parse.urlparse(f"s://{rest}")
                host = parsed.hostname or ""
                port = parsed.port or 0
                if host and port:
                    return ConfigRecord(uri=uri, host=host, port=port, protocol=proto, name=name)
    except Exception:
        pass
    return None


# ---------- TCP reachability test ----------

def tcp_test(host: str, port: int, timeout: float = TCP_TIMEOUT) -> float:
    try:
        t0 = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return (time.monotonic() - t0) * 1000.0
    except Exception:
        return -1.0


# ---------- xray proxy test ----------

def find_xray() -> Optional[str]:
    candidates = [
        shutil.which("xray"),
        str(REPO_ROOT / "bin" / "xray"),
        "/usr/local/bin/xray",
        "/usr/bin/xray",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _build_outbound(record: ConfigRecord) -> Optional[dict]:
    try:
        uri = record.uri
        if record.protocol == "vmess":
            raw = uri[8:] + "=" * ((-len(uri[8:])) % 4)
            d = json.loads(base64.b64decode(raw).decode("utf-8", errors="replace"))
            net = d.get("net", "tcp")
            stream: dict = {"network": net}
            if net == "ws":
                stream["wsSettings"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", record.host)}}
            if d.get("tls") == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": d.get("sni", record.host), "allowInsecure": False}
            return {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": record.host, "port": record.port,
                    "users": [{"id": d.get("id", ""), "alterId": int(d.get("aid", 0)), "security": d.get("scy", "auto")}]}]},
                "streamSettings": stream,
            }
        if record.protocol not in ("vless", "trojan"):
            return None
        rest = uri[len(record.protocol) + 3:]
        if "#" in rest:
            rest = rest.rsplit("#", 1)[0]
        parsed = urllib.parse.urlparse(f"s://{rest}")
        p = dict(urllib.parse.parse_qsl(parsed.query))
        user = parsed.username or ""
        transport = p.get("type", "tcp")
        if transport == "raw":
            transport = "tcp"
        security = p.get("security", "none")
        sni = p.get("sni", p.get("peer", record.host))
        stream = {"network": transport}
        if transport == "ws":
            stream["wsSettings"] = {"path": p.get("path", "/"), "headers": {"Host": p.get("host", sni)}}
        elif transport == "grpc":
            stream["grpcSettings"] = {"serviceName": p.get("serviceName", p.get("mode", ""))}
        elif transport == "xhttp":
            stream["xhttpSettings"] = {"path": p.get("path", "/")}
        if security == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": sni, "allowInsecure": False, "fingerprint": p.get("fp", "chrome")}
        elif security == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": sni, "fingerprint": p.get("fp", "chrome"),
                "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""), "spiderX": p.get("spx", ""),
            }
        if record.protocol == "vless":
            return {
                "protocol": "vless",
                "settings": {"vnext": [{"address": record.host, "port": record.port,
                    "users": [{"id": user, "flow": p.get("flow", ""), "encryption": "none"}]}]},
                "streamSettings": stream,
            }
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": record.host, "port": record.port, "password": user}]},
            "streamSettings": stream,
        }
    except Exception:
        pass
    return None


def _wait_for_port(port: int, deadline: float) -> bool:
    """Poll until xray SOCKS port is actually accepting connections."""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def proxy_test(record: ConfigRecord, xray_bin: str, timeout: float = PROXY_TIMEOUT) -> tuple[bool, float]:
    """
    Start xray, wait until SOCKS port is ready, send requests through it.
    Requires MIN_PASS_URLS successful responses to accept the config.
    Returns (success, best_latency_ms).
    """
    outbound = _build_outbound(record)
    if outbound is None:
        return False, -1.0

    local_port = random.randint(20000, 59000)
    xray_cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": False, "auth": "noauth"}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }
    proc = None
    cfg_path = None
    try:
        fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="mxvpn_")
        with os.fdopen(fd, "w") as f:
            json.dump(xray_cfg, f)

        proc = subprocess.Popen([xray_bin, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait until port is live — no fixed sleep
        if not _wait_for_port(local_port, deadline=time.monotonic() + 6.0):
            return False, -1.0

        proxy_url = f"socks5h://127.0.0.1:{local_port}"  # socks5h: DNS resolved remotely
        passed = 0
        best_ms = 9999.0

        for url in TEST_URLS:
            try:
                t0 = time.monotonic()
                r = subprocess.run(
                    ["curl", "-sf", "-o", "/dev/null", "-w", "%{http_code}",
                     "--proxy", proxy_url,
                     "--max-time", str(int(timeout)),
                     "--connect-timeout", "8",
                     "-L", url],
                    capture_output=True, text=True, timeout=timeout + 4,
                )
                ms = (time.monotonic() - t0) * 1000.0
                code = r.stdout.strip()
                if code.isdigit() and 200 <= int(code) < 400:
                    passed += 1
                    best_ms = min(best_ms, ms)
                    if passed >= MIN_PASS_URLS:
                        return True, best_ms
            except Exception:
                continue

        return False, -1.0
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except Exception:
                pass


# ---------- Pool persistence ----------

def load_pool() -> list[ConfigRecord]:
    if not STABLE_POOL_FILE.exists():
        return []
    try:
        data = json.loads(STABLE_POOL_FILE.read_text(encoding="utf-8"))
        records = []
        for d in data.get("configs", []):
            d.pop("score", None)
            try:
                records.append(ConfigRecord(**d))
            except TypeError:
                pass
        return records
    except Exception as e:
        print(f"[!] Could not load pool: {e}")
        return []


def save_pool(records: list[ConfigRecord]) -> None:
    ranked = sorted(records, key=lambda r: r.score, reverse=True)
    payload = {
        "updated": now_iso(),
        "count": len(ranked),
        "note": "Intermediate stable pool. Tested configs with metadata. Updated every run.",
        "configs": [r.to_dict() for r in ranked],
    }
    tmp = STABLE_POOL_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(STABLE_POOL_FILE)


def export_top(records: list[ConfigRecord], n: int = TOP_N) -> int:
    eligible = [r for r in records if r.consecutive_failures == 0 and r.success_count > 0]
    ranked = sorted(eligible, key=lambda r: r.score, reverse=True)[:n]
    content = "\n".join(r.uri for r in ranked)
    if content:
        content += "\n"
    STABLE_TOP_FILE.write_text(content, encoding="utf-8")
    return len(ranked)


# ---------- Phase 1: Recheck pool ----------

def recheck_pool(pool: list[ConfigRecord], xray_bin: Optional[str]) -> list[ConfigRecord]:
    if not pool:
        return pool
    print(f"\n[Phase 1] Rechecking {len(pool)} stable pool configs...")

    def _check(record: ConfigRecord) -> ConfigRecord:
        if xray_bin:
            ok, lat = proxy_test(record, xray_bin)
        else:
            lat = tcp_test(record.host, record.port)
            ok = lat >= 0
        record.last_checked = now_iso()
        if ok:
            record.latency_ms = lat if lat > 0 else record.latency_ms
            record.success_count += 1
            record.consecutive_failures = 0
            record.last_success = now_iso()
        else:
            record.failure_count += 1
            record.consecutive_failures += 1
        return record

    with concurrent.futures.ThreadPoolExecutor(max_workers=PROXY_WORKERS) as ex:
        futures = [ex.submit(_check, r) for r in pool]
        results = []
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            r = fut.result()
            tag = f"OK    {r.latency_ms:6.0f}ms" if r.consecutive_failures == 0 else f"FAIL  x{r.consecutive_failures}"
            print(f"  [{i:2d}/{len(pool)}] {tag}  {r.protocol:7s} {r.host}:{r.port}")
            results.append(r)

    kept = [r for r in results if r.consecutive_failures < EVICT_AFTER]
    evicted = len(results) - len(kept)
    if evicted:
        print(f"[Phase 1] Evicted {evicted} config(s) with {EVICT_AFTER}+ consecutive failures.")
    return kept


# ---------- Phase 2: Scan main list ----------

def scan_main_list(pool: list[ConfigRecord], xray_bin: Optional[str], needed: int) -> list[ConfigRecord]:
    if not MAIN_CONFIGS.exists():
        print(f"[!] Main configs not found: {MAIN_CONFIGS}")
        return pool

    pool_uris = {r.uri for r in pool}
    all_uris = [u.strip() for u in MAIN_CONFIGS.read_text(encoding="utf-8").splitlines()
                if u.strip() and not u.startswith("#")]
    new_uris = [u for u in all_uris if u not in pool_uris]
    print(f"\n[Phase 2] Found {len(new_uris)} new candidates (from {len(all_uris)} total).")
    if not new_uris:
        print("[Phase 2] No new candidates.")
        return pool

    records = [r for r in (parse_config(u) for u in new_uris) if r]
    print(f"[Phase 2a] TCP testing {len(records)} candidates...")

    def _tcp(r: ConfigRecord) -> ConfigRecord:
        r.latency_ms = tcp_test(r.host, r.port, timeout=3.0)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        tested = list(ex.map(_tcp, records))

    tcp_passed = [r for r in tested if r.latency_ms >= 0]
    print(f"[Phase 2a] TCP: {len(tcp_passed)}/{len(records)} reachable.")
    if not tcp_passed:
        return pool

    # REALITY first (most censorship-resistant), then by latency
    def _priority(r: ConfigRecord) -> tuple:
        return (-int("reality" in r.uri.lower()), r.latency_ms)

    candidates = sorted(tcp_passed, key=_priority)[:TCP_CANDIDATES]
    reality_count = sum(1 for r in candidates if "reality" in r.uri.lower())
    print(f"[Phase 2b] Testing top {len(candidates)} candidates ({reality_count} REALITY)...")

    if not xray_bin:
        to_add = candidates[:needed]
        print(f"[Phase 2b] No xray — adding {len(to_add)} by TCP latency.")
        for r in to_add:
            r.success_count = 1
            r.last_checked = now_iso()
            r.last_success = now_iso()
            pool.append(r)
        return pool

    added = 0

    def _proxy(r: ConfigRecord) -> tuple[ConfigRecord, bool, float]:
        ok, lat = proxy_test(r, xray_bin)
        return r, ok, lat

    with concurrent.futures.ThreadPoolExecutor(max_workers=PROXY_WORKERS) as ex:
        futures = {ex.submit(_proxy, r): r for r in candidates}
        for fut in concurrent.futures.as_completed(futures):
            r, ok, lat = fut.result()
            if ok:
                r.latency_ms = lat
                r.success_count = 1
                r.consecutive_failures = 0
                r.last_checked = now_iso()
                r.last_success = now_iso()
                pool.append(r)
                added += 1
                sec = "REALITY" if "reality" in r.uri.lower() else r.protocol.upper()
                print(f"  [+] {lat:6.0f}ms  {sec:10s} {r.host}:{r.port}  {r.name[:30]}")
                if added >= needed:
                    for f in futures:
                        f.cancel()
                    break

    print(f"[Phase 2b] Added {added} new config(s) to stable pool.")
    return pool


# ---------- Main ----------

def main() -> None:
    parser = argparse.ArgumentParser(description="Matryoshka VPN Stability Checker",
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("--quick", action="store_true", help="Recheck pool only, skip scan")
    parser.add_argument("--scan", action="store_true", help="Force scan even if pool is full")
    parser.add_argument("--top", type=int, default=TOP_N, help=f"Configs to export (default: {TOP_N})")
    parser.add_argument("--no-xray", action="store_true", help="TCP-only mode")
    args = parser.parse_args()

    xray_bin = None if args.no_xray else find_xray()
    mode = "TCP-only" if not xray_bin else f"xray ({xray_bin})"
    print(f"[*] Matryoshka VPN Stability Checker | test mode: {mode}")
    print(f"[*] Pool: {STABLE_POOL_FILE.name} | Output: {STABLE_TOP_FILE.name}")

    pool = load_pool()
    print(f"[*] Loaded stable pool: {len(pool)} configs.")

    pool = recheck_pool(pool, xray_bin)

    needed = MAX_POOL - len(pool)
    if not args.quick and (needed > 0 or args.scan):
        pool = scan_main_list(pool, xray_bin, needed if not args.scan else MAX_POOL)

    if len(pool) > MAX_POOL:
        pool = sorted(pool, key=lambda r: r.score, reverse=True)[:MAX_POOL]

    save_pool(pool)
    n_exported = export_top(pool, args.top)

    print(f"\n[+] Stable pool: {len(pool)} configs → {STABLE_POOL_FILE.name}")
    print(f"[+] Top-{n_exported} → {STABLE_TOP_FILE.name}")

    if pool:
        top5 = sorted(pool, key=lambda r: r.score, reverse=True)[:5]
        print("\n[*] Top-5 by score:")
        for r in top5:
            sec = "REALITY" if "reality" in r.uri.lower() else r.protocol.upper()
            print(f"    score={r.score:.3f}  lat={r.latency_ms:.0f}ms  "
                  f"ok={r.success_count}  fail={r.failure_count}  {sec} {r.host}:{r.port}")


if __name__ == "__main__":
    main()
