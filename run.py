#!/usr/bin/env python3
"""Scheduled collector for an LLM web interface.

This file is the harness: geo verification, session handling, pacing,
and artifact capture. Everything interface-specific lives in adapters/.

Usage:
    python run.py --login        one-time interactive sign-in
    python run.py --check-geo    verify the exit IP only
    python run.py                collect
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import random
import shutil
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

LOG = logging.getLogger("collector")

# Two independent sources, so one provider's bad geolocation record does
# not silently abort every run.
GEO_ENDPOINTS = [
    ("https://ipinfo.io/json", "country"),
    ("https://ifconfig.co/json", "country_iso"),
]


def setup_logging(log_path: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_path:
        handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )


def load_config(path: Path) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def fetch_json(url: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def check_geo(expected_country: str) -> dict:
    """Resolve the exit IP and its country.

    Raises RuntimeError if the country does not match, or if no endpoint
    could be reached at all. Returns the observed values for the record.
    """
    errors = []
    for url, country_key in GEO_ENDPOINTS:
        try:
            data = fetch_json(url)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            continue

        ip = data.get("ip")
        country = (data.get(country_key) or "").upper()
        if not ip or not country:
            errors.append(f"{url}: response missing ip or country")
            continue

        observed = {"ip": ip, "country": country, "source": url}
        if country != expected_country.upper():
            raise RuntimeError(
                f"Exit IP {ip} geolocates to {country}, expected "
                f"{expected_country.upper()} (source: {url})"
            )
        return observed

    raise RuntimeError("Could not determine exit IP or country: " + "; ".join(errors))


def load_adapter(name: str):
    module = importlib.import_module(f"adapters.{name}")
    return module.Adapter()


def load_prompts(path: Path) -> list[str]:
    prompts = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            prompts.append(line)
    if not prompts:
        raise RuntimeError(f"No prompts found in {path}")
    return prompts


def notify_failure(webhook: str, payload: dict) -> None:
    if not webhook:
        return
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as exc:
        LOG.warning("Failure webhook did not deliver: %s", exc)


def load_credentials(cfg: dict) -> dict:
    """Read credentials from the environment, optionally seeded by a file.

    Credentials are deliberately kept out of config.yaml so the config can
    be committed and shared without leaking an account.
    """
    path = ROOT / cfg.get("credentials_file", "credentials.env")
    if path.exists():
        mode = path.stat().st_mode & 0o077
        if mode:
            LOG.warning(
                "%s is readable by other users; chmod 600 it", path.name
            )
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    return {
        "email": os.environ.get("LLM_EMAIL", ""),
        "password": os.environ.get("LLM_PASSWORD", ""),
        "totp_secret": os.environ.get("LLM_TOTP_SECRET", ""),
    }


def ensure_logged_in(page, adapter, cfg: dict, credentials: dict) -> None:
    """Confirm a session, signing in automatically when configured."""
    if adapter.is_logged_in(page):
        return

    if not cfg.get("auto_login", False):
        raise RuntimeError(
            "Not signed in. Run with --login, or set auto_login: true."
        )
    if not adapter.supports_auto_login:
        raise RuntimeError(
            f"Adapter '{adapter.name}' does not implement automated login."
        )

    LOG.info("No valid session; attempting automated sign-in")
    adapter.login(page, credentials)

    if not adapter.is_logged_in(page):
        raise RuntimeError("Automated sign-in completed but no session resulted")
    LOG.info("Automated sign-in succeeded")


def browser_alive(page) -> bool:
    """Cheap round-trip to confirm the browser is still there.

    is_closed() alone is not enough: a crashed browser process can leave a
    page object that still claims to be open until something touches it.
    """
    try:
        if page is None or page.is_closed():
            return False
        page.title()
        return True
    except Exception:
        return False


def make_adapter(cfg: dict):
    adapter = load_adapter(cfg["adapter"])
    adapter.temporary_chat = bool(cfg.get("temporary_chat", False))
    return adapter


def launch_context(playwright, cfg: dict, profile_dir: Path | None = None):
    profile_dir = Path(profile_dir) if profile_dir else ROOT / cfg["profile_dir"]
    profile_dir.mkdir(parents=True, exist_ok=True)
    return playwright.chromium.launch_persistent_context(
        user_data_dir=str(profile_dir),
        headless=bool(cfg.get("headless", False)),
        viewport={
            "width": int(cfg.get("viewport_width", 1440)),
            "height": int(cfg.get("viewport_height", 900)),
        },
        # Keep these consistent with the exit IP. A German IP reporting a
        # Stockholm timezone is a fingerprint mismatch and draws exactly
        # the bot scrutiny you are trying to avoid.
        locale=cfg.get("browser_locale", "en-US"),
        timezone_id=cfg.get("browser_timezone", "Europe/Stockholm"),
        args=["--disable-blink-features=AutomationControlled"],
    )


def do_probe(cfg: dict) -> int:
    """Report which of the adapter's candidate selectors resolve right now.

    Run this whenever a collection starts failing. It turns selector rot
    from a guessing game into a one-line diagnosis.
    """
    adapter = make_adapter(cfg)
    candidates = adapter.selector_candidates()
    if not candidates:
        print(f"Adapter '{adapter.name}' does not expose selector candidates.")
        return 1

    with sync_playwright() as playwright:
        context = launch_context(playwright, cfg)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(adapter.url, wait_until="domcontentloaded")
        page.wait_for_timeout(6000)

        signed_in = None
        try:
            signed_in = adapter.is_logged_in(page)
        except Exception as exc:
            print(f"\nis_logged_in raised: {exc}")

        print(f"\nProbing {adapter.url}")
        print(f"Session state: {'SIGNED IN' if signed_in else 'SIGNED OUT'}\n")

        notes = adapter.probe_notes()
        for group, selectors in candidates.items():
            note = notes.get(group)
            print(f"  {group}:" + (f"   [{note}]" if note else ""))
            for sel in selectors:
                try:
                    count = page.locator(sel).count()
                    visible = page.locator(sel).first.is_visible(timeout=800)
                except Exception:
                    count, visible = 0, False
                mark = "MATCH  " if count and visible else "       "
                print(f"    {mark} n={count:<3} visible={str(visible):<5} {sel}")
            print()

        out = ROOT / "probe.html"
        out.write_text(page.content())
        print(f"Page HTML written to {out} for manual inspection.")
        context.close()
    return 0


def do_login(cfg: dict) -> int:
    """Open the target with the persistent profile and wait for manual sign-in."""
    adapter = make_adapter(cfg)
    with sync_playwright() as playwright:
        context = launch_context(playwright, cfg)
        page = context.pages[0] if context.pages else context.new_page()
        page.goto(adapter.url, wait_until="domcontentloaded")

        ok = False
        if cfg.get("auto_login", False) and adapter.supports_auto_login:
            try:
                ensure_logged_in(page, adapter, cfg, load_credentials(cfg))
                ok = True
            except Exception as exc:
                print(f"\nAutomated sign-in failed: {exc}\n")

        if not ok:
            print()
            print("Sign in in the browser window, then press Enter here.")
            print("The session is saved into the persistent profile directory.")
            input()
            ok = adapter.is_logged_in(page)

        context.close()
    if ok:
        print("Session looks valid.")
        return 0
    print("Could not confirm a valid session. Check the adapter's login marker.")
    return 1


def capture(page, adapter, out_dir: Path, meta: dict, response_text: str) -> None:
    """Persist everything needed to re-audit this exchange later."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "response.txt").write_text(response_text)
    try:
        (out_dir / "page.html").write_text(page.content())
    except Exception as exc:
        LOG.warning("Could not capture HTML: %s", exc)
    try:
        page.screenshot(path=str(out_dir / "screenshot.png"), full_page=True)
    except Exception as exc:
        LOG.warning("Could not capture screenshot: %s", exc)
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))


def collect(cfg: dict, run_dir: Path, geo: dict) -> dict:
    adapter = make_adapter(cfg)
    prompts = load_prompts(ROOT / cfg["prompts_file"])
    isolation = str(cfg.get("isolation", "persistent")).lower()
    if isolation not in ("persistent", "ephemeral"):
        raise RuntimeError("isolation must be 'persistent' or 'ephemeral'")
    repeats = int(cfg.get("repeats", 1))
    timeout_ms = int(cfg.get("response_timeout", 180)) * 1000

    # Build the full schedule up front, then shuffle once, so repeats of
    # the same prompt are not adjacent.
    schedule = [
        (idx, rep)
        for rep in range(1, repeats + 1)
        for idx in range(len(prompts))
    ]
    if cfg.get("shuffle", True):
        random.shuffle(schedule)

    results = {"ok": 0, "failed": 0, "items": []}

    LOG.info("Isolation mode: %s", isolation)
    model = None
    credentials = load_credentials(cfg)
    max_relaunches = int(cfg.get("max_relaunches", 3))
    relaunches = 0

    def write_partial() -> None:
        """Persist progress after every item.

        A crash between prompts should cost one response, not the record
        of everything collected before it.
        """
        try:
            (run_dir / "run.json").write_text(
                json.dumps(
                    {
                        "run_id": run_dir.name,
                        "status": "in_progress",
                        "geo": geo,
                        "adapter": adapter.name,
                        "isolation": isolation,
                        "relaunches": relaunches,
                        "results": results,
                    },
                    indent=2,
                    default=str,
                )
            )
        except Exception as exc:
            LOG.warning("Could not write partial summary: %s", exc)

    with sync_playwright() as playwright:
        context = None
        page = None
        temp_profile = None

        if isolation == "persistent":
            # One signed-in session reused for the whole run. The account
            # and its accumulated history are the treatment here.
            context = launch_context(playwright, cfg)
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(adapter.url, wait_until="domcontentloaded")
            try:
                ensure_logged_in(page, adapter, cfg, load_credentials(cfg))
            except Exception:
                context.close()
                raise
            model = adapter.model_label(page)
            LOG.info("Signed in. Model label: %s", model)

        for position, (idx, rep) in enumerate(schedule, start=1):
            prompt = prompts[idx]
            slug = f"p{idx:03d}_r{rep}"
            item_dir = run_dir / slug
            LOG.info("[%d/%d] %s", position, len(schedule), slug)

            if isolation == "ephemeral":
                # Throwaway profile per query: no cookies, no history, no
                # account carried in from the previous prompt.
                temp_profile = Path(tempfile.mkdtemp(prefix="profile-"))
                context = launch_context(playwright, cfg, profile_dir=temp_profile)
                page = context.pages[0] if context.pages else context.new_page()
            elif not browser_alive(page):
                # The browser died: crashed, was closed, or was killed by
                # the OS. Recover rather than losing the remaining prompts.
                if relaunches >= max_relaunches:
                    raise RuntimeError(
                        f"Browser died {relaunches} times; giving up. Something "
                        "is killing it repeatedly rather than randomly."
                    )
                relaunches += 1
                LOG.warning(
                    "Browser is gone; relaunching (%d/%d)", relaunches, max_relaunches
                )
                try:
                    context.close()
                except Exception:
                    pass
                context = launch_context(playwright, cfg)
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(adapter.url, wait_until="domcontentloaded")
                ensure_logged_in(page, adapter, cfg, credentials)
                LOG.info("Recovered; continuing from %s", slug)

            meta = {
                "prompt_index": idx,
                "repeat": rep,
                "position_in_run": position,
                "prompt": prompt,
                "adapter": adapter.name,
                "isolation": isolation,
                "temporary_chat": bool(cfg.get("temporary_chat", False)),
                "exit_ip": geo["ip"],
                "exit_country": geo["country"],
                "started_utc": datetime.now(timezone.utc).isoformat(),
            }

            try:
                adapter.new_chat(page)
                if isolation == "ephemeral":
                    model = adapter.model_label(page)
                meta["model_label"] = model
                adapter.send(page, prompt)
                adapter.wait_for_response(page, timeout_ms)
                text = adapter.extract_response(page)
                meta["status"] = "ok"
                meta["finished_utc"] = datetime.now(timezone.utc).isoformat()
                meta["url"] = page.url
                capture(page, adapter, item_dir, meta, text)
                results["ok"] += 1
            except Exception as exc:
                LOG.error("%s failed: %s", slug, exc)
                meta["status"] = "failed"
                meta["error"] = str(exc)
                meta["traceback"] = traceback.format_exc()
                meta["finished_utc"] = datetime.now(timezone.utc).isoformat()
                meta.setdefault("model_label", model)
                try:
                    meta["url"] = page.url
                except Exception:
                    pass
                capture(page, adapter, item_dir, meta, "")
                results["failed"] += 1
            finally:
                if isolation == "ephemeral":
                    try:
                        context.close()
                    except Exception:
                        pass
                    shutil.rmtree(temp_profile, ignore_errors=True)

            results["items"].append({"slug": slug, "status": meta["status"]})
            write_partial()

            if position < len(schedule):
                delay = random.uniform(
                    float(cfg.get("min_delay_seconds", 20)),
                    float(cfg.get("max_delay_seconds", 60)),
                )
                LOG.info("Sleeping %.1fs", delay)
                time.sleep(delay)

        if isolation == "persistent" and context is not None:
            context.close()

    results["model_label"] = model
    results["relaunches"] = relaunches
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(ROOT / "config.yaml"))
    parser.add_argument("--login", action="store_true", help="interactive sign-in")
    parser.add_argument("--check-geo", action="store_true", help="verify exit IP only")
    parser.add_argument(
        "--probe", action="store_true", help="report which selectors currently match"
    )
    args = parser.parse_args()

    cfg = load_config(Path(args.config))

    if args.probe:
        setup_logging(None)
        return do_probe(cfg)

    if args.check_geo:
        setup_logging(None)
        try:
            geo = check_geo(cfg["expected_country"])
        except RuntimeError as exc:
            print(f"FAIL: {exc}")
            return 1
        print(f"OK: {geo['ip']} -> {geo['country']} (via {geo['source']})")
        return 0

    if args.login:
        setup_logging(None)
        return do_login(cfg)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = ROOT / cfg["output_dir"] / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(run_dir / "run.log")

    summary = {
        "run_id": run_id,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "adapter": cfg["adapter"],
        "config": cfg,
    }

    try:
        geo = check_geo(cfg["expected_country"])
        LOG.info("Exit IP %s in %s (via %s)", geo["ip"], geo["country"], geo["source"])
    except RuntimeError as exc:
        if cfg.get("enforce_geo", True):
            LOG.error("Geo check failed, aborting: %s", exc)
            summary["status"] = "aborted_geo"
            summary["error"] = str(exc)
            summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
            (run_dir / "run.json").write_text(json.dumps(summary, indent=2))
            notify_failure(cfg.get("failure_webhook", ""), summary)
            return 2
        LOG.warning("Geo check failed but enforce_geo is false: %s", exc)
        geo = {"ip": None, "country": None, "source": None}

    summary["geo"] = geo

    try:
        results = collect(cfg, run_dir, geo)
        summary["status"] = "ok" if results["failed"] == 0 else "partial"
        summary["results"] = results
    except Exception as exc:
        LOG.error("Run failed: %s", exc)
        summary["status"] = "failed"
        summary["error"] = str(exc)
        summary["traceback"] = traceback.format_exc()

    summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (run_dir / "run.json").write_text(json.dumps(summary, indent=2, default=str))

    if summary["status"] in ("failed", "partial"):
        notify_failure(cfg.get("failure_webhook", ""), summary)

    LOG.info("Run %s finished: %s", run_id, summary["status"])
    return 0 if summary["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
