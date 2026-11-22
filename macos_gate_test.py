# -*- coding: utf-8 -*-
"""macOS 真机雷池门测试"""
import json, os, subprocess, sys, time, urllib.request
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

NL = chr(10)
exe = os.path.abspath("node_modules/electron/dist/Electron.app/Contents/MacOS/Electron")
proc = subprocess.Popen([exe, os.path.abspath("electron-main.js"), "https://berryhub.org/"],
                        env=dict(os.environ, ELECTRON_CDP_PORT="9223"))
verdict = "TIMEOUT"
try:
    for _ in range(45):
        try:
            urllib.request.urlopen("http://127.0.0.1:9223/json/version", timeout=2)
            break
        except Exception:
            time.sleep(1)
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    b = pw.chromium.connect_over_cdp("http://127.0.0.1:9223")
    pg = b.contexts[0].pages[0]
    for i in range(15):
        time.sleep(3)
        t = pg.title() or ""
        if "BerryHub" in t:
            verdict = f"PASS ({i*3}s)"
            r = pg.evaluate('async () => (await fetch("/wp-json/wp/v2/posts?per_page=1&orderby=date&order=desc",{credentials:"include"})).status')
            verdict += f" wp-json={r}"
            break
        if i in (4, 9, 14):
            txt = (pg.evaluate("document.body.innerText") or "").replace(NL, " ")[:120]
            print(f"[{i*3}s] title={t!r} txt={txt!r}", flush=True)
    pw.stop()
finally:
    proc.terminate()
print("VERDICT:", verdict, flush=True)
