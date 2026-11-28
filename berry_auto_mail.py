#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BerryHub 公益节点云端全自动收割 (GitHub Actions 版)

流程: Electron(Chromium152, 过雷池WAF) → 侦察新帖 → yt-dlp 下载频道最新视频
      → RapidOCR 跨帧多数投票提密码 → 页面内 REST 解锁 → curl 拉订阅
      → TCP 测活 → QQ SMTP 邮件投递

环境变量:
  MAIL_AUTHCODE  QQ邮箱SMTP授权码 (未配置=跳过发信, 只落盘)
  MAIL_TO        收件邮箱 (默认 719794448@qq.com)
  TEST_MODE      任意非空值 = 测试模式(不发邮件)
  CDP_PORT       Electron 调试端口 (默认 9223)

协议要点 (2026-11-22 实测破解, 详见 workspace REGISTRY.md 第十二节):
  - 帖子列表: GET /wp-json/wp/v2/posts (每日 20:00 发布, 有效期 28h)
  - 密码字段: 锁定页 <input type=password name=<数字ID>>, 每期不同
  - 解锁: POST /wp-json/wppp/v1/check-content-password/<ID>
          body: fields[<ID>]=<密码>&g-recaptcha-response=&area=0&pss=<密码>&idx=0&page=1&formType=&metaKey=
  - 订阅: express-free.868382.xyz/..., 必须非浏览器 app UA (clash-verge 可用),
          只拉一次, token 随帖子过期作废
  - berryhub.org 有雷池 WAF: curl/python 均 468, 仅真实浏览器构建可过
"""
import base64
import email.utils
import json
import os
import re
import smtplib
import socket
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

BASE = Path(__file__).resolve().parent
STATE = BASE / "state"
WORK = BASE / "work"
STATE.mkdir(exist_ok=True)
WORK.mkdir(exist_ok=True)

UA_SUB = "clash-verge/v2.0.0"
MAIL_TO = os.environ.get("MAIL_TO", "719794448@qq.com")
MAIL_AUTHCODE = os.environ.get("MAIL_AUTHCODE", "")
BARK_KEY = os.environ.get("BARK_KEY", "")            # iPhone Bark 推送
DINGTALK_WEBHOOK = os.environ.get("DINGTALK_WEBHOOK", "")  # 钉钉群机器人 webhook
TEST_MODE = bool(os.environ.get("TEST_MODE"))
CDP_PORT = os.environ.get("CDP_PORT", "9223")
DEADLINE = time.time() + 40 * 60          # 视频等待窗口 (job 总超时 50min)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def sh(cmd, timeout=600, quiet=False, **kw):
    """跑外部命令, 返回 (code, stdout)"""
    log("$ " + (cmd if isinstance(cmd, str) else " ".join(cmd))[:160])
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                       text=True, timeout=timeout, **kw)
    if not quiet and r.stdout:
        print(r.stdout[-800:], flush=True)
    if r.returncode != 0 and not quiet:
        log(f"  exit={r.returncode} stderr={r.stderr[-300:] if r.stderr else ''}")
    return r.returncode, (r.stdout or "")



# ── VPN Gate 住宅 SSTP 路由 (雷池对数据中心 IP 强制人工验证, 住宅 IP 直接过) ──
SSTP_NODES = [
    ("vpn267947139.opengw.net", 1663),   # JP SoftBank 锚点
    ("vpn210599978.opengw.net", 995),    # KR KT 锚点
    ("vpn547433109.opengw.net", 995),    # JP KDDI
    ("kanratown.opengw.net", 992),       # JP NTT
    ("vpn177463451.opengw.net", 995),    # KR SKB
    ("vpn313325973.opengw.net", 995),    # KR LG
    ("vpn473197536.opengw.net", 1475),   # US Spectrum
]
SSTP_STATE = {"active": False, "pin_ip": None, "dev": "ppp9"}


def dial_sstp_and_route(domain="berryhub.org"):
    """SSTP 拨号住宅节点, 把 domain 的 IPv4 流量路由过去; 成功返回进程"""
    import shutil, re as _re
    if os.name == "nt" or not shutil.which("sstpc"):
        log("无 sstpc, 跳过住宅路由")
        return None
    for host, port in SSTP_NODES:
        proc = None
        try:
            log(f"SSTP 拨号 {host}:{port} (vpn/vpn)")
            proc = subprocess.Popen(
                ["sudo", "sstpc", "--cert-warn", f"{host}:{port}",
                 "usepeerdns", "require-mschap-v2", "refuse-eap", "noauth",
                 "user", "vpn", "password", "vpn", "unit", "9", "nodetach"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            time.sleep(10)
            chk = subprocess.run(["ip", "link", "show", SSTP_STATE["dev"]],
                                 capture_output=True, text=True)
            if chk.returncode != 0:
                raise RuntimeError("ppp 未建立")
            r = subprocess.run(["dig", "+short", domain, "A"], capture_output=True, text=True)
            ips = [l.strip() for l in r.stdout.splitlines()
                   if _re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]
            if not ips:
                raise RuntimeError(f"{domain} 无 A 记录")
            for ip in ips:
                subprocess.run(["sudo", "ip", "route", "add", f"{ip}/32", "dev", SSTP_STATE["dev"]],
                               capture_output=True)
            pin = ips[0]
            ver = subprocess.run(["curl", "-s", "--max-time", "15", "--interface",
                                  SSTP_STATE["dev"], "https://api.ipify.org"],
                                 capture_output=True, text=True)
            exit_ip = ver.stdout.strip()
            if not exit_ip:
                raise RuntimeError("ppp 出口验证失败")
            log(f"住宅路由就绪: {domain} → {pin} via {SSTP_STATE['dev']}, 出口IP {exit_ip}")
            SSTP_STATE.update(active=True, pin_ip=pin)
            return proc
        except Exception as e:
            log(f"SSTP {host}:{port} 失败: {e}")
            if proc:
                try:
                    import signal
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    proc.kill()
            time.sleep(2)
    return None


# ─────────────────── Electron / CDP ───────────────────

def warp_proxy_available(port=40000):
    """WARP 代理可用性探测 (socks5 ping 不握手, 只看端口)"""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.close()
        return True
    except Exception:
        return False


def kill_tree(proc):
    """杀掉整个进程树 (xvfb-run/electron)"""
    try:
        import signal
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def start_electron(start_url="https://berryhub.org/", force_no_proxy=False):
    is_win = os.name == "nt"
    is_mac = sys.platform == "darwin"
    if is_mac:
        electron = BASE / "node_modules" / "electron" / "dist/Electron.app/Contents/MacOS/Electron"
    else:
        electron = BASE / "node_modules" / "electron" / ("dist/electron.exe" if is_win else "dist/electron")
    if not electron.exists():
        raise RuntimeError(f"electron binary missing: {electron}")
    env = dict(os.environ, ELECTRON_CDP_PORT=CDP_PORT, ELECTRON_DISABLE_SANDBOX="1")
    if not is_mac:  # macOS 真机用原生 UA/真 GPU, 不做任何伪装
        env["ELECTRON_UA"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.130 Safari/537.36"
    if force_no_proxy:
        log("Electron 直连 berryhub (强制, WARP 已降级)")
    elif SSTP_STATE["active"] and SSTP_STATE["pin_ip"]:
        env["ELECTRON_RESOLVER_MAP"] = f"MAP berryhub.org {SSTP_STATE['pin_ip']}"
        log(f"Electron 直连(经住宅路由) berryhub → {SSTP_STATE['pin_ip']}")
    elif warp_proxy_available():
        env["ELECTRON_PROXY"] = "socks5://127.0.0.1:40000"
        log("Electron 经 WARP socks5 代理访问 berryhub (池IP不接触berryhub)")
    else:
        log("WARP 代理不可用, Electron 直连 berryhub")
    errlog = open(WORK / "electron-stderr.log", "w", encoding="utf-8")
    if is_win:
        proc = subprocess.Popen([str(electron), str(BASE / "electron-main.js"), start_url],
                                env=env, stderr=errlog, creationflags=subprocess.CREATE_NO_WINDOW,
                                start_new_session=True)
    elif is_mac:
        proc = subprocess.Popen([str(electron), str(BASE / "electron-main.js"), start_url],
                                env=env, stderr=errlog, start_new_session=True)
    else:
        proc = subprocess.Popen(["xvfb-run", "-a", str(electron), str(BASE / "electron-main.js"), start_url],
                                env=env, stderr=errlog, start_new_session=True)
    # 等 CDP 起来
    import urllib.request
    for i in range(90):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2) as r:
                json.loads(r.read().decode())
            return proc
        except Exception:
            if i == 30:
                try:
                    errlog.flush()
                    c = (WORK / "electron-stderr.log").read_text(encoding="utf-8", errors="replace")[-600:]
                    if c.strip():
                        log(f"electron stderr: {c}")
                except Exception:
                    pass
            time.sleep(1)
    raise RuntimeError("Electron CDP 未在 90s 内就绪")


FINGERPRINT_SPOOF_JS = """
// WebGL renderer 伪装 (SwiftShader 字符串是机器人标记)
const patchGL = (proto) => {
  if (!proto) return;
  const orig = proto.getParameter;
  proto.getParameter = function (p) {
    if (p === 37445) return 'Google Inc. (NVIDIA)';
    if (p === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
    return orig.call(this, p);
  };
};
try { patchGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype); } catch (e) {}
try { patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype); } catch (e) {}
try { Object.defineProperty(navigator, 'platform', {get: () => 'Win32'}); } catch (e) {}
try { Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); } catch (e) {}
try { Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8}); } catch (e) {}
try { Object.defineProperty(navigator, 'deviceMemory', {get: () => 8}); } catch (e) {}
try { Object.defineProperty(screen, 'width', {get: () => 1920}); } catch (e) {}
try { Object.defineProperty(screen, 'height', {get: () => 1080}); } catch (e) {}
try { Object.defineProperty(screen, 'availWidth', {get: () => 1920}); } catch (e) {}
try { Object.defineProperty(screen, 'availHeight', {get: () => 1040}); } catch (e) {}
// AudioContext 指纹 (无声卡环境标记)
try {
  const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (AC) {
    const origGetChannelData = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function (ch) {
      const d = origGetChannelData.call(this, ch);
      if (d.length === 45000 && d[0] === 0) { d[0] = 1e-7; }
      return d;
    };
  }
} catch (e) {}
// 时区一致性 (Intl 由 TZ env 控制, 这里对齐 DST 偏移探测)
try {
  const dgo = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function () { return -480; };
} catch (e) {}
"""


def connect_page():
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP_PORT}")
    ctx = browser.contexts[0]
    if not os.environ.get("ELECTRON_NO_SPOOF"):   # macOS 真机无需伪装(注入反而触发检测)
        ctx.add_init_script(FINGERPRINT_SPOOF_JS)   # 伪装必须在雷池挑战 JS 之前生效
    pg = ctx.pages[0] if ctx.pages else ctx.new_page()
    return pw, browser, ctx, pg


def wait_berryhub_ready(pg, tries=120):
    """纯被动等雷池自动放行 (实测约需数分钟; 主动点击反而重置挑战计时, 保持零交互)"""
    for i in range(tries):
        try:
            t = pg.title() or ""
            if "BerryHub" in t:
                log(f"berryhub 页面就绪 ({i*5}s)")
                return True
            if i in (12, 36, 72, 108):
                txt = (pg.evaluate('document.body.innerText') or "").replace(chr(10), " ")[:80]
                log(f"等待中 {i*5}s: {txt!r}")
        except Exception:
            pass
        time.sleep(5)
    raise RuntimeError(f"berryhub 未就绪(雷池未放行, 等待600s)")



def api_posts(pg):
    """页面内 fetch 帖子列表 (不受雷池影响)"""
    return pg.evaluate(
        'async () => { const r = await fetch("/wp-json/wp/v2/posts?per_page=3&orderby=date&order=desc", {credentials:"include"}); return {s: r.status, j: await r.json()} }'
    )


# ─────────────────── 密码提取 (OCR) ───────────────────

def get_channel_url(pg, post_url):
    """从帖子页找 YouTube 频道链接"""
    pg.goto(post_url, timeout=40000)
    time.sleep(3)
    return pg.evaluate(
        '() => { const a = [...document.querySelectorAll("a")].find(a => /youtube/i.test(a.href)); return a ? a.href : null }'
    )


def latest_video_via_ytdlp(channel_url):
    """yt-dlp 找频道最新视频 (海外 runner 直连)"""
    code, out = sh(["yt-dlp", "--flat-playlist", "--playlist-end", "3",
                    "--print", "%(id)s|%(title)s|%(upload_date)s",
                    channel_url.rstrip("/") + "/videos"], timeout=120, quiet=True)
    rows = [l.split("|") for l in out.strip().splitlines() if "|" in l]
    return rows  # [(id, title, upload_date), ...]


def resolve_video_candidates(channel_url):
    """频道链接可能是「频道页」或「具体视频页」, 都处理"""
    cands = []
    m = re.search(r"v=([\w-]{11})|youtu\.be/([\w-]{11})|shorts/([\w-]{11})", channel_url)
    if m:
        vid = next(g for g in m.groups() if g)
        cands.append(vid)                      # 帖子直链的视频 = 密码视频首选
        # 频道最新视频作后备(链接错了也有救)
        ch = re.match(r"(https://www\.youtube\.com/(@[\w.-]+|channel/[\w-]+|c/[\w.-]+))", channel_url)
        if ch:
            rows = latest_video_via_ytdlp(ch.group(1))
            if rows and rows[0][0] != vid:
                cands.append(rows[0][0])
    else:
        rows = latest_video_via_ytdlp(channel_url)
        if rows:
            cands.append(rows[0][0])
    return cands


def download_video(vid):
    out_t = str(WORK / "video.mp4")
    desc_t = str(WORK / "video.description")
    code, _ = sh(["yt-dlp", "-f", "bv*[height<=480][ext=mp4]+ba[ext=m4a]/b[height<=480]/b",
                  "--write-description", "--skip-download", "-o", str(WORK / "video"),
                  f"https://www.youtube.com/watch?v={vid}"], timeout=600, quiet=True)
    if code != 0 or not Path(desc_t).exists():
        return None, None
    code, _ = sh(["yt-dlp", "-f", "b[height<=480]/b", "--no-playlist",
                  "-o", out_t, f"https://www.youtube.com/watch?v={vid}"], timeout=900, quiet=True)
    if code != 0 or not Path(out_t).exists():
        return None, None
    return out_t, desc_t


def ocr_password_candidates(video_path):
    """抽帧 + RapidOCR, 跨帧多数投票 → 密码候选列表"""
    import glob
    frames = WORK / "frames"
    if frames.exists():
        for f in frames.glob("*.jpg"):
            f.unlink()
    frames.mkdir(exist_ok=True)
    code, _ = sh(["ffmpeg", "-y", "-loglevel", "error", "-i", video_path,
                  "-vf", "fps=2", str(frames / "f%04d.jpg")], timeout=600, quiet=True)
    flist = sorted(glob.glob(str(frames / "f*.jpg")))
    log(f"抽帧 {len(flist)} 张")
    if not flist:
        return []

    from rapidocr_onnxruntime import RapidOCR
    ocr = RapidOCR()
    votes = {}
    for i, f in enumerate(flist):
        try:
            res, _ = ocr(f)
            texts = [x[1] for x in res] if res else []
        except Exception:
            continue
        joined = " ".join(texts)
        if ("密码" not in joined) and ("获取" not in joined):
            continue
        cands = set(re.findall(r"(\d{3,8})", joined))
        for c in cands:
            votes[c] = votes.get(c, 0) + 1
        if i % 60 == 0:
            log(f"  OCR 进度 {i}/{len(flist)} 票:{votes}")
    ranked = sorted(votes.items(), key=lambda kv: -kv[1])
    log(f"OCR 票选: {ranked[:8]}")
    # 共识≥2 的优先, 其后单帧候选兜底
    strong = [c for c, n in ranked if n >= 2]
    weak = [c for c, n in ranked if n == 1]
    return (strong + weak)[:5]


# ─────────────────── 解锁 / 拉订阅 ───────────────────

def try_unlock(pg, post_url, fid, pw):
    pg.goto(post_url, timeout=40000)
    time.sleep(2)
    body = f"fields%5B{fid}%5D={pw}&g-recaptcha-response=&area=0&pss={pw}&idx=0&page=1&formType=&metaKey="
    return pg.evaluate(
        'async ([body, fid]) => { const r = await fetch("/wp-json/wppp/v1/check-content-password/" + fid, {method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}, body, credentials:"include"}); const j = await r.json(); const m = (j.content||"").match(/https:\\/\\/express-free[^"<\\s]+/); return {isValid: j.isValid, subLink: m ? m[0] : null} }',
        [body, fid],
    )


def fetch_sub(sublink, out_dir):
    """curl 拉订阅 (JA3 指纹要求, 仅一次)"""
    out_dir.mkdir(exist_ok=True)
    raw_p = out_dir / "raw.txt"
    subprocess.run(["curl", "-s", "--max-time", "40", "-A", UA_SUB, sublink, "-o", str(raw_p)], timeout=60)
    raw = raw_p.read_text(encoding="utf-8", errors="replace")
    if '"status":"fail"' in raw:
        return None, raw.strip()[:200]
    try:
        pad = raw.strip() + "=" * (-len(raw.strip()) % 4)
        decoded = base64.b64decode(pad).decode("utf-8", "replace")
    except Exception:
        decoded = raw
    uris = [u for u in decoded.splitlines() if u.strip() and "://" in u]
    (out_dir / "uris.txt").write_text("\n".join(uris), encoding="utf-8")
    return uris, None


def tcp_alive(host, port, timeout=6):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def test_nodes(uris, out_dir):
    results = []
    def probe(u):
        m = re.match(r"^[a-z0-9]+://[^@/]+@(\[[^\]]+\]|[^:/]+):(\d+)", u)
        if not m:
            return (u, False, "?")
        host, port = m.group(1).strip("[]"), m.group(2)
        tag = u.split("#")[-1][:30] if "#" in u else host
        return (tag, tcp_alive(host, port), f"{host}:{port}")
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(probe, uris))
    alive = [r for r in results if r[1]]
    (out_dir / "report.txt").write_text(
        "\n".join(f"{'存活' if a else '超时'}  {t}  {hp}" for t, a, hp in results), encoding="utf-8")
    return results, len(alive)


# ─────────────────── 邮件 ───────────────────

def notify(title, body):
    """多通道通知: Bark > 钉钉 > 邮件; 全缺则落盘"""
    if TEST_MODE:
        log(f"[TEST_MODE] 跳过通知: {title}")
        return False
    if BARK_KEY:
        try:
            import urllib.request
            req = urllib.request.Request(
                "https://api.day.app/push",
                data=json.dumps({"device_key": BARK_KEY, "title": title[:60],
                                 "body": body[:4000], "group": "BerryHub",
                                 "sound": "bell"}).encode(),
                headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.loads(r.read().decode())
            log(f"Bark push: {out.get('code')}")
            return True
        except Exception as e:
            log(f"Bark fail: {e}")
    if DINGTALK_WEBHOOK:
        try:
            import urllib.request
            req = urllib.request.Request(
                DINGTALK_WEBHOOK,
                data=json.dumps({"msgtype": "markdown",
                                 "markdown": {"title": title[:60],
                                              "text": f"### {title}" + chr(10)*2 + body}}).encode(),
                headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
            with urllib.request.urlopen(req, timeout=20) as r:
                out = json.loads(r.read().decode())
            log(f"DingTalk push: {out}")
            return True
        except Exception as e:
            log(f"DingTalk fail: {e}")
    return send_mail(title, body, None)

def send_mail(subject, body, attach=None):
    if TEST_MODE:
        log(f"[TEST_MODE] 跳过发信: {subject}")
        return False
    if not MAIL_AUTHCODE:
        log(f"[未配置 MAIL_AUTHCODE] 邮件内容落盘: {subject}")
        (STATE / "last-mail-draft.txt").write_text(f"{subject}\n\n{body}", encoding="utf-8")
        return False
    msg = MIMEMultipart()
    msg["From"] = MAIL_TO
    msg["To"] = MAIL_TO
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate()
    msg.attach(MIMEText(body, "plain", "utf-8"))
    if attach and Path(attach).exists():
        with open(attach, "rb") as f:
            part = MIMEApplication(f.read())
        part.add_header("Content-Disposition", "attachment", filename=Path(attach).name)
        msg.attach(part)
    with smtplib.SMTP_SSL("smtp.qq.com", 465, timeout=30) as s:
        s.login(MAIL_TO, MAIL_AUTHCODE)
        s.sendmail(MAIL_TO, [MAIL_TO], msg.as_string())
    log("邮件已发送")
    return True


# ─────────────────── 主流程 ───────────────────

def main():
    sstp_proc = None
    if os.name != "nt" and sys.platform != "darwin":
        sstp_proc = dial_sstp_and_route()
    cookies_f = STATE / "berry-cookies.json"
    have_cookies = cookies_f.exists()
    start_url = "about:blank" if have_cookies else "https://berryhub.org/"
    proc = start_electron(start_url)
    pw = browser = None
    try:
        pw, browser, ctx, pg = connect_page()
        if have_cookies:
            try:
                ctx.add_cookies(json.loads(cookies_f.read_text(encoding="utf-8")))
                log("已载入上次存档的通行 cookie")
            except Exception as e:
                log(f"cookie 载入失败(忽略): {e}")
        pg.goto("https://berryhub.org/", timeout=40000)
        try:
            wait_berryhub_ready(pg)
        except RuntimeError as gate_err:
            used_proxy = warp_proxy_available()
            kill_tree(proc)
            if not used_proxy:
                raise
            log("WARP 出口被拦, 降级直连重试")
            proc = start_electron("https://berryhub.org/", force_no_proxy=True)
            pw.stop()
            pw, browser, ctx, pg = connect_page()
            pg.goto("https://berryhub.org/", timeout=40000)
            wait_berryhub_ready(pg)
        try:
            cks = ctx.cookies("https://berryhub.org")
            cookies_f.write_text(json.dumps(cks), encoding="utf-8")
            log(f"通行 cookie 已存档 ({len(cks)} 条)")
        except Exception as e:
            log(f"cookie 存档失败(忽略): {e}")

        # 1) 侦察最新帖
        r = api_posts(pg)
        if r["s"] != 200:
            raise RuntimeError(f"wp-json 状态 {r['s']}")
        latest = r["j"][0]
        link, title, date = latest["link"], latest["title"]["rendered"], latest["date"]
        log(f"最新帖: {title} ({date})")

        last = (STATE / "last-post.txt").read_text(encoding="utf-8").strip() if (STATE / "last-post.txt").exists() else ""
        if link == last:
            log("无新帖, 结束")
            notify("BerryHub 今日无新帖, 系统正常",
                   f"今天 BerryHub 没有发布新一期(它自己偶尔跳过, 如 11-21)。" + chr(10)*2 +
                   f"最近一次成功收割: {(STATE / 'last-harvest.json').read_text(encoding='utf-8')[:200] if (STATE / 'last-harvest.json').exists() else '尚无'}" + chr(10) +
                   f"系统每日 20:05 自动巡检, 无需任何操作。")
            return 0
        log(f"发现新帖! 处理 {link}")

        # 2) 频道链接 + 字段ID
        channel = get_channel_url(pg, link)
        if not channel:
            raise RuntimeError("帖子页未找到 YouTube 频道链接")
        log(f"频道: {channel}")
        fid = pg.evaluate(
            '() => { const i = document.querySelector("input[type=password]"); return i ? i.name : null }'
        )
        if not fid:
            raise RuntimeError("未找到密码字段ID")
        log(f"字段ID: {fid}")

        # 3) 视频候选 (等发布, 最多到 deadline)
        video_cands = []
        while time.time() < DEADLINE and not video_cands:
            video_cands = resolve_video_candidates(channel)
            if not video_cands:
                log("视频未就绪, 5 分钟后重试")
                time.sleep(300)
        if not video_cands:
            raise RuntimeError("deadline 前未取到视频")
        log(f"视频候选: {video_cands}")

        # 4/5) 逐候选下载+提密码, 首个出候选的胜出
        all_cands = []
        for vid in video_cands:
            video_path, desc_path = download_video(vid)
            if not video_path:
                log(f"视频 {vid} 下载失败, 试下一个")
                continue
            desc = Path(desc_path).read_text(encoding="utf-8", errors="replace")
            desc_cands = list(dict.fromkeys(re.findall(r"(\d{4,8})", desc)))[:3]
            log(f"描述数字候选: {desc_cands}")
            ocr_cands = ocr_password_candidates(video_path)
            all_cands = list(dict.fromkeys(desc_cands + ocr_cands))
            log(f"密码候选: {all_cands}")
            if all_cands:
                break
        if not all_cands:
            raise RuntimeError("OCR 未得到任何密码候选")

        # 6) 解锁 (最多试 4 个候选)
        sublink = None
        for i, cand in enumerate(all_cands[:4]):
            res = try_unlock(pg, link, fid, cand)
            log(f"尝试密码 {cand}: isValid={res.get('isValid')} subLink={'有' if res.get('subLink') else '无'}")
            if res.get("isValid") and res.get("subLink"):
                sublink = res["subLink"]
                break
        if not sublink:
            raise RuntimeError(f"全部候选被拒: {all_cands[:4]}")

        # 7) 拉订阅 + 测活
        out_dir = WORK / "harvest"
        uris, err = fetch_sub(sublink, out_dir)
        n_alive = 0
        if uris is None:
            log(f"订阅API拒绝: {err}")
        else:
            log(f"节点数: {len(uris)}")
            results, n_alive = test_nodes(uris, out_dir)
            log(f"TCP 存活: {n_alive}/{len(uris)}")

        # 8) 邮件投递
        exp_note = ""
        m = re.search(r"(\d{4}) 年 (\d+) 月 (\d+) 日[^~]*?[~–]?\s*(\d+) 月 (\d+) 日", title)
        subject = f"BerryHub 公益节点 {time.strftime('%m-%d')}: {n_alive}节点可用"
        if uris is None:
            body = (f"新帖已解锁, 但订阅链接 token 已失效(过期)。\n\n帖子: {title}\n链接: {link}\n"
                    f"订阅: {sublink}\nAPI返回: {err}\n\n(可能是刷新时点太晚, 明天会自动重试新帖)")
        else:
            body = (f"今日 BerryHub 公益节点已收割:\n\n"
                    f"帖子: {title}\n订阅链接(28小时内有效, 请尽快导入):\n{sublink}\n\n"
                    f"节点总数: {len(uris)} | TCP存活: {n_alive}\n\n"
                    f"导入方法: Shadowrocket/Clash 添加订阅 → 粘贴上方链接\n"
                    f"注意: 请清理旧订阅, 频繁刷新失效订阅会触发封IP")
        notify(subject, body)

        # 9) 状态落盘
        (STATE / "last-post.txt").write_text(link, encoding="utf-8")
        (STATE / "last-harvest.json").write_text(json.dumps({
            "date": time.strftime("%F %T"), "post": link, "password": cand,
            "sublink": sublink, "nodes": len(uris) if uris else 0, "alive": n_alive,
        }, ensure_ascii=False), encoding="utf-8")
        return 0
    except Exception as e:
        log(f"!! 失败: {e}")
        traceback.print_exc()
        try:
            notify(f"BerryHub 收割失败 {time.strftime('%m-%d %H:%M')}",
                      f"失败原因: {e}\n\n详见 Actions 日志。")
        except Exception as me:
            log(f"(失败邮件也发不出: {me})")
        return 1
    finally:
        if pw:
            try: pw.stop()
            except Exception: pass
        try:
            import signal
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try: proc.kill()
            except Exception: pass
        if sstp_proc:
            try:
                import signal
                os.killpg(os.getpgid(sstp_proc.pid), signal.SIGTERM)
            except Exception:
                sstp_proc.kill()


if __name__ == "__main__":
    sys.exit(main())
