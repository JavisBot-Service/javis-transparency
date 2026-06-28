#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Javis 模型真偽 · 公開審計探針 (public transparency audit probe)
================================================================
本脚本在 GitHub Actions（非 Javis 服务器）上运行，调用 Javis 对外 API
(api.javis.bot) 对在售模型做模型替换审计，把原始结果与可复现证据写入仓库，
由 github-actions[bot] 提交。任何人可在本仓库 Actions 页查看每次运行的原始日志。

检测方法实现自已发表的同行评审研究（见生成页「方法與出處」）：
  - Cai et al., "Are You Getting What You Pay For? Auditing Model Substitution in LLM APIs", arXiv:2504.04715
  - Zhang et al. (CISPA), "Real Money, Fake Models: Deceptive Model Claims in Shadow APIs", arXiv:2603.01919
  - Zhu et al., "Auditing Black-Box LLM APIs with a Rank-Based Uniformity Test", arXiv:2506.06975
  - Lin et al., "Behavioral Consistency and Transparency Analysis on LLM API Gateways" (IMC'26), arXiv:2604.21083

用法:
  python3 probe_public.py --capture-baseline   # 首次/重采公开基线（手动 dispatch）
  python3 probe_public.py                       # 审计：探测→判定→写历史→渲染透明页

纯标准库；探测 Key 经环境变量 JAVIS_PROBE_KEY 注入（GitHub Secrets），脚本绝不打印它。
"""
import argparse
import datetime as _dt
import difflib
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BASELINE_DIR = os.path.join(HERE, "baselines")
DOCS = os.path.join(REPO, "docs")
DATA = os.path.join(DOCS, "data")
HISTORY_PATH = os.path.join(DATA, "history.json")
PAGE_PATH = os.path.join(DOCS, "index.html")

# 已验真的方法出处（每条均经 arXiv 原页核实，2026-06）
SOURCES = [
    ("Are You Getting What You Pay For? Auditing Model Substitution in LLM APIs",
     "Cai, Shi, Zhao, Song (UC Berkeley)", "arXiv:2504.04715", "https://arxiv.org/abs/2504.04715",
     "形式化定义 LLM API「模型替换」问题并评估检测方法——提供方暗中以更便宜模型（量化/小模型）替换所宣称模型。"),
    ("Real Money, Fake Models: Deceptive Model Claims in Shadow APIs",
     "Zhang, Jiang, Chen, Backes, Shen, Zhang (CISPA)", "arXiv:2603.01919", "https://arxiv.org/abs/2603.01919",
     "系统审计影子 API，发现 45.83% 的指纹测试未通过模型身份验证——本审计实现同类指纹方法。"),
    ("Auditing Black-Box LLM APIs with a Rank-Based Uniformity Test",
     "Zhu, Ye, Qiu, … Popa, Neiswanger", "arXiv:2506.06975", "https://arxiv.org/abs/2506.06975",
     "黑盒审计模型替换，并诚实列出提供方的规避手段（量化、随机替换、对探测的对抗响应）——故本审计多信号叠加且承认局限。"),
    ("Behavioral Consistency and Transparency Analysis on LLM API Gateways (IMC'26)",
     "Lin, Wan, Pei, Xu, Xu, Xue", "arXiv:2604.21083", "https://arxiv.org/abs/2604.21083",
     "黑盒框架 GateScope 检测网关的模型降级/替换、静默截断、计费偏差等行为。"),
]


def load_json(p):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(p, obj):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)


def now_iso():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(m):
    print("[%s] %s" % (now_iso(), m), flush=True)


def call_model(api_base, key, model, messages, temperature, max_tokens, timeout, retries):
    url = api_base.rstrip("/") + "/v1/chat/completions"
    payload = json.dumps({"model": model, "messages": messages, "temperature": temperature,
                          "max_tokens": max_tokens, "stream": False}).encode("utf-8")
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
    last = None
    for attempt in range(retries + 1):
        t0 = time.time()
        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            choice = (body.get("choices") or [{}])[0]
            usage = body.get("usage") or {}
            return {"ok": True, "text": (((choice.get("message") or {}).get("content")) or "").strip(),
                    "response_model": body.get("model"), "prompt_tokens": usage.get("prompt_tokens"),
                    "latency_ms": int((time.time() - t0) * 1000), "error": None}
        except urllib.error.HTTPError as e:
            try:
                d = e.read().decode("utf-8")[:200]
            except Exception:
                d = ""
            last = "HTTP %s %s" % (e.code, d)
        except Exception as e:  # noqa: BLE001
            last = "%s: %s" % (type(e).__name__, e)
        time.sleep(1.5 * (attempt + 1))
    return {"ok": False, "text": "", "response_model": None, "prompt_tokens": None,
            "latency_ms": None, "error": last}


def gather(cfg, probes, key, mc):
    rq = cfg["request"]

    def c(msgs):
        return call_model(cfg["api_base"], key, mc["name"], msgs, rq["temperature"],
                          rq["max_tokens"], rq["timeout_seconds"], rq["retries"])
    ev = {"model": mc["name"], "ts": now_iso(), "completions": {}, "self_id": "",
          "response_model": None, "token": {}, "errors": []}
    r = c(probes["self_id"]["messages"])
    if r["ok"]:
        ev["self_id"] = r["text"]
        ev["response_model"] = r.get("response_model")
    else:
        ev["errors"].append("self_id: " + str(r["error"]))
    for p in probes["completions"]:
        r = c(p["messages"])
        if r["ok"]:
            ev["completions"][p["id"]] = r["text"]
            if not ev["response_model"]:
                ev["response_model"] = r.get("response_model")
        else:
            ev["errors"].append(p["id"] + ": " + str(r["error"]))
    if mc.get("token_signal"):
        r = c(probes["token_probe"]["messages"])
        if r["ok"]:
            ev["token"] = {"prompt_tokens": r["prompt_tokens"]}
    return ev


def _ratio(a, b):
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()


def score(ev, base, mc, probes, th):
    signals, strong = [], 0
    if ev.get("errors") and not ev.get("completions"):
        return {"verdict": "error", "score": 0.0, "signals": ["探测失败: " + "; ".join(ev["errors"][:2])]}
    markers = probes["family_markers"]
    fam = mc["family"]
    hits = set(m for m in markers.get(fam, []) if m.lower() in (ev.get("self_id", "") or "").lower())
    for t in ev.get("completions", {}).values():
        hits |= set(m for m in markers.get(fam, []) if m.lower() in (t or "").lower())
    rm = ev.get("response_model")
    id_mismatch = bool(rm) and (fam.lower() not in str(rm).lower())
    if hits or id_mismatch:
        strong += 1
        why = []
        if hits:
            why.append("响应含他家族标志 " + ", ".join(sorted(hits)))
        if id_mismatch:
            why.append("上游模型 ID『%s』与家族『%s』不符" % (rm, fam))
        signals.append("家族矛盾: " + "；".join(why))
    ratios = [_ratio(cur, base["completions"][pid]) for pid, cur in ev.get("completions", {}).items()
              if base and pid in base.get("completions", {})]
    avg = sum(ratios) / len(ratios) if ratios else None
    if avg is not None:
        if avg < th["completion_fail"]:
            strong += 1
            signals.append("补全大幅偏移: 相似度 %.2f" % avg)
        elif avg < th["completion_pass"]:
            signals.append("补全轻微偏移: 相似度 %.2f" % avg)
    if avg is None and not (hits or id_mismatch):
        return {"verdict": "warn", "score": 0.5, "signals": ["无基线可比对"]}
    sc = avg if avg is not None else (0.0 if (hits or id_mismatch) else 0.6)
    verdict = "fail" if strong >= 2 else ("warn" if strong == 1 or (avg is not None and avg < th["completion_pass"]) else "pass")
    return {"verdict": verdict, "score": round(float(sc), 3), "signals": signals or ["各信号与基线一致"]}


def bpath(model):
    return os.path.join(BASELINE_DIR, "%s.%s.json" % (model.replace("/", "_"),
                        hashlib.md5(model.encode()).hexdigest()[:8]))


def append_history(results, retention):
    hist = load_json(HISTORY_PATH) if os.path.exists(HISTORY_PATH) else {}
    for r in results:
        hist.setdefault(r["model"], [])
        e = {"ts": r["ts"], "verdict": r["verdict"], "score": r["score"],
             "response_model": r.get("response_model"), "signals": r["signals"]}
        if not (hist[r["model"]] and hist[r["model"]][-1]["ts"] == e["ts"]):
            hist[r["model"]].append(e)
        hist[r["model"]] = hist[r["model"]][-retention:]
    save_json(HISTORY_PATH, hist)
    return hist


# ---------- 透明页（全透明 + 方法出处 + 自验 + 局限） ----------
STATE = {"pass": ("通過", "#16a34a", "✓"), "warn": ("關注", "#d97706", "⚠"),
         "fail": ("異常", "#dc2626", "✕"), "error": ("無法檢測", "#6b7280", "?")}


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def render(cfg, results, hist, probes, repo_slug):
    rows = ""
    for r in results:
        label, color, icon = STATE.get(r["verdict"], STATE["error"])
        series = (hist.get(r["model"]) or [])[-cfg["page"]["timeline_points"]:]
        dots = "".join('<span class="dot" style="background:%s" title="%s %s"></span>'
                       % (STATE.get(h["verdict"], STATE["error"])[1], h["ts"], STATE.get(h["verdict"], STATE["error"])[0])
                       for h in series)
        rows += ('<tr><td class="m">%s</td><td><span class="badge" style="background:%s">%s %s</span></td>'
                 '<td class="rm">%s</td><td class="tl">%s</td><td class="ts">%s</td></tr>'
                 % (esc(r["model"]), color, icon, label, esc(r.get("response_model") or "—"), dots, esc(r["ts"])))

    src_rows = "".join(
        '<li><a href="%s" target="_blank" rel="noopener">%s</a> · <span class="src-au">%s</span> · <code>%s</code><br><span class="src-d">%s</span></li>'
        % (u, esc(t), esc(au), esc(idn), esc(d)) for (t, au, idn, u, d) in SOURCES)

    # 自验区：列出确定性 prompt + 一段 curl
    verify_prompts = "".join(
        '<li><code>%s</code></li>' % esc(p["messages"][0]["content"]) for p in probes["completions"])
    curl = ("curl -s %s/v1/chat/completions \\\n"
            "  -H \"Authorization: Bearer $YOUR_KEY\" -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"model\":\"claude-opus-4.8\",\"temperature\":0,\"max_tokens\":50,"
            "\"messages\":[{\"role\":\"user\",\"content\":\"List the first 12 prime numbers separated by single spaces, on one line, nothing else.\"}]}'\n"
            "# 看返回 JSON 的 \"model\" 字段 = 上游真实模型 ID；temp=0 下补全应与本页一致") % cfg["api_base"]

    html = """<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Javis · 模型真偽公開審計</title><style>
:root{{--ink:#1b1f27;--card:#f7f8fa;--bd:#e6e8ec;--mut:#6b7280}}
*{{box-sizing:border-box}}body{{margin:0;background:#fff;color:var(--ink);
font-family:"PingFang TC","Microsoft JhengHei",-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.65;padding:46px 18px}}
.wrap{{max-width:920px;margin:0 auto}}
h1{{font-size:28px;margin:0 0 4px;background:linear-gradient(90deg,#4f46e5,#db2777);-webkit-background-clip:text;background-clip:text;color:transparent}}
h2{{font-size:19px;margin:34px 0 10px;border-left:4px solid #4f46e5;padding-left:10px}}
.sub{{color:var(--mut);margin:0 0 8px;font-size:15px}}
.trust{{background:#eef2ff;border:1px solid #c7d2fe;border-radius:12px;padding:14px 16px;font-size:14px;margin:16px 0}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);border-radius:14px;overflow:hidden;font-size:14px}}
th,td{{padding:12px 14px;text-align:left;border-bottom:1px solid var(--bd)}}
th{{background:#eef0f4;color:#3b4250;font-weight:600}}tr:last-child td{{border-bottom:none}}
td.m{{font-weight:600}}td.rm{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#4b5563}}
.badge{{color:#fff;padding:2px 9px;border-radius:999px;font-size:12px;white-space:nowrap}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:2px}}
.ts{{color:#9aa2b0;font-size:11px;white-space:nowrap}}
code{{background:#f1f3f7;padding:1px 5px;border-radius:5px;font-size:12.5px}}
pre{{background:#0d1117;color:#e6edf3;padding:14px;border-radius:10px;overflow:auto;font-size:12.5px;line-height:1.5}}
ul{{padding-left:20px}}li{{margin:6px 0}}
.src-au{{color:var(--mut);font-size:13px}}.src-d{{color:#4b5563;font-size:13px}}
.warn{{background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;padding:14px 16px;font-size:14px}}
.ft{{margin-top:30px;color:#9aa2b0;font-size:12px;text-align:center}}
a{{color:#4f46e5}}
</style></head><body><div class="wrap">
<h1>模型真偽 · 公開審計</h1>
<p class="sub">最後更新 {updated}（UTC）</p>
<div class="trust">本頁的檢測<strong>代碼、運行記錄、結果全部公開</strong>，由 <strong>GitHub Actions 自動定時運行</strong>（非 Javis 伺服器），結果由 <code>github-actions[bot]</code> 自動提交、git 歷史防篡改。
不信？➜ <a href="https://github.com/{repo}/actions" target="_blank" rel="noopener">查看每一次運行的原始日誌</a> ｜ <a href="https://github.com/{repo}" target="_blank" rel="noopener">審計代碼</a></div>

<h2>當前狀態</h2>
<table><thead><tr><th>模型</th><th>檢測</th><th>上游回傳模型 ID</th><th>近期</th><th>最後檢測</th></tr></thead>
<tbody>{rows}</tbody></table>
<p class="sub" style="margin-top:8px;font-size:13px">「上游回傳模型 ID」取自每次 API 響應的 <code>model</code> 欄位（上游原樣透傳，如 <code>claude-haiku-4-5-20251001</code>）。</p>

<h2>方法與出處</h2>
<p class="sub">本審計實現的是安全學術界已發表的<strong>模型替換審計方法</strong>，非自創。各來源均經原始頁面核實：</p>
<ul>{sources}</ul>

<h2>自己驗證（不必信我們）</h2>
<p class="sub">以下為本頁所用的確定性探針（<code>temperature=0</code>）。用你自己的 key 對同一 endpoint 跑，結果應與本頁一致；並查響應 <code>model</code> 欄位是否為宣稱模型：</p>
<ul>{vprompts}</ul>
<pre>{curl}</pre>

<h2>局限（誠實聲明）</h2>
<div class="warn">本檢測為<strong>機率性一致性審計，非密碼學意義的「證明為真」</strong>。理論上，提供方可對已知的審計來源（如 GitHub Actions 的 IP）返回真模型、而對真實流量掉包——這是所有黑盒審計的共同局限（見 arXiv:2506.06975）。我們以「你自己可複現」（上方）來緩解：審計用的探針與你日常呼叫走的是同一個 endpoint。</div>

<div class="ft">由 GitHub Actions 自動生成 · 代碼與數據開源於 <a href="https://github.com/{repo}" target="_blank" rel="noopener">{repo}</a></div>
</div></body></html>""".format(
        updated=now_iso(), repo=repo_slug, rows=rows or '<tr><td colspan="5">尚無資料</td></tr>',
        sources=src_rows, vprompts=verify_prompts, curl=esc(curl))
    os.makedirs(DOCS, exist_ok=True)
    with open(PAGE_PATH, "w", encoding="utf-8") as f:
        f.write(html)
    log("已渲染透明页 -> " + PAGE_PATH)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture-baseline", action="store_true")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--probes", default=os.path.join(HERE, "probes.json"))
    args = ap.parse_args()
    cfg = load_json(args.config)
    probes = load_json(args.probes)
    repo_slug = os.environ.get("GITHUB_REPOSITORY", cfg.get("repo_slug", "JavisBot-Service/javis-transparency"))
    key = os.environ.get(cfg["probe_key_env"], "")
    if not key:
        log("缺少探测 Key（环境变量 %s）。" % cfg["probe_key_env"])
        sys.exit(2)

    if args.capture_baseline:
        for mc in cfg["models"]:
            if not mc.get("enabled", True):
                continue
            ev = gather(cfg, probes, key, mc)
            ev["captured_at"] = now_iso()
            save_json(bpath(mc["name"]), ev)
            log("基线已采集: %s（%d 补全, %d 错误）" % (mc["name"], len(ev["completions"]), len(ev["errors"])))
        return

    results = []
    for mc in cfg["models"]:
        if not mc.get("enabled", True):
            continue
        ev = gather(cfg, probes, key, mc)
        base = load_json(bpath(mc["name"])) if os.path.exists(bpath(mc["name"])) else None
        sc = score(ev, base, mc, probes, cfg["thresholds"])
        results.append({"model": mc["name"], "ts": ev["ts"], "response_model": ev.get("response_model"),
                        "verdict": sc["verdict"], "score": sc["score"], "signals": sc["signals"]})
        log("  %-20s %-5s | %s" % (mc["name"], sc["verdict"].upper(), sc["signals"][0]))
    hist = append_history(results, cfg["history"]["retention_per_model"])
    render(cfg, results, hist, probes, repo_slug)
    log("完成：%d 模型。" % len(results))


if __name__ == "__main__":
    main()
