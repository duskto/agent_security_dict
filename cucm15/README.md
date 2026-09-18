# cucm15（Cisco Unified Communications Manager）

> 本目录记录该虚拟机上**已实际动态复现**的漏洞；候选与待验证条目见各 CVE 子目录内的 `复现情况.md`。

## 资产确权（2026-09 实测）

| 项 | 值 |
|---|---|
| 台账条目 | #181 `cucm15`，登记版本 `15.0.1.14901` |
| **真实 IP** | **`192.168.188.x`** |
| 台账登记 IP | `192.168.188.x` —— **已失效**（该 IP 现由 Tableau 服务占用，非 Cisco） |
| 确权依据 | ESXi `192.168.188.x` 虚拟机 444 `cucm15` 的 guest 信息：`hostName=cucm15`、`ipAddress=192.168.188.x` |
| 实测版本 | **15.0.1**（无认证端点 `GET /cucm-uds/version`） |
| 开放端口 | TCP 22 / 80 / 443 / 8443 / 8080 |
| 无认证面 | `/cucm-uds/version`(200)、`/cucm-uds/servers`(200)、`/ccmadmin/`(200)、`/ucmuser/`(200)、`/webdialer/*`(200) |

> **注意**：本仓库 `历史漏洞台账.md` 中 Cisco 资产的 IP 映射大面积失效（IP 已被回收改派给其它产品），
> 后续所有 Cisco 条目一律以 ESXi guest 信息 + 实测指纹确权，不得沿用台账 IP。

## 漏洞清单

| 子目录 | 漏洞 | 类型 | 认证边界 | 状态 |
|---|---|---|---|---|
| `CVE-2026-20230/` | WebDialer 未认证 SSRF → 写 JSP → 命令执行 | CWE-918 → CWE-94 | **pre-auth** | ✅ **已复现**（取得 `uid=502(tomcat)` 回显；root 提权未验证） |

### CVE-2026-20230 复现要点（细节见子目录 `复现情况.md`）
- 入口：`/cmplatform/installClusterStatusExecute?action=clusterNodeInstallStatus&hostname=<X>#`
  → 内部 `https://<X>/platformcom/api/v1/software/installstages/`（未认证 SSRF）
- 链：SSRF → `/webdialer/services/AdminService?method=<WSDD>` 注册带 `LogHandler` 的服务
  → LogHandler 把请求报文写入绝对路径 `…/axis2-web/<随机>.jsp`（内容用 `<![CDATA[<%…%>]]>` 保原始）
  → Tomcat 编译执行 → `Runtime.exec` 回显
- 三个必须的构造细节：**`xmlns:java` 命名空间声明**、**`!-->` 前缀且载荷末尾不带 `>`**、**JSP 每次用新随机文件名**
- 清理：27 个自建服务已全部 undeploy（`?wsdl` 复核 404）；落盘 JSP 与临时文件已删除；原厂 `ctf*` 等未被触碰
- **PoC**：`CVE-2026-20230/poc/CVE-2026-20230-poc.py`（本地修正版，端到端跑通含自动清理；`--check` 只读探测）
