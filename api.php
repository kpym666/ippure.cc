<?php
// =========================================================
// 1. 强制禁用所有缓存：防止 CDN、Nginx 或客户端缓存旧的数据
// =========================================================
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

// =========================================================
// 2. 安全防盗链控制：只允许你的域名调用，同时允许命令行直接请求
// =========================================================
$allowed_domain = "ippure.cc";      // 【核心设置】换成你的实际域名（不带 http:// 或 www.）
$allow_empty_referer = true;        // 【核心设置】设为 true 允许命令行 curl 或直接在浏览器输入地址打开

$referer = $_SERVER['HTTP_REFERER'] ?? '';
$referer_host = parse_url($referer, PHP_URL_HOST) ?? '';

// 如果是 www. 域名，统一去除 www. 前缀方便匹配
if (substr($referer_host, 0, 4) === 'www.') {
    $referer_host = substr($referer_host, 4);
}

// 判定拦截逻辑
if (empty($referer)) {
    // 来源为空且不允许为空时拦截
    if (!$allow_empty_referer) {
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["status" => "error", "message" => "仅允许官方域名调用该接口"]);
        exit;
    }
} else {
    // 来源不为空，但域名不匹配时拦截
    if ($referer_host !== $allowed_domain) {
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(["status" => "error", "message" => "仅允许官方域名调用该接口"]);
        exit;
    }
}

// =========================================================
// 3. 完美获取真实客户端 IP：穿透 CDN（如 Cloudflare 等）和多重反向代理
// =========================================================
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $client_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    // 处理多重代理的情况，取第一个真实的客户端 IP
    $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $client_ip = trim($ips[0]);
} elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
    $client_ip = $_SERVER['HTTP_X_REAL_IP'];
} else {
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// =========================================================
// 4. 简易抗 CC 攻击限流系统（防止别人用循环脚本狂刷你的接口）
// =========================================================
$limit_dir = sys_get_temp_dir() . '/api_purity_limits/';
if (!is_dir($limit_dir)) {
    @mkdir($limit_dir, 0755, true);
}
$limit_file = $limit_dir . md5($client_ip) . '.json';
$now = time();
$limit_window = 60; // 限制窗口：60秒
$max_requests = 20; // 每个用户 IP 每分钟最多请求 20 次

if (file_exists($limit_file)) {
    $data = json_decode(@file_get_contents($limit_file), true) ?? [];
    if (isset($data['start_time']) && ($now - $data['start_time'] < $limit_window)) {
        if ($data['count'] >= $max_requests) {
            header('HTTP/1.1 429 Too Many Requests');
            if (strpos(strtolower($_SERVER['HTTP_USER_AGENT'] ?? ''), 'curl') !== false) {
                echo "错误：请求过于频繁，请一分钟后再试。\n";
            } else {
                echo "callback('0.0.0.0', '请求过于频繁，请一分钟后再试', 'N/A', 'N/A');";
            }
            exit;
        }
        $data['count']++;
    } else {
        $data = ['start_time' => $now, 'count' => 1];
    }
} else {
    $data = ['start_time' => $now, 'count' => 1];
}
@file_put_contents($limit_file, json_encode($data));

// =========================================================
// 5. 识别客户端：是网页前端，还是命令行终端 (curl / wget)
// =========================================================
$user_agent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$is_curl = false;

if (strpos($user_agent, 'curl') !== false || strpos($user_agent, 'wget') !== false || isset($_GET['cli'])) {
    $is_curl = true;
}

// =========================================================
// 6. 确定要查询的目标 IP
// =========================================================
$target_ip = $_GET['ip'] ?? '';
if ($target_ip !== '') {
    if (!filter_var($target_ip, FILTER_VALIDATE_IP)) {
        header('HTTP/1.1 400 Bad Request');
        if ($is_curl) {
            echo "错误：无效的 IP 格式。\n";
        } else {
            echo "callback('0.0.0.0', '无效的 IP 格式', 'N/A', 'N/A');";
        }
        exit;
    }
} else {
    $target_ip = $client_ip;
}

// =========================================================
// 7. 后台实时请求上游接口（主通道 + 备用通道双重防灾设计）
// =========================================================
$api_url = 'https://ping0.cc/geo/jsonp/callback';
if ($target_ip !== '0.0.0.0' && $target_ip !== '127.0.0.1') {
    $api_url .= '/' . $target_ip;
}

// --- 【通道一】尝试请求主数据源 ping0.cc ---
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 4); // 4秒超时保护
curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_error = curl_error($ch);
curl_close($ch);

// --- 【通道二】如果通道一失败，启动备用通道方案（请求 ip-api.com 并转换为兼容格式） ---
if ($http_code !== 200 || !$response) {
    $backup_url = 'http://ip-api.com/json/' . ($target_ip !== '0.0.0.0' ? $target_ip : '') . '?lang=zh-CN';
    
    $ch_backup = curl_init();
    curl_setopt($ch_backup, CURLOPT_URL, $backup_url);
    curl_setopt($ch_backup, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch_backup, CURLOPT_TIMEOUT, 4); // 4秒超时保护
    $backup_res = curl_exec($ch_backup);
    $backup_code = curl_getinfo($ch_backup, CURLINFO_HTTP_CODE);
    curl_close($ch_backup);

    if ($backup_code === 200 && $backup_res) {
        $ip_data = json_decode($backup_res, true);
        if ($ip_data && isset($ip_data['query'])) {
            // 完美包装成原 JSONP 格式，使后续正则解析逻辑无需变动
            $back_ip = $ip_data['query'];
            $back_loc = ($ip_data['country'] ?? '') . ' ' . ($ip_data['regionName'] ?? '') . ' ' . ($ip_data['city'] ?? '');
            $back_asn = $ip_data['as'] ?? '未知';
            $back_org = $ip_data['isp'] ?? '未知';
            $response = "callback('{$back_ip}', '{$back_loc}', '{$back_asn}', '{$back_org}')";
            $http_code = 200; // 虚拟成功状态码
        }
    }
}

// --- 异常兜底：双通道全挂时报错，并打印 cURL 报错详情 ---
if ($http_code !== 200 || !$response) {
    if ($is_curl) {
        echo "\033[1;31m错误：诊断通道异常！\033[0m\n";
        echo "调试信息：\n";
        echo "- 主通道 HTTP 状态码: " . $http_code . "\n";
        echo "- Curl 错误原因: " . ($curl_error ?: '无') . "\n";
        echo "- 建议：请在当前服务器终端执行 `ping ping0.cc` 测试其网络连通性。\n";
    } else {
        echo "callback('0.0.0.0', '上游诊断通道异常，请联系管理员检查服务器网络。', 'N/A', 'N/A');";
    }
    exit;
}

// =========================================================
// 8. 根据客户端类型，输出对应的格式
// =========================================================
if (!$is_curl) {
    // 网页前端调用：直接输出 jsonp 回调格式的数据
    header('Content-Type: application/javascript; charset=utf-8');
    echo $response;
    exit;
} else {
    // 命令行终端调用
    header('Content-Type: text/plain; charset=utf-8');

    preg_match("/callback\s*\(\s*['\"](.*?)['\"]\s*,\s*['\"](.*?)['\"]\s*,\s*['\"](.*?)['\"]\s*,\s*['\"](.*?)['\"]\s*\)/is", $response, $matches);

    $ip = !empty($matches[1]) ? trim($matches[1]) : '未知';
    $location = !empty($matches[2]) ? trim($matches[2]) : '未知';
    $asn = !empty($matches[3]) ? trim($matches[3]) : '未知';
    $org = !empty($matches[4]) ? trim($matches[4]) : '未知';

    // 判定网络类型
    $org_lower = strtolower($org);
    $asn_lower = strtolower($asn);

    $datacenterKeywords = ['hosting', 'cloud', 'server', 'datacenter', 'ovh', 'digitalocean', 'linode', 'vultr', 'aws', 'amazon', 'alibaba', 'tencent', 'cloudflare', 'proxy', 'vpn', 'dedicated', 'm247', 'leaseweb', 'choopa', 'zenlayer', 'colocation', 'he.net', 'hurricane electric', 'cogent', 'gtt', 'fastly', 'akamai', 'limelight', 'scaleway', 'contabo', 'hetzner', 'hinet-idc', 'ovhcloud'];
    $residentialKeywords = ['telecom', 'unicom', 'mobile', 'broadband', 'chinanet', 'fios', 'comcast', 'charter', 'at&t', 'verizon', 'residential', 'hinet', 'so-net', 'kddi', 'softbank', 'moe', 'education', 'university', 'campus', 'starlink', 'rogers', 'bell', 'orange', 'vodafone', 'bt-net'];

    if (array_filter($datacenterKeywords, fn($kw) => strpos($org_lower, $kw) !== false || strpos($asn_lower, $kw) !== false)) {
        $net_type = "IDC 机房 (数据中心/云服务器/代理)";
        $color_code = "\033[1;31m"; 
    } elseif (array_filter($residentialKeywords, fn($kw) => strpos($org_lower, $kw) !== false || strpos($asn_lower, $kw) !== false)) {
        $net_type = "家庭宽带 (住宅纯净 IP)";
        $color_code = "\033[1;32m"; 
    } else {
        $net_type = "企业专线 / 混合网络";
        $color_code = "\033[1;36m"; 
    }

    $reset_code = "\033[0m"; 
    $bold_code = "\033[1m";

    echo "\n";
    echo " {$bold_code}==============================================={$reset_code}\n";
    echo "       🌐 IP 属性与网络类型检测 (ippure.cc)      \n";
    echo " {$bold_code}==============================================={$reset_code}\n";
    echo "  目标 IP:     {$bold_code}{$ip}{$reset_code}\n";
    echo "  地理位置:    {$location}\n";
    echo "  自治系统:    {$asn}\n";
    echo "  运营商/归属: {$org}\n";
    echo " -----------------------------------------------\n";
    echo "  网络类型:    {$color_code}{$net_type}{$reset_code}\n";
    echo " {$bold_code}==============================================={$reset_code}\n";
    echo "\n";
}
?>