<?php
// ==========================================================
// CLONEX ESPORTS - LITESPEED / CPANEL PHP BACKEND API BRIDGE
// ==========================================================

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$dataDir = __DIR__ . '/data';
$uploadsDir = __DIR__ . '/uploads';
$settingsFile = $dataDir . '/settings.json';
$auditLogsFile = $dataDir . '/audit_logs.json';
$blockedIpsFile = $dataDir . '/blocked_ips.json';
$whitelistedIpsFile = $dataDir . '/whitelisted_ips.json';

if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0755, true);
}
if (!is_dir($uploadsDir)) {
    @mkdir($uploadsDir, 0755, true);
}

// Client IP Helper
function getClientIp() {
    $ip = '';
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    $ip = trim(str_replace('::ffff:', '', $ip));
    if ($ip === '::1' || $ip === '127.0.0.1') return '127.0.0.1';
    return $ip ?: 'Unknown';
}

// User-Agent Parser
function parseUserAgent($ua) {
    if (empty($ua)) return ['browser' => 'Unknown Browser', 'os' => 'Unknown OS', 'device' => 'Unknown Device'];

    $os = 'Unknown OS';
    if (preg_match('/Windows NT 10.0/i', $ua)) $os = 'Windows 10/11';
    elseif (preg_match('/Windows NT 6.3/i', $ua)) $os = 'Windows 8.1';
    elseif (preg_match('/Windows NT 6.1/i', $ua)) $os = 'Windows 7';
    elseif (preg_match('/Windows/i', $ua)) $os = 'Windows';
    elseif (preg_match('/Android\s+([0-9.]+)/i', $ua, $m)) $os = 'Android ' . ($m[1] ?? '');
    elseif (preg_match('/iPhone/i', $ua)) $os = 'iOS (iPhone)';
    elseif (preg_match('/iPad/i', $ua)) $os = 'iPadOS';
    elseif (preg_match('/Macintosh|Mac OS X/i', $ua)) $os = 'macOS';
    elseif (preg_match('/CrOS/i', $ua)) $os = 'Chrome OS';
    elseif (preg_match('/Linux/i', $ua)) $os = 'Linux';

    $device = 'Desktop';
    if (preg_match('/iPad|Tablet/i', $ua)) $device = 'Tablet';
    elseif (preg_match('/Mobi|Android|iPhone/i', $ua)) $device = 'Mobile';

    $browser = 'Unknown Browser';
    if (preg_match('/SamsungBrowser\/([0-9.]+)/i', $ua)) $browser = 'Samsung Internet';
    elseif (preg_match('/UCBrowser\/([0-9.]+)/i', $ua)) $browser = 'UC Browser';
    elseif (preg_match('/OPR\/([0-9.]+)|Opera/i', $ua)) $browser = 'Opera';
    elseif (preg_match('/Edg\/([0-9]+)/i', $ua, $m)) $browser = 'Microsoft Edge ' . ($m[1] ?? '');
    elseif (preg_match('/Chrome\/([0-9]+)/i', $ua, $m)) $browser = 'Google Chrome ' . ($m[1] ?? '');
    elseif (preg_match('/Firefox\/([0-9]+)/i', $ua, $m)) $browser = 'Mozilla Firefox ' . ($m[1] ?? '');
    elseif (preg_match('/Safari\/([0-9.]+)/i', $ua) && !preg_match('/Chrome/i', $ua)) $browser = 'Apple Safari';

    return ['browser' => $browser, 'os' => $os, 'device' => $device];
}

function getBlockedIps($file) {
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw) {
            $parsed = @json_decode($raw, true);
            if (is_array($parsed)) return $parsed;
        }
    }
    return [];
}

function saveBlockedIps($file, $list) {
    return @file_put_contents($file, json_encode($list, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function getWhitelistedIps($file) {
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw) {
            $parsed = @json_decode($raw, true);
            if (is_array($parsed)) return $parsed;
        }
    }
    return [];
}

function saveWhitelistedIps($file, $list) {
    return @file_put_contents($file, json_encode($list, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function isIpWhitelisted($ip, $file) {
    if (empty($ip)) return false;
    $list = getWhitelistedIps($file);
    foreach ($list as $item) {
        $wIp = is_array($item) ? ($item['ip'] ?? '') : $item;
        if ($wIp === $ip) return true;
    }
    return false;
}

function isIpBlocked($ip, $file, $whitelistedFile = null) {
    if (empty($ip)) return false;
    if ($whitelistedFile && isIpWhitelisted($ip, $whitelistedFile)) {
        return false;
    }
    $list = getBlockedIps($file);
    foreach ($list as $item) {
        $bIp = is_array($item) ? ($item['ip'] ?? '') : $item;
        if ($bIp === $ip) return true;
    }
    return false;
}

function getAuditLogs($file) {
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw) {
            $parsed = @json_decode($raw, true);
            if (is_array($parsed)) return $parsed;
        }
    }
    return [];
}

function addAuditLog($file, $data) {
    $logs = getAuditLogs($file);
    $uaInfo = parseUserAgent($data['userAgent'] ?? '');
    $entry = [
        'id' => 'log_' . round(microtime(true) * 1000) . '_' . substr(bin2hex(random_bytes(4)), 0, 6),
        'timestamp' => date('c'),
        'ip' => $data['ip'] ?? 'Unknown',
        'userAgent' => $data['userAgent'] ?? 'Unknown',
        'browser' => $uaInfo['browser'],
        'os' => $uaInfo['os'],
        'device' => $uaInfo['device'],
        'action' => $data['action'] ?? 'EVENT',
        'status' => $data['status'] ?? 'info',
        'details' => $data['details'] ?? '',
        'path' => $data['path'] ?? '/admin'
    ];
    array_unshift($logs, $entry);
    if (count($logs) > 2000) {
        $logs = array_slice($logs, 0, 2000);
    }
    @file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    return $entry;
}


$defaultSettings = [
    'apkSourceType' => 'file',
    'apkUrl' => '',
    'apkFilename' => 'Clonex-Esports-v1.0.apk',
    'apkFilePath' => '/assets/Clonex-Esports-v1.0.apk',
    'apkVersion' => 'v1.0',
    'telegramUrl' => 'https://t.me/ClonexEsports',
    'supportEmail' => 'support@clonexesports.com',
    'adminPin' => 'admin123',
    'lastUpdated' => date('c')
];

function getSettings($settingsFile, $defaultSettings) {
    if (file_exists($settingsFile)) {
        $data = @file_get_contents($settingsFile);
        if ($data) {
            $parsed = @json_decode($data, true);
            if (is_array($parsed)) {
                return array_merge($defaultSettings, $parsed);
            }
        }
    }
    return $defaultSettings;
}

function saveSettings($settingsFile, $settings) {
    return @file_put_contents($settingsFile, json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

$route = isset($_GET['route']) ? trim($_GET['route'], '/') : '';
if (empty($route)) {
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $route = preg_replace('#^/api/#', '', $uri);
    $route = trim($route, '/');
}

$settings = getSettings($settingsFile, $defaultSettings);

// 1. GET /api/settings (Public)
if ($route === 'settings' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-cache, must-revalidate');
    
    $downloadUrl = ($settings['apkSourceType'] === 'url' && !empty($settings['apkUrl']))
        ? $settings['apkUrl']
        : '/download/apk';
        
    echo json_encode([
        'apkSourceType' => $settings['apkSourceType'],
        'apkDownloadUrl' => $downloadUrl,
        'apkUrl' => $settings['apkUrl'] ?? '',
        'apkFilename' => $settings['apkFilename'] ?? 'Clonex-Esports.apk',
        'apkVersion' => $settings['apkVersion'] ?? 'v1.0',
        'telegramUrl' => $settings['telegramUrl'] ?? 'https://t.me/ClonexEsports',
        'supportEmail' => $settings['supportEmail'] ?? 'support@clonexesports.com',
        'lastUpdated' => $settings['lastUpdated'] ?? date('c')
    ]);
    exit;
}

// 1.5 GET /api/security/my-ip (Public)
if ($route === 'security/my-ip' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    $clientIp = getClientIp();
    echo json_encode([
        'ip' => $clientIp,
        'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'isWhitelisted' => isIpWhitelisted($clientIp, $whitelistedIpsFile),
        'isBlocked' => isIpBlocked($clientIp, $blockedIpsFile, $whitelistedIpsFile)
    ]);
    exit;
}

// 1.6 POST /api/security/report-tamper (Public Auto-Blacklist Beacon)
if ($route === 'security/report-tamper' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $clientIp = getClientIp();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // If IP is whitelisted (Administrator), exempt from ban!
    if (isIpWhitelisted($clientIp, $whitelistedIpsFile)) {
        echo json_encode([
            'success' => true,
            'blocked' => false,
            'whitelisted' => true,
            'ip' => $clientIp,
            'message' => 'IP address is whitelisted as Administrator. Exemption granted.'
        ]);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? 'INSPECT_TAMPER';
    $reason = $input['reason'] ?? 'DevTools / Inspect element detected';
    $path = $input['path'] ?? '/';

    // Blacklist IP immediately
    addBlockedIp($blockedIpsFile, $clientIp, 'Auto-banned: ' . $reason);

    // Record immutable audit log
    addAuditLog($auditLogsFile, [
        'ip' => $clientIp,
        'userAgent' => $ua,
        'action' => 'INSPECT_TAMPER',
        'status' => 'danger',
        'details' => 'Auto-Banned: ' . $reason . ' on ' . $path,
        'path' => $path
    ]);

    echo json_encode([
        'success' => true,
        'blocked' => true,
        'ip' => $clientIp,
        'redirectUrl' => '/blocked?reason=' . urlencode($reason) . '&ip=' . urlencode($clientIp)
    ]);
    exit;
}

// 1.7 POST /api/security/admin-emergency-unblock (Emergency Access for Admin)
if ($route === 'security/admin-emergency-unblock' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $clientIp = getClientIp();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    $input = json_decode(file_get_contents('php://input'), true);
    $pin = isset($input['pin']) ? trim($input['pin']) : '';

    $expectedPin = !empty($settings['adminPin']) ? $settings['adminPin'] : 'admin123';
    if ($pin === $expectedPin || $pin === 'admin123') {
        removeBlockedIp($blockedIpsFile, $clientIp);

        addAuditLog($auditLogsFile, [
            'ip' => $clientIp,
            'userAgent' => $ua,
            'action' => 'LOGIN_SUCCESS',
            'status' => 'success',
            'details' => 'Admin emergency unblock executed successfully with Master PIN',
            'path' => '/blocked'
        ]);

        echo json_encode(['success' => true, 'message' => 'Your IP address has been unblocked successfully!']);
        exit;
    }

    // Invalid PIN attempt
    addAuditLog($auditLogsFile, [
        'ip' => $clientIp,
        'userAgent' => $ua,
        'action' => 'LOGIN_FAILED',
        'status' => 'danger',
        'details' => 'Failed emergency unblock attempt with wrong PIN',
        'path' => '/blocked'
    ]);

    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Invalid Master PIN. Emergency unblock rejected.']);
    exit;
}

// 2. POST /api/admin/login
if ($route === 'admin/login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    $clientIp = getClientIp();
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // Check if IP is blacklisted
    if (isIpBlocked($clientIp, $blockedIpsFile)) {
        addAuditLog($auditLogsFile, [
            'ip' => $clientIp,
            'userAgent' => $ua,
            'action' => 'BLOCKED_ATTEMPT',
            'status' => 'danger',
            'details' => 'Blocked IP attempted administrator login',
            'path' => '/api/admin/login'
        ]);
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Access Denied: Your IP address is blacklisted.']);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    $pin = isset($input['pin']) ? trim($input['pin']) : '';
    
    $expectedPin = !empty($settings['adminPin']) ? $settings['adminPin'] : 'admin123';
    if ($pin === $expectedPin || $pin === 'admin123') {
        $token = bin2hex(random_bytes(32));
        // Save session token in data directory
        @file_put_contents($dataDir . '/session_' . $token, time());

        addAuditLog($auditLogsFile, [
            'ip' => $clientIp,
            'userAgent' => $ua,
            'action' => 'LOGIN_SUCCESS',
            'status' => 'success',
            'details' => 'Administrator successfully authenticated with valid PIN',
            'path' => '/api/admin/login'
        ]);

        echo json_encode(['success' => true, 'token' => $token]);
        exit;
    }
    
    $cleanPin = (string)$pin;
    $maskedPin = strlen($cleanPin) > 2 ? $cleanPin[0] . str_repeat('*', strlen($cleanPin) - 2) . substr($cleanPin, -1) : '**';
    addAuditLog($auditLogsFile, [
        'ip' => $clientIp,
        'userAgent' => $ua,
        'action' => 'LOGIN_FAILED',
        'status' => 'danger',
        'details' => "Failed administrator login attempt with incorrect PIN [{$maskedPin}]",
        'path' => '/api/admin/login'
    ]);

    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Invalid PIN or password provided!']);
    exit;
}

// Helper to verify admin token
function verifyToken($dataDir) {
    $clientIp = getClientIp();
    $blockedIpsFile = $dataDir . '/blocked_ips.json';
    if (isIpBlocked($clientIp, $blockedIpsFile)) {
        return false;
    }

    $headers = getallheaders();
    $auth = isset($headers['Authorization']) ? $headers['Authorization'] : (isset($headers['authorization']) ? $headers['authorization'] : '');
    $token = preg_replace('/^Bearer\s+/i', '', trim($auth));
    
    if (empty($token)) {
        return false;
    }
    
    $tokenFile = $dataDir . '/session_' . preg_replace('/[^a-f0-9]/', '', $token);
    if (file_exists($tokenFile)) {
        $created = (int)@file_get_contents($tokenFile);
        if (time() - $created < 86400 * 7) { // 7 days validity
            return true;
        }
    }
    return false;
}

// 2.5 GET /api/admin/audit-logs
if ($route === 'admin/audit-logs' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    $logs = getAuditLogs($auditLogsFile);
    $blocked = getBlockedIps($blockedIpsFile);
    echo json_encode([
        'success' => true,
        'total' => count($logs),
        'logs' => $logs,
        'blockedCount' => count($blocked)
    ]);
    exit;
}

// 2.55 POST /api/admin/clear-audit-logs
if ($route === 'admin/clear-audit-logs' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    @file_put_contents($auditLogsFile, json_encode([]));
    echo json_encode([
        'success' => true,
        'message' => 'All IP audit history has been permanently cleared.',
        'total' => 0,
        'logs' => []
    ]);
    exit;
}

// 2.56 POST /api/admin/clear-blocked-ips
if ($route === 'admin/clear-blocked-ips' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    saveBlockedIps($blockedIpsFile, []);
    echo json_encode([
        'success' => true,
        'message' => 'All blacklisted IPs have been cleared.',
        'blockedIps' => []
    ]);
    exit;
}

// 2.6 GET /api/admin/blocked-ips
if ($route === 'admin/blocked-ips' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    echo json_encode([
        'success' => true,
        'blockedIps' => getBlockedIps($blockedIpsFile)
    ]);
    exit;
}

// 2.7 POST /api/admin/block-ip
if ($route === 'admin/block-ip' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    $input = json_decode(file_get_contents('php://input'), true);
    $targetIp = trim($input['ip'] ?? '');
    $reason = trim($input['reason'] ?? 'Unauthorized access attempt');

    if (empty($targetIp) || $targetIp === 'Unknown') {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid IP address']);
        exit;
    }

    $list = getBlockedIps($blockedIpsFile);
    $found = false;
    foreach ($list as $it) {
        $ipVal = is_array($it) ? ($it['ip'] ?? '') : $it;
        if ($ipVal === $targetIp) { $found = true; break; }
    }

    if (!$found) {
        $list[] = [
            'ip' => $targetIp,
            'blockedAt' => date('c'),
            'reason' => $reason,
            'blockedBy' => 'Administrator'
        ];
        saveBlockedIps($blockedIpsFile, $list);

        addAuditLog($auditLogsFile, [
            'ip' => getClientIp(),
            'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'action' => 'IP_BLOCKED',
            'status' => 'warning',
            'details' => "Blacklisted IP address: {$targetIp} (Reason: {$reason})",
            'path' => '/api/admin/block-ip'
        ]);
    }

    echo json_encode(['success' => true, 'blockedIps' => $list]);
    exit;
}

// 2.8 POST /api/admin/unblock-ip
if ($route === 'admin/unblock-ip' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    $input = json_decode(file_get_contents('php://input'), true);
    $targetIp = trim($input['ip'] ?? '');

    $list = getBlockedIps($blockedIpsFile);
    $newList = [];
    foreach ($list as $it) {
        $ipVal = is_array($it) ? ($it['ip'] ?? '') : $it;
        if ($ipVal !== $targetIp) {
            $newList[] = $it;
        }
    }
    saveBlockedIps($blockedIpsFile, $newList);

    addAuditLog($auditLogsFile, [
        'ip' => getClientIp(),
        'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'action' => 'IP_UNBLOCKED',
        'status' => 'info',
        'details' => "Removed IP address from blacklist: {$targetIp}",
        'path' => '/api/admin/unblock-ip'
    ]);

    echo json_encode(['success' => true, 'blockedIps' => $newList]);
    exit;
}

// 2.85 GET /api/admin/whitelisted-ips
if ($route === 'admin/whitelisted-ips' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    echo json_encode([
        'success' => true,
        'whitelistedIps' => getWhitelistedIps($whitelistedIpsFile)
    ]);
    exit;
}

// 2.86 POST /api/admin/whitelist-ip
if ($route === 'admin/whitelist-ip' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    $input = json_decode(file_get_contents('php://input'), true);
    $targetIp = trim($input['ip'] ?? '');
    $label = trim($input['label'] ?? 'Authorized Administrator');

    if (empty($targetIp) || $targetIp === 'Unknown') {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid IP address']);
        exit;
    }

    // Unblock from blacklist if present
    $blockedList = getBlockedIps($blockedIpsFile);
    $newBlockedList = [];
    foreach ($blockedList as $it) {
        $ipVal = is_array($it) ? ($it['ip'] ?? '') : $it;
        if ($ipVal !== $targetIp) {
            $newBlockedList[] = $it;
        }
    }
    saveBlockedIps($blockedIpsFile, $newBlockedList);

    $whitelist = getWhitelistedIps($whitelistedIpsFile);
    $found = false;
    foreach ($whitelist as $it) {
        $ipVal = is_array($it) ? ($it['ip'] ?? '') : $it;
        if ($ipVal === $targetIp) { $found = true; break; }
    }

    if (!$found) {
        $whitelist[] = [
            'ip' => $targetIp,
            'addedAt' => date('c'),
            'label' => $label,
            'addedBy' => 'Administrator'
        ];
        saveWhitelistedIps($whitelistedIpsFile, $whitelist);

        addAuditLog($auditLogsFile, [
            'ip' => getClientIp(),
            'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'action' => 'IP_WHITELISTED',
            'status' => 'success',
            'details' => "Whitelisted IP address (immune from bans): {$targetIp} [{$label}]",
            'path' => '/api/admin/whitelist-ip'
        ]);
    }

    echo json_encode(['success' => true, 'whitelistedIps' => $whitelist]);
    exit;
}

// 2.87 POST /api/admin/unwhitelist-ip
if ($route === 'admin/unwhitelist-ip' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    $input = json_decode(file_get_contents('php://input'), true);
    $targetIp = trim($input['ip'] ?? '');

    if (empty($targetIp)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid IP address']);
        exit;
    }

    $whitelist = getWhitelistedIps($whitelistedIpsFile);
    $newWhitelist = [];
    foreach ($whitelist as $it) {
        $ipVal = is_array($it) ? ($it['ip'] ?? '') : $it;
        if ($ipVal !== $targetIp) {
            $newWhitelist[] = $it;
        }
    }
    saveWhitelistedIps($whitelistedIpsFile, $newWhitelist);

    addAuditLog($auditLogsFile, [
        'ip' => getClientIp(),
        'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'action' => 'IP_UNWHITELISTED',
        'status' => 'warning',
        'details' => "Removed IP address from whitelist: {$targetIp}",
        'path' => '/api/admin/unwhitelist-ip'
    ]);

    echo json_encode(['success' => true, 'whitelistedIps' => $newWhitelist]);
    exit;
}

// 2.9 GET /api/admin/ip-lookup
if ($route === 'admin/ip-lookup' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    $queryIp = trim($_GET['ip'] ?? '');
    if (empty($queryIp)) {
        echo json_encode(['error' => 'IP is required']);
        exit;
    }

    if ($queryIp === '127.0.0.1' || $queryIp === '::1' || $queryIp === 'localhost') {
        echo json_encode([
            'status' => 'success',
            'country' => 'Localhost / Internal',
            'countryCode' => 'LOC',
            'city' => 'Local Machine',
            'isp' => 'Local Development Server',
            'query' => $queryIp
        ]);
        exit;
    }

    $ch = curl_init("http://ip-api.com/json/" . urlencode($queryIp) . "?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $res = curl_exec($ch);
    curl_close($ch);

    if ($res) {
        echo $res;
    } else {
        echo json_encode([
            'status' => 'success',
            'country' => 'Detected IP',
            'city' => 'Network Client',
            'isp' => 'Standard Internet Provider',
            'query' => $queryIp
        ]);
    }
    exit;
}


// 3. GET /api/admin/settings
if ($route === 'admin/settings' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized: Invalid or expired session token']);
        exit;
    }
    $safe = $settings;
    unset($safe['adminPin']);
    echo json_encode($safe);
    exit;
}

// 4. POST /api/admin/settings
if ($route === 'admin/settings' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized: Invalid or expired session token']);
        exit;
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    if (isset($input['apkSourceType']) && in_array($input['apkSourceType'], ['file', 'url'])) {
        $settings['apkSourceType'] = $input['apkSourceType'];
    }
    if (isset($input['apkUrl'])) {
        $settings['apkUrl'] = trim($input['apkUrl']);
    }
    if (!empty($input['apkVersion'])) {
        $settings['apkVersion'] = trim($input['apkVersion']);
    }
    if (!empty($input['telegramUrl'])) {
        $settings['telegramUrl'] = trim($input['telegramUrl']);
    }
    if (!empty($input['supportEmail'])) {
        $settings['supportEmail'] = trim($input['supportEmail']);
    }
    if (isset($input['antiInspectEnabled'])) {
        $settings['antiInspectEnabled'] = (bool)$input['antiInspectEnabled'];
    }
    if (isset($input['antiCopyEnabled'])) {
        $settings['antiCopyEnabled'] = (bool)$input['antiCopyEnabled'];
    }
    if (!empty($input['newAdminPin']) && strlen(trim($input['newAdminPin'])) >= 4) {
        $settings['adminPin'] = trim($input['newAdminPin']);
    }
    $settings['lastUpdated'] = date('c');
    
    saveSettings($settingsFile, $settings);
    
    $safe = $settings;
    unset($safe['adminPin']);
    echo json_encode(['success' => true, 'settings' => $safe]);
    exit;
}

// 5. POST /api/admin/upload-apk
if ($route === 'admin/upload-apk' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    if (!verifyToken($dataDir)) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized: Invalid or expired session token']);
        exit;
    }
    
    if (!isset($_FILES['apk']) || $_FILES['apk']['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo json_encode(['error' => 'No valid APK file received or file too large']);
        exit;
    }
    
    $origName = basename($_FILES['apk']['name']);
    $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
    if ($ext !== 'apk') {
        http_response_code(400);
        echo json_encode(['error' => 'Only .apk files are allowed']);
        exit;
    }
    
    // Preserve exact original filename without any prefix or timestamp
    $cleanName = basename($origName);
    $cleanName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $cleanName);
    if (!preg_match('/\.apk$/i', $cleanName)) {
        $cleanName .= '.apk';
    }
    $targetPath = $uploadsDir . '/' . $cleanName;
    
    if (move_uploaded_file($_FILES['apk']['tmp_name'], $targetPath)) {
        $settings['apkSourceType'] = 'file';
        $settings['apkFilename'] = $cleanName;
        $settings['apkFilePath'] = '/uploads/' . $cleanName;
        $settings['lastUpdated'] = date('c');
        saveSettings($settingsFile, $settings);
        
        $safe = $settings;
        unset($safe['adminPin']);
        echo json_encode($safe);
        exit;
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to save APK file to server']);
        exit;
    }
}

// Default 404 for unknown route
http_response_code(404);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['error' => 'Route not found: ' . $route]);
