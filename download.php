<?php
// ==========================================================
// CLONEX ESPORTS - APK DOWNLOAD HANDLER (LiteSpeed / Apache)
// ==========================================================

$dataDir = __DIR__ . '/data';
$settingsFile = $dataDir . '/settings.json';

$apkUrl = '';
$apkFilePath = '/assets/Clonex-Esports-v1.0.apk';
$apkFilename = 'Clonex-Esports-v1.0.apk';
$apkSourceType = 'file';

if (file_exists($settingsFile)) {
    $data = @file_get_contents($settingsFile);
    if ($data) {
        $s = @json_decode($data, true);
        if (is_array($s)) {
            $apkSourceType = $s['apkSourceType'] ?? 'file';
            $apkUrl = $s['apkUrl'] ?? '';
            $apkFilePath = $s['apkFilePath'] ?? $apkFilePath;
            $apkFilename = $s['apkFilename'] ?? $apkFilename;
        }
    }
}

if ($apkSourceType === 'url' && !empty($apkUrl)) {
    header("Location: " . $apkUrl, true, 302);
    exit;
}

$localPath = __DIR__ . $apkFilePath;
if (!file_exists($localPath)) {
    $altUploadPath = __DIR__ . '/uploads/' . basename($apkFilename);
    if (file_exists($altUploadPath)) {
        $localPath = $altUploadPath;
    } else {
        $localPath = __DIR__ . '/assets/Clonex-Esports-v1.0.apk';
    }
}

if (file_exists($localPath)) {
    $downloadName = !empty($apkFilename) ? basename($apkFilename) : basename($localPath);
    if (!preg_match('/\.apk$/i', $downloadName)) {
        $downloadName .= '.apk';
    }
    header('Content-Description: File Transfer');
    header('Content-Type: application/vnd.android.package-archive');
    header('Content-Disposition: attachment; filename="' . $downloadName . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($localPath));
    readfile($localPath);
    exit;
} else {
    http_response_code(404);
    echo "APK file not found on server.";
}
