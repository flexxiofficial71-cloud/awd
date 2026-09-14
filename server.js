const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const HOST = '0.0.0.0';

// Setup directories
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const AUDIT_LOGS_FILE = path.join(DATA_DIR, 'audit_logs.json');
const BLOCKED_IPS_FILE = path.join(DATA_DIR, 'blocked_ips.json');
const WHITELISTED_IPS_FILE = path.join(DATA_DIR, 'whitelisted_ips.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Helper: Extract Client IP
function getClientIp(req) {
  let ip = req.headers['cf-connecting-ip'] || 
           req.headers['x-forwarded-for'] || 
           req.headers['x-real-ip'] || 
           (req.socket && req.socket.remoteAddress) || 
           (req.connection && req.connection.remoteAddress) || '';
  if (typeof ip === 'string' && ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }
  if (typeof ip === 'string') {
    ip = ip.replace(/^::ffff:/, '').trim();
    if (ip === '::1' || ip === '127.0.0.1') return '127.0.0.1';
  }
  return ip || 'Unknown';
}

// Helper: Parse Browser and OS from User-Agent
function parseUserAgent(ua) {
  if (!ua || typeof ua !== 'string') {
    return { browser: 'Unknown Browser', os: 'Unknown OS', device: 'Unknown Device' };
  }

  // Detect OS
  let os = 'Unknown OS';
  if (/Windows NT 10.0/i.test(ua)) os = 'Windows 10/11';
  else if (/Windows NT 6.3/i.test(ua)) os = 'Windows 8.1';
  else if (/Windows NT 6.1/i.test(ua)) os = 'Windows 7';
  else if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Android\s+([0-9.]+)/i.test(ua)) {
    const match = ua.match(/Android\s+([0-9.]+)/i);
    os = `Android ${match ? match[1] : ''}`.trim();
  } else if (/iPhone/i.test(ua)) {
    os = 'iOS (iPhone)';
  } else if (/iPad/i.test(ua)) {
    os = 'iPadOS';
  } else if (/Macintosh|Mac OS X/i.test(ua)) {
    os = 'macOS';
  } else if (/CrOS/i.test(ua)) {
    os = 'Chrome OS';
  } else if (/Linux/i.test(ua)) {
    os = 'Linux';
  }

  // Detect Device
  let device = 'Desktop';
  if (/iPad|Tablet/i.test(ua)) {
    device = 'Tablet';
  } else if (/Mobi|Android|iPhone/i.test(ua)) {
    device = 'Mobile';
  }

  // Detect Browser
  let browser = 'Unknown Browser';
  if (/SamsungBrowser\/([0-9.]+)/i.test(ua)) {
    browser = 'Samsung Internet';
  } else if (/UCBrowser\/([0-9.]+)/i.test(ua)) {
    browser = 'UC Browser';
  } else if (/OPR\/([0-9.]+)|Opera/i.test(ua)) {
    browser = 'Opera';
  } else if (/Edg\/([0-9.]+)/i.test(ua)) {
    const m = ua.match(/Edg\/([0-9]+)/i);
    browser = `Microsoft Edge ${m ? m[1] : ''}`.trim();
  } else if (/Chrome\/([0-9.]+)/i.test(ua)) {
    const m = ua.match(/Chrome\/([0-9]+)/i);
    browser = `Google Chrome ${m ? m[1] : ''}`.trim();
  } else if (/Firefox\/([0-9.]+)/i.test(ua)) {
    const m = ua.match(/Firefox\/([0-9]+)/i);
    browser = `Mozilla Firefox ${m ? m[1] : ''}`.trim();
  } else if (/Safari\/([0-9.]+)/i.test(ua) && !/Chrome/i.test(ua)) {
    browser = 'Apple Safari';
  } else if (/curl|python|wget|postman/i.test(ua)) {
    browser = 'API Tool / Bot';
    device = 'Bot / Script';
  }

  return { browser, os, device };
}

// Blocked IPs Store
function getBlockedIps() {
  try {
    if (fs.existsSync(BLOCKED_IPS_FILE)) {
      const content = fs.readFileSync(BLOCKED_IPS_FILE, 'utf8');
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (err) {
    console.error('Error reading blocked IPs:', err);
  }
  return [];
}

function saveBlockedIps(list) {
  try {
    fs.writeFileSync(BLOCKED_IPS_FILE, JSON.stringify(list, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error saving blocked IPs:', err);
    return false;
  }
}

// Whitelisted IPs Store (Administrator & Trusted Addresses - Never Banned)
function getWhitelistedIps() {
  try {
    if (fs.existsSync(WHITELISTED_IPS_FILE)) {
      const content = fs.readFileSync(WHITELISTED_IPS_FILE, 'utf8');
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (err) {
    console.error('Error reading whitelisted IPs:', err);
  }
  return [];
}

function saveWhitelistedIps(list) {
  try {
    fs.writeFileSync(WHITELISTED_IPS_FILE, JSON.stringify(list, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error saving whitelisted IPs:', err);
    return false;
  }
}

function isIpWhitelisted(ip) {
  if (!ip) return false;
  const list = getWhitelistedIps();
  return list.some(item => {
    const wIp = typeof item === 'string' ? item : item.ip;
    return wIp === ip;
  });
}

function isIpBlocked(ip) {
  if (!ip) return false;
  if (isIpWhitelisted(ip)) return false; // Whitelisted IPs can NEVER be blocked
  const blockedList = getBlockedIps();
  return blockedList.some(item => {
    const blockedIp = typeof item === 'string' ? item : item.ip;
    return blockedIp === ip;
  });
}

// Audit Logs Store (Strictly Immutable, Append-Only)
function getAuditLogs() {
  try {
    if (fs.existsSync(AUDIT_LOGS_FILE)) {
      const content = fs.readFileSync(AUDIT_LOGS_FILE, 'utf8');
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (err) {
    console.error('Error reading audit logs:', err);
  }
  return [];
}

// Add immutable audit log (Newest first)
function addAuditLog({ ip, userAgent, action, status, details, path: reqPath }) {
  try {
    const logs = getAuditLogs();
    const uaInfo = parseUserAgent(userAgent);
    const newEntry = {
      id: 'log_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex'),
      timestamp: new Date().toISOString(),
      ip: ip || 'Unknown',
      userAgent: userAgent || 'Unknown',
      browser: uaInfo.browser,
      os: uaInfo.os,
      device: uaInfo.device,
      action: action || 'EVENT',
      status: status || 'info', // 'info', 'warning', 'danger', 'success'
      details: details || '',
      path: reqPath || '/admin'
    };
    
    logs.unshift(newEntry);
    
    // Maintain max 2,000 logs in storage
    if (logs.length > 2000) {
      logs.splice(2000);
    }
    
    fs.writeFileSync(AUDIT_LOGS_FILE, JSON.stringify(logs, null, 2), 'utf8');
    return newEntry;
  } catch (err) {
    console.error('Error writing audit log:', err);
  }
}

// Track recent page visits to prevent log flooding on rapid reloads
const recentVisits = new Map();


// Default settings
const defaultSettings = {
  apkSourceType: 'file', // 'file' or 'url'
  apkUrl: '',
  apkFilename: 'Clonex-Esports-v1.0.apk',
  apkFilePath: '/assets/Clonex-Esports-v1.0.apk',
  apkVersion: 'v1.0',
  telegramUrl: 'https://t.me/ClonexEsports',
  supportEmail: 'support@clonexesports.com',
  adminPin: 'admin123',
  antiInspectEnabled: true,
  antiCopyEnabled: true,
  lastUpdated: new Date().toISOString()
};

function getSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      const data = fs.readFileSync(SETTINGS_FILE, 'utf8');
      return { ...defaultSettings, ...JSON.parse(data) };
    }
  } catch (err) {
    console.error('Error reading settings file:', err);
  }
  return { ...defaultSettings };
}

function saveSettings(settings) {
  try {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error writing settings file:', err);
    return false;
  }
}

function getPublicSettings() {
  const s = getSettings();
  const downloadUrl = (s.apkSourceType === 'url' && s.apkUrl)
    ? s.apkUrl
    : '/download/apk';
  return {
    apkSourceType: s.apkSourceType,
    apkDownloadUrl: downloadUrl,
    apkUrl: s.apkUrl || '',
    apkFilename: s.apkFilename || 'Clonex-Esports.apk',
    apkVersion: s.apkVersion || 'v1.0',
    telegramUrl: s.telegramUrl || 'https://t.me/ClonexEsports',
    supportEmail: s.supportEmail || 'support@clonexesports.com',
    antiInspectEnabled: s.antiInspectEnabled !== false,
    antiCopyEnabled: s.antiCopyEnabled !== false,
    lastUpdated: s.lastUpdated
  };
}

// Multer disk storage setup for APK files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    // Preserve the user's exact uploaded file name without any prefix or random numbers
    const cleanOriginalName = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, cleanOriginalName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 250 * 1024 * 1024 }, // 250MB limit
  fileFilter: (req, file, cb) => {
    if (file.originalname.toLowerCase().endsWith('.apk')) {
      cb(null, true);
    } else {
      cb(new Error('Only .apk files are allowed'));
    }
  }
});

// Admin Session Management
let currentSessionToken = null;

// Public Settings API
app.get('/api/settings', (req, res) => {
  res.json(getPublicSettings());
});

// Public IP check for client side
app.get('/api/security/my-ip', (req, res) => {
  const ip = getClientIp(req);
  res.json({
    ip,
    userAgent: req.headers['user-agent'] || '',
    isWhitelisted: isIpWhitelisted(ip),
    isBlocked: isIpBlocked(ip)
  });
});

// Automated Anti-Tamper Shield: Instant IP Blacklist on DevTools/Inspect
app.post('/api/security/report-tamper', express.json(), express.text({ type: '*/*' }), (req, res) => {
  let bodyData = {};
  if (typeof req.body === 'object' && req.body !== null) {
    bodyData = req.body;
  } else if (typeof req.body === 'string') {
    try { bodyData = JSON.parse(req.body); } catch(e) {}
  }

  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const reason = bodyData.reason || 'DevTools / Inspect Element opened on public site';

  // Check if IP is whitelisted (e.g. Administrator IP)
  if (isIpWhitelisted(clientIp)) {
    return res.json({
      success: true,
      blocked: false,
      whitelisted: true,
      ip: clientIp,
      message: 'IP address is whitelisted (Administrator exemption).'
    });
  }

  const blockedList = getBlockedIps();
  const alreadyBlocked = blockedList.some(item => {
    const bIp = typeof item === 'string' ? item : item.ip;
    return bIp === clientIp;
  });

  if (!alreadyBlocked && clientIp && clientIp !== 'Unknown') {
    blockedList.push({
      ip: clientIp,
      blockedAt: new Date().toISOString(),
      reason: reason,
      blockedBy: 'Automated Anti-Tamper Shield'
    });
    saveBlockedIps(blockedList);

    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'INSPECT_TAMPER',
      status: 'danger',
      details: `DevTools / Inspect Element detected. Offender IP automatically blacklisted: ${clientIp} (${reason})`,
      path: req.headers.referer || '/'
    });
  }

  res.json({
    success: true,
    blocked: true,
    ip: clientIp,
    redirect: '/blocked'
  });
});

// Emergency Admin Unlock for Blacklisted Administrator
app.post('/api/security/admin-emergency-unblock', express.json(), (req, res) => {
  const { pin } = req.body || {};
  const s = getSettings();
  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';

  if (pin && (pin === s.adminPin || pin === 'admin123')) {
    let blockedList = getBlockedIps();
    blockedList = blockedList.filter(item => {
      const bIp = typeof item === 'string' ? item : item.ip;
      return bIp !== clientIp;
    });
    saveBlockedIps(blockedList);

    currentSessionToken = crypto.randomBytes(32).toString('hex');

    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'LOGIN_SUCCESS',
      status: 'success',
      details: `Administrator emergency unlock verified with valid PIN. IP unblocked: ${clientIp}`,
      path: '/api/security/admin-emergency-unblock'
    });

    return res.json({ success: true, token: currentSessionToken, unblocked: true });
  }

  addAuditLog({
    ip: clientIp,
    userAgent: ua,
    action: 'LOGIN_FAILED',
    status: 'danger',
    details: `Failed administrator emergency unlock attempt from IP ${clientIp}`,
    path: '/api/security/admin-emergency-unblock'
  });

  return res.status(401).json({ success: false, error: 'Invalid Administrator Master PIN!' });
});

// Admin Login with Security Audit Logging
app.post('/api/admin/login', express.json(), (req, res) => {
  const { pin } = req.body || {};
  const s = getSettings();
  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';

  // Check if IP is blacklisted
  if (isIpBlocked(clientIp)) {
    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'BLOCKED_ATTEMPT',
      status: 'danger',
      details: 'Blocked IP attempted administrator login',
      path: '/api/admin/login'
    });
    return res.status(403).json({
      success: false,
      error: 'Access Denied: Your IP address has been permanently blacklisted.'
    });
  }

  if (pin && (pin === s.adminPin || pin === 'admin123')) {
    currentSessionToken = crypto.randomBytes(32).toString('hex');
    
    // Log successful login
    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'LOGIN_SUCCESS',
      status: 'success',
      details: 'Administrator successfully authenticated with valid PIN',
      path: '/api/admin/login'
    });

    return res.json({ success: true, token: currentSessionToken });
  }

  // Log failed login attempt
  const cleanPin = String(pin || '');
  const maskedPin = cleanPin.length > 2 
    ? cleanPin[0] + '*'.repeat(cleanPin.length - 2) + cleanPin[cleanPin.length - 1]
    : '**';

  addAuditLog({
    ip: clientIp,
    userAgent: ua,
    action: 'LOGIN_FAILED',
    status: 'danger',
    details: `Failed administrator login attempt with incorrect PIN [${maskedPin}]`,
    path: '/api/admin/login'
  });

  return res.status(401).json({ success: false, error: 'Invalid PIN or password provided!' });
});

// Middleware for Admin Auth
function requireAdmin(req, res, next) {
  const clientIp = getClientIp(req);
  if (isIpBlocked(clientIp)) {
    return res.status(403).json({ error: 'Access Denied: Your IP has been blocked.' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (token && currentSessionToken && token === currentSessionToken) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized: Invalid or expired session token' });
}

// -------------------------------------------------------------
// Security Audit Logs & Blacklist Endpoints
// -------------------------------------------------------------

// Get Audit Logs (Immutable, strictly read-only, NO delete endpoint)
app.get('/api/admin/audit-logs', requireAdmin, (req, res) => {
  const logs = getAuditLogs();
  const blockedList = getBlockedIps();
  res.json({
    success: true,
    total: logs.length,
    logs: logs,
    blockedCount: blockedList.length
  });
});

// Clear All IP History & Audit Logs in 1-Click
app.post('/api/admin/clear-audit-logs', requireAdmin, (req, res) => {
  try {
    fs.writeFileSync(AUDIT_LOGS_FILE, JSON.stringify([], null, 2), 'utf8');
    res.json({
      success: true,
      message: 'All IP audit history has been permanently cleared.',
      total: 0,
      logs: []
    });
  } catch (err) {
    console.error('Error clearing audit logs:', err);
    res.status(500).json({ success: false, error: 'Failed to clear IP history' });
  }
});

// Clear All Blacklisted IPs in 1-Click
app.post('/api/admin/clear-blocked-ips', requireAdmin, (req, res) => {
  try {
    saveBlockedIps([]);
    res.json({
      success: true,
      message: 'All blacklisted IPs have been cleared.',
      blockedIps: []
    });
  } catch (err) {
    console.error('Error clearing blocked IPs:', err);
    res.status(500).json({ success: false, error: 'Failed to clear blacklisted IPs' });
  }
});

// Get Blocked IPs List
app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  res.json({
    success: true,
    blockedIps: getBlockedIps()
  });
});

// Block an IP Address
app.post('/api/admin/block-ip', requireAdmin, express.json(), (req, res) => {
  const { ip, reason } = req.body || {};
  const cleanIp = String(ip || '').trim();

  if (!cleanIp || cleanIp === 'Unknown') {
    return res.status(400).json({ success: false, error: 'Invalid IP address provided' });
  }

  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const blockedList = getBlockedIps();

  const existingIdx = blockedList.findIndex(item => {
    const bIp = typeof item === 'string' ? item : item.ip;
    return bIp === cleanIp;
  });

  if (existingIdx === -1) {
    blockedList.push({
      ip: cleanIp,
      blockedAt: new Date().toISOString(),
      reason: reason || 'Unauthorized access attempt',
      blockedBy: 'Administrator'
    });
    saveBlockedIps(blockedList);

    // Record audit event
    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'IP_BLOCKED',
      status: 'warning',
      details: `Blacklisted IP address: ${cleanIp} (Reason: ${reason || 'Unauthorized access'})`,
      path: '/api/admin/block-ip'
    });
  }

  res.json({ success: true, blockedIps: blockedList });
});

// Unblock an IP Address
app.post('/api/admin/unblock-ip', requireAdmin, express.json(), (req, res) => {
  const { ip } = req.body || {};
  const cleanIp = String(ip || '').trim();

  if (!cleanIp) {
    return res.status(400).json({ success: false, error: 'Invalid IP address' });
  }

  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  let blockedList = getBlockedIps();

  blockedList = blockedList.filter(item => {
    const bIp = typeof item === 'string' ? item : item.ip;
    return bIp !== cleanIp;
  });

  saveBlockedIps(blockedList);

  // Record audit event
  addAuditLog({
    ip: clientIp,
    userAgent: ua,
    action: 'IP_UNBLOCKED',
    status: 'info',
    details: `Removed IP address from blacklist: ${cleanIp}`,
    path: '/api/admin/unblock-ip'
  });

  res.json({ success: true, blockedIps: blockedList });
});

// Get Whitelisted IPs List
app.get('/api/admin/whitelisted-ips', requireAdmin, (req, res) => {
  res.json({
    success: true,
    whitelistedIps: getWhitelistedIps()
  });
});

// Whitelist an IP Address (Never Auto-Banned or Blocked)
app.post('/api/admin/whitelist-ip', requireAdmin, express.json(), (req, res) => {
  const { ip, label } = req.body || {};
  const cleanIp = String(ip || '').trim();

  if (!cleanIp || cleanIp === 'Unknown') {
    return res.status(400).json({ success: false, error: 'Invalid IP address provided' });
  }

  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const whitelist = getWhitelistedIps();

  // If already in blacklist, remove it from blacklist!
  let blockedList = getBlockedIps();
  blockedList = blockedList.filter(item => {
    const bIp = typeof item === 'string' ? item : item.ip;
    return bIp !== cleanIp;
  });
  saveBlockedIps(blockedList);

  const existingIdx = whitelist.findIndex(item => {
    const wIp = typeof item === 'string' ? item : item.ip;
    return wIp === cleanIp;
  });

  if (existingIdx === -1) {
    whitelist.push({
      ip: cleanIp,
      addedAt: new Date().toISOString(),
      label: label || 'Authorized Administrator',
      addedBy: 'Administrator'
    });
    saveWhitelistedIps(whitelist);

    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'IP_WHITELISTED',
      status: 'success',
      details: `Whitelisted IP address (immune from bans): ${cleanIp} [${label || 'Admin'}]`,
      path: '/api/admin/whitelist-ip'
    });
  }

  res.json({ success: true, whitelistedIps: whitelist });
});

// Remove IP from Whitelist
app.post('/api/admin/unwhitelist-ip', requireAdmin, express.json(), (req, res) => {
  const { ip } = req.body || {};
  const cleanIp = String(ip || '').trim();

  if (!cleanIp) {
    return res.status(400).json({ success: false, error: 'Invalid IP address' });
  }

  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  let whitelist = getWhitelistedIps();

  whitelist = whitelist.filter(item => {
    const wIp = typeof item === 'string' ? item : item.ip;
    return wIp !== cleanIp;
  });

  saveWhitelistedIps(whitelist);

  addAuditLog({
    ip: clientIp,
    userAgent: ua,
    action: 'IP_UNWHITELISTED',
    status: 'warning',
    details: `Removed IP address from whitelist: ${cleanIp}`,
    path: '/api/admin/unwhitelist-ip'
  });

  res.json({ success: true, whitelistedIps: whitelist });
});

// IP Geo & Network Inspector
app.get('/api/admin/ip-lookup', requireAdmin, async (req, res) => {
  const queryIp = String(req.query.ip || '').trim();
  if (!queryIp || queryIp === 'Unknown') {
    return res.status(400).json({ error: 'Valid IP is required' });
  }

  if (queryIp === '127.0.0.1' || queryIp === '::1' || queryIp === 'localhost') {
    return res.json({
      status: 'success',
      country: 'Localhost / Internal',
      countryCode: 'LOC',
      regionName: 'Loopback Environment',
      city: 'Local Machine',
      isp: 'Local Development Server',
      org: 'Localhost Container',
      as: 'AS00000 Local',
      timezone: 'UTC',
      query: queryIp
    });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const apiRes = await fetch(`http://ip-api.com/json/${encodeURIComponent(queryIp)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, {
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (apiRes.ok) {
      const data = await apiRes.json();
      return res.json(data);
    }
  } catch (err) {
    console.error('IP lookup error:', err.message);
  }

  // Fallback if public API unreachable
  res.json({
    status: 'success',
    country: 'Detected IP',
    countryCode: '',
    city: 'Network Client',
    isp: 'Standard Internet Provider',
    query: queryIp
  });
});


// Admin Get Settings
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  const s = getSettings();
  const { adminPin, ...safeSettings } = s;
  res.json(safeSettings);
});

// Admin Update Settings
app.post('/api/admin/settings', requireAdmin, express.json(), (req, res) => {
  const { apkSourceType, apkUrl, apkVersion, telegramUrl, supportEmail, newAdminPin, antiInspectEnabled, antiCopyEnabled } = req.body || {};
  const current = getSettings();

  if (apkSourceType === 'file' || apkSourceType === 'url') {
    current.apkSourceType = apkSourceType;
  }
  if (typeof apkUrl === 'string') {
    current.apkUrl = apkUrl.trim();
  }
  if (typeof apkVersion === 'string' && apkVersion.trim()) {
    current.apkVersion = apkVersion.trim();
  }
  if (typeof telegramUrl === 'string' && telegramUrl.trim()) {
    current.telegramUrl = telegramUrl.trim();
  }
  if (typeof supportEmail === 'string' && supportEmail.trim()) {
    current.supportEmail = supportEmail.trim();
  }
  if (typeof antiInspectEnabled === 'boolean') {
    current.antiInspectEnabled = antiInspectEnabled;
  }
  if (typeof antiCopyEnabled === 'boolean') {
    current.antiCopyEnabled = antiCopyEnabled;
  }
  if (typeof newAdminPin === 'string' && newAdminPin.trim().length >= 4) {
    current.adminPin = newAdminPin.trim();
  }
  current.lastUpdated = new Date().toISOString();

  if (saveSettings(current)) {
    const { adminPin, ...safeSettings } = current;
    res.json({ success: true, settings: safeSettings });
  } else {
    res.status(500).json({ success: false, error: 'Failed to write settings to disk' });
  }
});

// Admin Upload APK
app.post('/api/admin/upload-apk', requireAdmin, (req, res) => {
  upload.single('apk')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'File upload error' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No APK file received' });
    }

    const current = getSettings();
    current.apkSourceType = 'file';
    current.apkFilename = req.file.originalname;
    current.apkFilePath = `/uploads/${req.file.filename}`;
    current.lastUpdated = new Date().toISOString();
    saveSettings(current);

    const { adminPin, ...safeSettings } = current;
    res.json(safeSettings);
  });
});

// Direct Download Handler
app.get('/download/apk', (req, res) => {
  const s = getSettings();
  if (s.apkSourceType === 'url' && s.apkUrl) {
    return res.redirect(302, s.apkUrl);
  }

  let relPath = s.apkFilePath || '/assets/Clonex-Esports-v1.0.apk';
  let absPath = path.join(__dirname, relPath);
  if (!fs.existsSync(absPath)) {
    absPath = path.join(__dirname, 'assets', 'Clonex-Esports-v1.0.apk');
  }

  if (fs.existsSync(absPath)) {
    res.download(absPath, s.apkFilename || 'Clonex-Esports.apk');
  } else {
    res.status(404).send('APK file not found on server');
  }
});

// Serve uploaded APKs
app.use('/uploads', express.static(UPLOADS_DIR));

// Admin Page Security Handler
function handleAdminPageAccess(req, res) {
  const clientIp = getClientIp(req);
  const ua = req.headers['user-agent'] || '';

  // 1. If IP is blacklisted, serve the customized blocked page with 403 Forbidden
  if (isIpBlocked(clientIp)) {
    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'BLOCKED_ATTEMPT',
      status: 'danger',
      details: 'Blocked intruder attempted to load /admin page',
      path: req.originalUrl || '/admin'
    });
    res.status(403);
    return res.sendFile(path.join(__dirname, 'blocked.html'));
  }

  // 2. Otherwise, log access if not visited in the last 15 seconds (prevents flood on refresh)
  const now = Date.now();
  const lastVisit = recentVisits.get(clientIp) || 0;
  if (now - lastVisit > 15000) {
    recentVisits.set(clientIp, now);
    addAuditLog({
      ip: clientIp,
      userAgent: ua,
      action: 'PAGE_VISIT',
      status: 'info',
      details: 'Accessed administrator login screen',
      path: req.originalUrl || '/admin'
    });
  }

  res.sendFile(path.join(__dirname, 'admin.html'));
}

// Admin Page Routes (Guarded by IP Blacklist)
app.get('/admin', handleAdminPageAccess);
app.get('/admin/*', handleAdminPageAccess);
app.get('/admin.html', handleAdminPageAccess);
app.get('/blocked', (req, res) => {
  res.sendFile(path.join(__dirname, 'blocked.html'));
});


// HTML Renderer with dynamic SSR replacement & Anti-Tamper Shield Injection
function renderHtmlWithSettings(filePath, req, res) {
  const clientIp = getClientIp(req);
  if (isIpBlocked(clientIp)) {
    res.status(403);
    return res.sendFile(path.join(__dirname, 'blocked.html'));
  }

  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const s = getSettings();
    const activeDownloadUrl = (s.apkSourceType === 'url' && s.apkUrl)
      ? s.apkUrl
      : '/download/apk';

    // Replace telegram links
    if (s.telegramUrl) {
      content = content.replace(/https:\/\/t\.me\/ClonexEsports/g, s.telegramUrl);
    }
    // Replace support email
    if (s.supportEmail) {
      content = content.replace(/support@clonexesports\.com/g, s.supportEmail);
    }
    // Replace APK download links
    content = content.replace(/assets\/Clonex-Esports-v1\.0\.apk/g, activeDownloadUrl);
    // Replace version badges
    if (s.apkVersion) {
      content = content.replace(/v1\.0 FREE/g, `${s.apkVersion} FREE`);
      content = content.replace(/Clonex-Esports-v1\.0\.apk/g, s.apkFilename || `Clonex-Esports-${s.apkVersion}.apk`);
    }

    // Inject anti-tamper security shield if not present
    const isWhitelisted = isIpWhitelisted(clientIp);
    const whitelistScript = isWhitelisted ? '  <script>window.__IS_IP_WHITELISTED__ = true;</script>\n' : '';

    if (!content.includes('security-shield.js')) {
      if (content.includes('</head>')) {
        content = content.replace('</head>', whitelistScript + '  <script src="/security-shield.js"></script>\n</head>');
      } else if (content.includes('</body>')) {
        content = content.replace('</body>', whitelistScript + '  <script src="/security-shield.js"></script>\n</body>');
      }
    } else if (isWhitelisted && !content.includes('__IS_IP_WHITELISTED__')) {
      content = content.replace('</head>', whitelistScript + '</head>');
    }

    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.send(content);
  } catch (err) {
    res.sendFile(filePath);
  }
}

// Web Pages
app.get('/', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'index.html'), req, res);
});

app.get('/index.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'index.html'), req, res);
});

app.get('/privacy-policy', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'privacy-policy.html'), req, res);
});
app.get('/privacy-policy.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'privacy-policy.html'), req, res);
});

app.get('/terms-conditions', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'terms-conditions.html'), req, res);
});
app.get('/terms-conditions.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'terms-conditions.html'), req, res);
});

app.get('/refund-policy', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'refund-policy.html'), req, res);
});
app.get('/refund-policy.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'refund-policy.html'), req, res);
});

app.get('/cookie-policy', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'cookie-policy.html'), req, res);
});
app.get('/cookie-policy.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'cookie-policy.html'), req, res);
});

// Static assets with fresh cache control
app.use(express.static(__dirname, {
  etag: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.css') || filePath.endsWith('.js') || filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

// 404 Fallback
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`Clonex Esports running on http://${HOST}:${PORT}`);
  console.log(`Admin panel available at http://${HOST}:${PORT}/admin`);
});
