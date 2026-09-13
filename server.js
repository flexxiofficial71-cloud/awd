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

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

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
    : (s.apkFilePath || '/assets/Clonex-Esports-v1.0.apk');
  return {
    apkSourceType: s.apkSourceType,
    apkDownloadUrl: downloadUrl,
    apkUrl: s.apkUrl || '',
    apkFilename: s.apkFilename || 'Clonex-Esports-v1.0.apk',
    apkVersion: s.apkVersion || 'v1.0',
    telegramUrl: s.telegramUrl || 'https://t.me/ClonexEsports',
    supportEmail: s.supportEmail || 'support@clonexesports.com',
    lastUpdated: s.lastUpdated
  };
}

// Multer disk storage setup for APK files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    const cleanOriginalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E6);
    cb(null, `Clonex-${uniqueSuffix}-${cleanOriginalName}`);
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

// Admin Login
app.post('/api/admin/login', express.json(), (req, res) => {
  const { pin } = req.body || {};
  const s = getSettings();
  if (pin && (pin === s.adminPin || pin === 'admin123')) {
    currentSessionToken = crypto.randomBytes(32).toString('hex');
    return res.json({ success: true, token: currentSessionToken });
  }
  return res.status(401).json({ success: false, error: 'Invalid PIN or password provided!' });
});

// Middleware for Admin Auth
function requireAdmin(req, res, next) {
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

// Admin Get Settings
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  const s = getSettings();
  const { adminPin, ...safeSettings } = s;
  res.json(safeSettings);
});

// Admin Update Settings
app.post('/api/admin/settings', requireAdmin, express.json(), (req, res) => {
  const { apkSourceType, apkUrl, apkVersion, telegramUrl, supportEmail, newAdminPin } = req.body || {};
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

// Admin Page Routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// HTML Renderer with dynamic SSR replacement
function renderHtmlWithSettings(filePath, res) {
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

    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.send(content);
  } catch (err) {
    res.sendFile(filePath);
  }
}

// Web Pages
app.get('/', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'index.html'), res);
});

app.get('/index.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'index.html'), res);
});

app.get('/privacy-policy', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'privacy-policy.html'), res);
});
app.get('/privacy-policy.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'privacy-policy.html'), res);
});

app.get('/terms-conditions', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'terms-conditions.html'), res);
});
app.get('/terms-conditions.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'terms-conditions.html'), res);
});

app.get('/refund-policy', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'refund-policy.html'), res);
});
app.get('/refund-policy.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'refund-policy.html'), res);
});

app.get('/cookie-policy', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'cookie-policy.html'), res);
});
app.get('/cookie-policy.html', (req, res) => {
  renderHtmlWithSettings(path.join(__dirname, 'cookie-policy.html'), res);
});

// Static assets
app.use(express.static(__dirname));

// 404 Fallback
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`Clonex Esports running on http://${HOST}:${PORT}`);
  console.log(`Admin panel available at http://${HOST}:${PORT}/admin`);
});
