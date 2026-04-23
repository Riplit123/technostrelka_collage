// server.js
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const multer = require('multer');
const sharp = require('sharp');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// =====================================================
//   КОНФИГУРАЦИЯ
// =====================================================
const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'a7k2p';
const SUPERADMIN_SECRET = process.env.SUPERADMIN_SECRET || 'root-9xQ2k';
const MAX_UPLOAD_MB = 8;
const PHOTO_MAX_WIDTH = 1200;
const PHOTO_QUALITY = 82;
const MAX_APPROVED_PHOTOS = 200; // лимит фото в коллаже (скрытый)

const START_TIME = Date.now();

const BEHIND_PROXY =
  process.env.RENDER === 'true' ||
  process.env.BEHIND_PROXY === '1' ||
  process.env.NODE_ENV === 'production';

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const APPROVED_FILE = path.join(DATA_DIR, 'approved.json');
const PENDING_FILE = path.join(DATA_DIR, 'pending.json');
const STATE_FILE = path.join(DATA_DIR, 'state.json');

[DATA_DIR, UPLOAD_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const app = express();
const server = http.createServer(app);

// =====================================================
//   MIDDLEWARE
// =====================================================
if (BEHIND_PROXY) {
  app.set('trust proxy', 1);
  console.log('[config] trust proxy: 1 (production / behind proxy)');
} else {
  app.set('trust proxy', false);
  console.log('[config] trust proxy: false (local dev)');
}

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

app.use(compression({ level: 6, threshold: 1024 }));

app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));

// --- Rate limiting ---
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'too_many_requests' }
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'upload_limit' }
});

const approvedLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(generalLimiter);

// =====================================================
//   ХРАНИЛИЩЕ В ПАМЯТИ
// =====================================================
let pending = [];
let approved = [];
let rejectedSinceStart = 0;

// Глобальное состояние (управляется суперадмином)
let appState = {
  uploadsEnabled: true
};

function loadFromDisk() {
  try {
    if (fs.existsSync(PENDING_FILE)) {
      pending = JSON.parse(fs.readFileSync(PENDING_FILE, 'utf8'));
    }
    if (fs.existsSync(APPROVED_FILE)) {
      approved = JSON.parse(fs.readFileSync(APPROVED_FILE, 'utf8'));
    }
    if (fs.existsSync(STATE_FILE)) {
      const s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      if (s && typeof s.uploadsEnabled === 'boolean') {
        appState.uploadsEnabled = s.uploadsEnabled;
      }
    }
    console.log(`Загружено: pending=${pending.length}, approved=${approved.length}, uploadsEnabled=${appState.uploadsEnabled}`);
  } catch (e) {
    console.error('Ошибка чтения данных:', e);
  }
}

let pendingSaveTimer = null;
let approvedSaveTimer = null;
let stateSaveTimer = null;
function savePending() {
  if (pendingSaveTimer) return;
  pendingSaveTimer = setTimeout(() => {
    fs.writeFile(PENDING_FILE, JSON.stringify(pending), () => {});
    pendingSaveTimer = null;
  }, 1000);
}
function saveApproved() {
  if (approvedSaveTimer) return;
  approvedSaveTimer = setTimeout(() => {
    fs.writeFile(APPROVED_FILE, JSON.stringify(approved), () => {});
    approvedSaveTimer = null;
  }, 1000);
}
function saveState() {
  if (stateSaveTimer) return;
  stateSaveTimer = setTimeout(() => {
    fs.writeFile(STATE_FILE, JSON.stringify(appState), () => {});
    stateSaveTimer = null;
  }, 300);
}

loadFromDisk();

// =====================================================
//   UPLOAD
// =====================================================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (!/^image\/(jpeg|png|webp|heic|heif)$/i.test(file.mimetype)) {
      return cb(new Error('bad_mime'));
    }
    cb(null, true);
  }
});

function genId() {
  return crypto.randomBytes(8).toString('hex');
}

// =====================================================
//   СТАТИКА
// =====================================================
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '7d',
  etag: true,
  setHeaders: (res, filePath) => {
    if (/\.html$/.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

app.use('/uploads', express.static(UPLOAD_DIR, {
  maxAge: '30d',
  immutable: true,
  etag: false
}));

// =====================================================
//   ROUTES (страницы)
// =====================================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/upload/:id', (req, res) => {
  if (!/^[a-zA-Z0-9_-]{1,32}$/.test(req.params.id)) {
    return res.status(404).send('Not found');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/upload', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/screen', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'screen.html'));
});

app.get('/admin/:token', (req, res) => {
  const match = /^(\d+)-([a-zA-Z0-9]{3,10})$/.exec(req.params.token);
  if (!match || match[2] !== ADMIN_SECRET) {
    return res.status(404).send('Not found');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Страница суперадмина
app.get('/superadmin/:secret', (req, res) => {
  if (req.params.secret !== SUPERADMIN_SECRET) {
    return res.status(404).send('Not found');
  }
  res.sendFile(path.join(__dirname, 'public', 'superadmin.html'));
});

// Health-check
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    approved: approved.length,
    pending: pending.length,
    limitReached: approved.length >= MAX_APPROVED_PHOTOS,
    uploadsEnabled: appState.uploadsEnabled
  });
});

// =====================================================
//   API
// =====================================================

// Публичное API: состояние приёма фото (для страницы участника)
app.get('/api/uploads-state', (req, res) => {
  res.json({ ok: true, enabled: appState.uploadsEnabled });
});

// API: загрузка фото участником
app.post('/api/upload', uploadLimiter, upload.single('photo'), async (req, res) => {
  try {
    // Проверка глобального свича
    if (!appState.uploadsEnabled) {
      return res.status(423).json({ ok: false, error: 'uploads_disabled' });
    }

    if (!req.file) return res.status(400).json({ ok: false, error: 'no_file' });

    // Скрытый лимит по хранилищу: если всего (pending + approved) ≥ лимита — тихо отклоняем
    if ((pending.length + approved.length) >= MAX_APPROVED_PHOTOS) {
      return res.status(507).json({ ok: false, error: 'limit_reached' });
    }

    const uploaderId = typeof req.body.uploaderId === 'string'
      ? req.body.uploaderId.slice(0, 32).replace(/[^a-zA-Z0-9_-]/g, '')
      : null;

    const id = genId();
    const filename = `${id}.jpg`;
    const fullPath = path.join(UPLOAD_DIR, filename);

    await sharp(req.file.buffer, { failOn: 'none' })
      .rotate()
      .resize({ width: PHOTO_MAX_WIDTH, withoutEnlargement: true })
      .jpeg({ quality: PHOTO_QUALITY, mozjpeg: true })
      .toFile(fullPath);

    const url = `/uploads/${filename}`;
    const item = {
      id,
      url,
      createdAt: Date.now(),
      ip: req.ip,
      uploaderId: uploaderId || null
    };
    pending.push(item);
    savePending();

    broadcastToAdmins({ type: 'new_pending', item });
    broadcastToSupers({ type: 'stats_changed' });
    res.json({ ok: true, id });
  } catch (err) {
    console.error('upload error:', err.message);
    res.status(400).json({ ok: false, error: 'upload_failed' });
  }
});

// API: проверка админ-токена
app.get('/api/admin/check/:token', (req, res) => {
  const match = /^(\d+)-([a-zA-Z0-9]{3,10})$/.exec(req.params.token);
  if (!match || match[2] !== ADMIN_SECRET) {
    return res.status(403).json({ ok: false });
  }
  res.json({ ok: true, modId: match[1] });
});

// API: список pending (для админа)
app.get('/api/pending/:token', (req, res) => {
  const match = /^(\d+)-([a-zA-Z0-9]{3,10})$/.exec(req.params.token);
  if (!match || match[2] !== ADMIN_SECRET) {
    return res.status(403).json({ ok: false });
  }
  res.json({ ok: true, items: pending });
});

// API: модерация
app.post('/api/moderate/:token', (req, res) => {
  const match = /^(\d+)-([a-zA-Z0-9]{3,10})$/.exec(req.params.token);
  if (!match || match[2] !== ADMIN_SECRET) {
    return res.status(403).json({ ok: false });
  }

  const { id, action } = req.body;
  if (!id || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ ok: false });
  }

  const idx = pending.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ ok: false });

  const [item] = pending.splice(idx, 1);
  savePending();

  if (action === 'approve') {
    if (approved.length >= MAX_APPROVED_PHOTOS) {
      const filePath = path.join(UPLOAD_DIR, path.basename(item.url));
      fs.unlink(filePath, () => {});
      console.log(`[limit] Фото ${id} одобрено, но лимит ${MAX_APPROVED_PHOTOS} достигнут — тихо удалено`);
      broadcastToAdmins({ type: 'moderated', id, action });
      broadcastToSupers({ type: 'stats_changed' });
      return res.json({ ok: true });
    }

    const approvedItem = { id: item.id, url: item.url, approvedAt: Date.now() };
    approved.push(approvedItem);
    saveApproved();
    broadcastToScreens({ type: 'approved', url: item.url });
  } else {
    rejectedSinceStart++;
    const filePath = path.join(UPLOAD_DIR, path.basename(item.url));
    fs.unlink(filePath, () => {});
  }

  broadcastToAdmins({ type: 'moderated', id, action });
  broadcastToSupers({ type: 'stats_changed' });
  res.json({ ok: true });
});

// API: одобренные (для экрана)
app.get('/api/approved', approvedLimiter, (req, res) => {
  res.set('Cache-Control', 'public, max-age=5');
  res.json({ ok: true, items: approved.map(a => ({ url: a.url })) });
});

// =====================================================
//   SUPERADMIN API
// =====================================================
function checkSuperSecret(req) {
  const s = req.query.secret || req.headers['x-superadmin'];
  return s === SUPERADMIN_SECRET;
}

function getStoragePayload() {
  let totalBytes = 0;
  let fileCount = 0;
  try {
    const files = fs.readdirSync(UPLOAD_DIR);
    for (const f of files) {
      try {
        const st = fs.statSync(path.join(UPLOAD_DIR, f));
        if (st.isFile()) {
          totalBytes += st.size;
          fileCount++;
        }
      } catch(_) {}
    }
  } catch(_) {}
  return {
    bytes: totalBytes,
    mb: (totalBytes / (1024 * 1024)).toFixed(1),
    fileCount
  };
}

function countClientsByRole() {
  const counts = { uploader: 0, admin: 0, screen: 0, superadmin: 0 };
  wss.clients.forEach(c => {
    if (c.readyState !== WebSocket.OPEN) return;
    if (c.role && counts[c.role] !== undefined) counts[c.role]++;
  });
  return counts;
}

// Статистика
app.get('/api/super/stats', (req, res) => {
  if (!checkSuperSecret(req)) return res.status(403).json({ ok: false });

  const storage = getStoragePayload();
  const memMB = (process.memoryUsage().rss / (1024 * 1024)).toFixed(1);

  res.json({
    ok: true,
    uploadsEnabled: appState.uploadsEnabled,
    photo: {
      total: pending.length + approved.length,
      approved: approved.length,
      pending: pending.length,
      rejectedSinceStart,
      limit: MAX_APPROVED_PHOTOS
    },
    clients: countClientsByRole(),
    storage,
    uptimeMs: Date.now() - START_TIME,
    processUptimeS: Math.floor(process.uptime()),
    memoryMB: memMB
  });
});

// Свич приёма фото
app.post('/api/super/uploads-toggle', (req, res) => {
  if (!checkSuperSecret(req)) return res.status(403).json({ ok: false });

  const desired = typeof req.body.enabled === 'boolean'
    ? req.body.enabled
    : !appState.uploadsEnabled;

  appState.uploadsEnabled = desired;
  saveState();

  // Оповещаем все клиенты об изменении
  broadcastAll({ type: 'uploads_state', enabled: desired });

  console.log(`[super] uploadsEnabled => ${desired}`);
  res.json({ ok: true, enabled: desired });
});

// Стереть все фото
app.post('/api/super/wipe', (req, res) => {
  if (!checkSuperSecret(req)) return res.status(403).json({ ok: false });

  try {
    // Удаляем файлы с диска
    try {
      const files = fs.readdirSync(UPLOAD_DIR);
      for (const f of files) {
        try { fs.unlinkSync(path.join(UPLOAD_DIR, f)); } catch(_) {}
      }
    } catch(_) {}

    pending = [];
    approved = [];
    rejectedSinceStart = 0;

    // Форсим запись json-ов
    fs.writeFile(PENDING_FILE, JSON.stringify(pending), () => {});
    fs.writeFile(APPROVED_FILE, JSON.stringify(approved), () => {});

    // Оповещаем всех
    broadcastToScreens({ type: 'wipe' });
    broadcastToAdmins({ type: 'wipe' });
    broadcastToSupers({ type: 'wipe' });

    console.log('[super] WIPE — все фото удалены');
    res.json({ ok: true });
  } catch (e) {
    console.error('wipe error:', e);
    res.status(500).json({ ok: false, error: 'wipe_failed' });
  }
});

// =====================================================
//   404 + ОБРАБОТКА ОШИБОК
// =====================================================
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ ok: false, error: 'not_found' });
  }
  if (req.method === 'GET') {
    return res.redirect('/');
  }
  res.status(404).send('Not found');
});

app.use((err, req, res, next) => {
  if (err.message === 'bad_mime') {
    return res.status(400).json({ ok: false, error: 'bad_format' });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ ok: false, error: 'file_too_large' });
  }
  console.error(err);
  res.status(500).json({ ok: false, error: 'server_error' });
});

// =====================================================
//   WEBSOCKET
// =====================================================
const wss = new WebSocket.Server({ server, maxPayload: 64 * 1024 });

function heartbeat() { this.isAlive = true; }

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const role = url.searchParams.get('role');   // 'screen' | 'admin' | 'uploader' | 'superadmin'
  const token = url.searchParams.get('token'); // для admin/superadmin

  if (role === 'admin') {
    const match = /^(\d+)-([a-zA-Z0-9]{3,10})$/.exec(token || '');
    if (!match || match[2] !== ADMIN_SECRET) {
      ws.close(1008, 'forbidden');
      return;
    }
  } else if (role === 'superadmin') {
    if (token !== SUPERADMIN_SECRET) {
      ws.close(1008, 'forbidden');
      return;
    }
  } else if (role !== 'screen' && role !== 'uploader') {
    ws.close(1008, 'bad_role');
    return;
  }

  ws.role = role;
  ws.isAlive = true;
  ws.on('pong', heartbeat);
  ws.on('error', () => {});
  ws.on('close', () => {
    // уведомим суперадмина — счётчики клиентов могли поменяться
    broadcastToSupers({ type: 'clients_changed' });
  });

  // Сразу отдаём текущее состояние свича
  try {
    ws.send(JSON.stringify({ type: 'uploads_state', enabled: appState.uploadsEnabled }));
  } catch(_) {}

  // Суперадмину сразу сообщим о новом клиенте (для живых счётчиков)
  broadcastToSupers({ type: 'clients_changed' });
});

const hbInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => clearInterval(hbInterval));

function broadcastToScreens(obj) {
  const msg = JSON.stringify(obj);
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN && c.role === 'screen') c.send(msg);
  });
}

function broadcastToAdmins(obj) {
  const msg = JSON.stringify(obj);
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN && c.role === 'admin') c.send(msg);
  });
}

function broadcastToSupers(obj) {
  const msg = JSON.stringify(obj);
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN && c.role === 'superadmin') c.send(msg);
  });
}

function broadcastAll(obj) {
  const msg = JSON.stringify(obj);
  wss.clients.forEach(c => {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  });
}

// =====================================================
//   GRACEFUL SHUTDOWN
// =====================================================
process.on('SIGTERM', () => {
  console.log('SIGTERM');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  console.log('SIGINT');
  server.close(() => process.exit(0));
});

// =====================================================
//   ВСПОМОГАТЕЛЬНОЕ: LAN-IP
// =====================================================
function getLanIPs() {
  const ips = [];
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      // IPv4, не loopback, не virtual
      if (net.family === 'IPv4' && !net.internal) {
        ips.push(net.address);
      }
    }
  }
  return ips;
}

// =====================================================
//   СТАРТ
// =====================================================
server.listen(PORT, '0.0.0.0', () => {
  const adminToken = `1-${ADMIN_SECRET}`;
  const lanIps = getLanIPs();

  const lines = [];
  lines.push('');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push(`  🚀 Сервер запущен на порту ${PORT}`);
  lines.push('═══════════════════════════════════════════════════════');
  lines.push('');
  lines.push('  📍 Локально (этот компьютер):');
  lines.push(`     • Участник:   http://localhost:${PORT}/`)
  lines.push(`     • Участник (с ID): http://localhost:${PORT}/upload/1`);
  lines.push(`     • Коллаж:     http://localhost:${PORT}/screen`);
  lines.push(`     • Админ:      http://localhost:${PORT}/admin/${adminToken}`);
  lines.push(`     • 👑 Суперадмин: http://localhost:${PORT}/superadmin/${SUPERADMIN_SECRET}`);
  lines.push(`     • Health:     http://localhost:${PORT}/health`);
  lines.push('');

  if (lanIps.length) {
    lines.push('  📱 В локальной сети (Wi-Fi, для телефонов):');
    for (const ip of lanIps) {
      lines.push(`     • Участник:   http://${ip}:${PORT}/`);
      lines.push(`     • Коллаж:     http://${ip}:${PORT}/screen`);
      lines.push(`     • Админ:      http://${ip}:${PORT}/admin/${adminToken}`);
      lines.push(`     • 👑 Супер:   http://${ip}:${PORT}/superadmin/${SUPERADMIN_SECRET}`);
      lines.push('');
    }
  } else {
    lines.push('  ⚠  LAN IP не найден — телефоны подключить по Wi-Fi не получится');
    lines.push('');
  }

  lines.push('  ⚙  Настройки:');
  lines.push(`     • Лимит фото в коллаже: ${MAX_APPROVED_PHOTOS}`);
  lines.push(`     • Макс. размер загрузки: ${MAX_UPLOAD_MB} МБ`);
  lines.push(`     • Приём фото сейчас: ${appState.uploadsEnabled ? '✅ ВКЛЮЧЁН' : '⛔ ВЫКЛЮЧЕН'}`);
  lines.push(`     • Папка с данными: ${DATA_DIR}`);
  lines.push('');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push('');

  console.log(lines.join('\n'));
});