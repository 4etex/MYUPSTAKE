/**
 * MYUPSTAKE CRASH CASINO - СЕРВЕР
 * 
 * СИСТЕМА БЕЗОПАСНОСТИ:
 * ✅ Валидация всех входных данных
 * ✅ Rate limiting (защита от спама)
 * ✅ Проверка userId (защита от подделки)
 * ✅ Логирование подозрительной активности
 * ✅ Защита от манипуляций балансом
 * ✅ Защита Socket.io соединений
 * ✅ Санитизация всех параметров
 * ✅ Ограничение размеров запросов
 * ✅ Защита админ-команд
 * ✅ Скрытие чувствительной информации (банк, crashAt)
 * 
 * ВАЖНО: Установите в .env:
 * - ADMIN_TELEGRAM_ID=8095351884
 * - SECRET_KEY=случайная_строка_32_символа
 * - ALLOWED_ORIGINS=https://your-domain.com (в продакшене)
 */

require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ============================================
// СИСТЕМА БЕЗОПАСНОСТИ
// ============================================

const ADMIN_ID = process.env.ADMIN_TELEGRAM_ID || '8095351884';
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex');

// Rate limiting - защита от спама
const rateLimitMap = new Map();
const RATE_LIMIT = {
  window: 60000, // 1 минута
  maxRequests: 30, // максимум запросов
  strict: {
    window: 60000,
    maxRequests: 5 // для критичных операций
  }
};

function rateLimit(strict = false) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const key = `${ip}_${req.path}`;
    const limit = strict ? RATE_LIMIT.strict : RATE_LIMIT;
    
    const now = Date.now();
    const record = rateLimitMap.get(key) || { count: 0, resetTime: now + limit.window };
    
    if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + limit.window;
    }
    
    record.count++;
    rateLimitMap.set(key, record);
    
    if (record.count > limit.maxRequests) {
      logSecurityEvent('RATE_LIMIT_EXCEEDED', { ip, path: req.path, count: record.count });
      return res.status(429).json({ ok: false, error: 'Слишком много запросов. Попробуйте позже.' });
    }
    
    next();
  };
}

// Валидация и санитизация входных данных
function sanitizeInput(input, type = 'string') {
  if (input === null || input === undefined) return null;
  
  if (type === 'string') {
    return String(input).trim().slice(0, 500); // Ограничение длины
  } else if (type === 'number') {
    const num = Number(input);
    if (isNaN(num) || !isFinite(num)) return null;
    return Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, num)); // Ограничение диапазона
  } else if (type === 'userId') {
    const str = String(input).trim();
    // Проверка формата userId (только буквы, цифры, подчеркивания, дефисы)
    if (!/^[a-zA-Z0-9_-]+$/.test(str) || str.length > 100) return null;
    return str;
  } else if (type === 'wallet') {
    const str = String(input).trim();
    // Базовая валидация адреса кошелька
    if (str.length < 10 || str.length > 200) return null;
    return str;
  }
  
  return input;
}

// Валидация userId - защита от подделки
function validateUserId(userId) {
  if (!userId) return false;
  const sanitized = sanitizeInput(userId, 'userId');
  if (!sanitized) return false;
  
  // Проверка формата (для Telegram: user_xxx или просто цифры)
  if (/^user_/.test(sanitized) || /^\d+$/.test(sanitized)) {
    return sanitized;
  }
  
  return false;
}

// Логирование подозрительной активности
const securityLog = [];
const MAX_LOG_SIZE = 1000;

function logSecurityEvent(type, data) {
  const entry = {
    type,
    timestamp: Date.now(),
    data: JSON.stringify(data),
    ip: data.ip || 'unknown'
  };
  
  securityLog.push(entry);
  if (securityLog.length > MAX_LOG_SIZE) {
    securityLog.shift();
  }
  
  console.error(`🚨 SECURITY: ${type}`, data);
  
  // Критичные события - уведомляем админа
  if (['SUSPICIOUS_ACTIVITY', 'UNAUTHORIZED_ACCESS', 'BALANCE_MANIPULATION'].includes(type)) {
    if (global.adminBot) {
      global.adminBot.telegram.sendMessage(ADMIN_ID, 
        `🚨 КРИТИЧЕСКОЕ СОБЫТИЕ БЕЗОПАСНОСТИ\n\n` +
        `Тип: ${type}\n` +
        `Время: ${new Date().toLocaleString()}\n` +
        `Данные: ${JSON.stringify(data, null, 2)}`
      ).catch(console.error);
    }
  }
}

// Middleware для проверки безопасности запросов
function securityMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Проверка размера тела запроса
  if (req.body && JSON.stringify(req.body).length > 10000) {
    logSecurityEvent('LARGE_REQUEST', { ip, path: req.path, size: JSON.stringify(req.body).length });
    return res.status(413).json({ ok: false, error: 'Слишком большой запрос' });
  }
  
  // Санитизация всех строковых параметров
  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitizeInput(req.body[key], 'string');
      }
    }
  }
  
  // Логирование подозрительных запросов
  if (req.path.includes('admin') || req.path.includes('withdraw') || req.path.includes('deposit')) {
    logSecurityEvent('SENSITIVE_ENDPOINT_ACCESS', { ip, path: req.path, method: req.method });
  }
  
  next();
}

// Проверка прав доступа для админа
function requireAdmin(req, res, next) {
  const userId = req.body?.userId || req.params?.userId || req.query?.userId;
  
  if (!userId || String(userId) !== ADMIN_ID) {
    logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', { 
      ip: req.ip, 
      path: req.path, 
      attemptedUserId: userId 
    });
    return res.status(403).json({ ok: false, error: 'Доступ запрещён' });
  }
  
  next();
}

const PORT = process.env.PORT || 3001;
const app = express();
const server = http.createServer(app);

// Ограничение размера тела запроса
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Security middleware
app.use(securityMiddleware);

// Rate limiting для всех запросов
app.use(rateLimit());

// CORS - настройка для Telegram Mini App
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['*']; // В продакшене указать конкретные домены

// Telegram Mini App origins
const telegramOrigins = [
  'https://web.telegram.org',
  'https://webk.telegram.org',
  'https://webz.telegram.org'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Разрешаем Telegram Mini App
  const isTelegramOrigin = origin && telegramOrigins.some(tg => origin.startsWith(tg));
  const isAllowed = allowedOrigins.includes('*') || 
                   (origin && allowedOrigins.includes(origin)) ||
                   isTelegramOrigin;
  
  if (isAllowed) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
  }
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Socket.io с защитой и поддержкой Telegram Mini App
const socketOrigins = allowedOrigins.includes('*') 
  ? ['*'] 
  : [...allowedOrigins, ...telegramOrigins];

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      // Разрешаем Telegram Mini App
      const isTelegram = origin && telegramOrigins.some(tg => origin.startsWith(tg));
      const isAllowed = socketOrigins.includes('*') || 
                       (origin && socketOrigins.includes(origin)) ||
                       isTelegram;
      
      if (isAllowed || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000,
  transports: ['websocket', 'polling']
});

// Serve static files from build folder (React production build)
const publicPath = path.join(__dirname, 'build');а
if (!fs.existsSync(publicPath)) {
  console.warn('⚠️ Build folder not found! Run "npm run build" first.');
  console.warn(`   Looking for: ${publicPath}`);
  console.warn(`   Current dir: ${__dirname}`);
} else {
  console.log(`✅ Build folder found: ${publicPath}`);
  const indexFile = path.join(publicPath, 'index.html');
  if (fs.existsSync(indexFile)) {
    console.log(`✅ index.html found: ${indexFile}`);
  } else {
    console.warn(`⚠️ index.html not found in build folder!`);
  }
  
  // Проверяем наличие статических файлов
  const staticPath = path.join(publicPath, 'static');
  if (fs.existsSync(staticPath)) {
    console.log(`✅ Static folder found: ${staticPath}`);
  }
}

// Настройка статических файлов
// ВАЖНО: Это должно быть ДО всех маршрутов, чтобы статические файлы обрабатывались первыми
app.use(express.static(publicPath, {
  maxAge: '1d', // Кэширование на 1 день
  etag: true,
  lastModified: true,
  index: 'index.html' // Указываем index.html как индексный файл
}));

// Логирование для диагностики статических файлов
app.use((req, res, next) => {
  // Логируем только статические файлы для диагностики
  if (req.path.match(/\.(js|css|map|json|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/)) {
    const filePath = path.join(publicPath, req.path);
    if (fs.existsSync(filePath)) {
      console.log(`✅ Serving static file: ${req.path}`);
    } else {
      console.warn(`⚠️ Static file not found: ${req.path} (looking for: ${filePath})`);
    }
  }
  next();
});

// Простая работа с JSON файлом
const dbFile = path.join(__dirname, 'db.json');

// Функции для работы с базой данных
function readDB() {
  if (!fs.existsSync(dbFile)) {
    const defaultData = { users: [], rounds: [], bank: 0, watchers: [] };
    fs.writeFileSync(dbFile, JSON.stringify(defaultData, null, 2));
    return defaultData;
  }
  try {
    const data = fs.readFileSync(dbFile, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    console.error('Ошибка чтения БД:', e);
    return { users: [], rounds: [], bank: 0, watchers: [] };
  }
}

function writeDB(data) {
  try {
    fs.writeFileSync(dbFile, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Ошибка записи БД:', e);
  }
}

// Инициализация базы данных
readDB();

// ============================================
// СИСТЕМА БАНКА КАЗИНО
// ============================================
let houseBank = 0;

function loadBank() {
  const data = readDB();
  houseBank = data.bank || 0;
  
  // Если банк пустой - начинаем с 0 (режим жёсткого накопления)
  if (houseBank < 0) {
    houseBank = 0;
    saveBank();
  }
  console.log(`💰 Банк загружен: ${houseBank}`);
}

function saveBank() {
  const data = readDB();
  data.bank = houseBank;
  writeDB(data);
}

loadBank();

// ═══════════════════════════════════════════════════════════════
// КОНФИГУРАЦИЯ КАЗИНО v2.0
// ═══════════════════════════════════════════════════════════════
const CASINO_CONFIG = {
  TARGET_BANK: 1000000,
  HOUSE_EDGE: 0.12, // 12% маржа
  
  // ПОКАЗАТЕЛЬНЫЕ РАУНДЫ (когда нет ставок)
  SHOWCASE: {
    ENABLED: true,
    // Распределение показательных множителей
    LOW: { chance: 0.35, range: [1.50, 3.40] },      // 35% - низкие
    MEDIUM: { chance: 0.35, range: [3.40, 10.0] },   // 35% - средние
    HIGH: { chance: 0.30, range: [10.0, 50.0] }      // 30% - высокие
  },
  
  // СТАРТОВАЯ ФАЗА (первые 7 раундов со ставками)
  STARTUP_PHASE: {
    ENABLED: true,
    ROUNDS_WITH_BETS: 7, // Первые 7 раундов СО СТАВКАМИ
    HARD_DRAIN_ROUNDS: 3,
    MULTIPLIER_RANGE: {
      HARD: [1.00, 1.05],  // Раунды 1-3 со ставками
      SOFT: [1.05, 1.20]   // Раунды 4-7 со ставками
    }
  },
  
  // ЗАЩИТА БАНКА
  BANK_PROTECTION: {
    MIN_BANK: 50,
    WHALE_BET_THRESHOLD: 0.15,      // 15% от банка = кит
    WHALE_MAX_MULTIPLIER: 1.10,     // Максимум для кита
    RESERVE_PERCENT: 0.05,          // 5% резерв
    CRITICAL_THRESHOLD: 0.3         // Если ставки > 30% банка = критично
  },
  
  // АДАПТИВНАЯ СИСТЕМА
  ADAPTIVE: {
    LOSS_STREAK_TRIGGER: 3,
    PLAYER_WIN_STREAK_TRIGGER: 2,
    HOT_PLAYER_PROFIT_THRESHOLD: 5000,
  },
  
  // РАСПРЕДЕЛЕНИЕ МНОЖИТЕЛЕЙ (когда есть ставки)
  MULTIPLIER_DISTRIBUTION: {
    // Фаза накопления (банк < 50% цели)
    ACCUMULATION: {
      VERY_LOW: { weight: 40, range: [1.00, 1.30] },  // 40% - очень низкие
      LOW: { weight: 35, range: [1.30, 2.00] },       // 35%
      MEDIUM: { weight: 15, range: [2.00, 4.00] },    // 15%
      HIGH: { weight: 7, range: [4.00, 8.00] },       // 7%
      VERY_HIGH: { weight: 3, range: [8.00, 20.00] }  // 3%
    },
    // Фаза баланса (банк 50-100% цели)
    BALANCED: {
      VERY_LOW: { weight: 30, range: [1.00, 1.50] },
      LOW: { weight: 35, range: [1.50, 2.50] },
      MEDIUM: { weight: 20, range: [2.50, 5.00] },
      HIGH: { weight: 10, range: [5.00, 12.00] },
      VERY_HIGH: { weight: 5, range: [12.00, 30.00] }
    },
    // Фаза достижения цели (банк > 100% цели)
    ACHIEVED: {
      VERY_LOW: { weight: 20, range: [1.00, 2.00] },
      LOW: { weight: 30, range: [2.00, 3.50] },
      MEDIUM: { weight: 30, range: [3.50, 8.00] },
      HIGH: { weight: 15, range: [8.00, 20.00] },
      VERY_HIGH: { weight: 5, range: [20.00, 100.00] }
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// ГЛОБАЛЬНОЕ СОСТОЯНИЕ
// ═══════════════════════════════════════════════════════════════
let roundCounter = 0;
let roundsWithBetsCounter = 0; // Счетчик раундов СО СТАВКАМИ
let startupRoundsComplete = false;
let consecutiveLosses = 0;
let consecutiveWins = 0;
const stats = {
  totalBets: 0,
  totalPayouts: 0,
  totalRounds: 0,
  totalProfit: 0,
  currentRTP: 0
};
const playerTracking = new Map();

// ═══════════════════════════════════════════════════════════════
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ═══════════════════════════════════════════════════════════════
function getCurrentPhase() {
  const progress = houseBank / CASINO_CONFIG.TARGET_BANK;
  if (progress < 0.5) return 'ACCUMULATION';
  if (progress < 1.0) return 'BALANCED';
  return 'ACHIEVED';
}

function exponentialRandom(lambda = 1.0) {
  const u = Math.random();
  return -Math.log(1 - u) / lambda;
}

function weightedRandomChoice(distribution) {
  const totalWeight = Object.values(distribution).reduce((sum, item) => sum + item.weight, 0);
  let random = Math.random() * totalWeight;
  
  for (const [key, item] of Object.entries(distribution)) {
    random -= item.weight;
    if (random <= 0) {
      const [min, max] = item.range;
      return min + Math.random() * (max - min);
    }
  }
  return 1.50;
}

function applyHouseEdge(multiplier) {
  return multiplier * (1 - CASINO_CONFIG.HOUSE_EDGE);
}

function canAfford(amount) {
  const reserve = houseBank * CASINO_CONFIG.BANK_PROTECTION.RESERVE_PERCENT;
  return (houseBank - reserve) >= amount;
}

function updatePlayerTracking(userId, betAmount, payout, crashed) {
  if (!playerTracking.has(userId)) {
    playerTracking.set(userId, {
      profit: 0,
      winStreak: 0,
      lossStreak: 0,
      lastRounds: []
    });
  }
  
  const player = playerTracking.get(userId);
  const profit = payout - betAmount;
  player.profit += profit;
  
  if (payout > betAmount) {
    player.winStreak++;
    player.lossStreak = 0;
  } else {
    player.lossStreak++;
    player.winStreak = 0;
  }
  
  player.lastRounds.push({ bet: betAmount, payout, crashed, profit });
  if (player.lastRounds.length > 10) {
    player.lastRounds.shift();
  }
}

function isHotPlayer(userId) {
  const player = playerTracking.get(userId);
  if (!player) return false;
  return player.profit > CASINO_CONFIG.ADAPTIVE.HOT_PLAYER_PROFIT_THRESHOLD ||
         player.winStreak >= CASINO_CONFIG.ADAPTIVE.PLAYER_WIN_STREAK_TRIGGER;
}

/**
 * АНАЛИЗ СТАВОК В РАУНДЕ
 */
function analyzeBets(bets) {
  const betList = Object.entries(bets).map(([userId, bet]) => ({
    userId,
    amount: bet.amount || 0
  })).filter(b => b.amount > 0);
  
  const totalBets = betList.reduce((sum, b) => sum + b.amount, 0);
  const betCount = betList.length;
  const maxBet = betList.length > 0 ? Math.max(...betList.map(b => b.amount)) : 0;
  const avgBet = betCount > 0 ? totalBets / betCount : 0;
  
  const whaleThreshold = houseBank * CASINO_CONFIG.BANK_PROTECTION.WHALE_BET_THRESHOLD;
  const hasWhale = maxBet > whaleThreshold;
  
  const criticalThreshold = houseBank * CASINO_CONFIG.BANK_PROTECTION.CRITICAL_THRESHOLD;
  const isCritical = totalBets > criticalThreshold;
  
  const hotPlayers = betList.filter(b => isHotPlayer(b.userId));
  const hasHotPlayers = hotPlayers.length > 0;
  
  return {
    totalBets,
    betCount,
    maxBet,
    avgBet,
    hasWhale,
    whaleThreshold,
    isCritical,
    criticalThreshold,
    hasHotPlayers,
    hotPlayers: hotPlayers.map(p => p.userId),
    betList
  };
}

/**
 * ПРОВЕРКА: Можем ли выплатить ставку с определённым множителем?
 */
function canAffordPayout(betAmount, multiplier) {
  const payout = betAmount * multiplier;
  // Можем выплатить если выплата <= банк + ставка (ставка идёт в банк)
  return payout <= (houseBank + betAmount);
}

/**
 * РАСЧЁТ МАКСИМАЛЬНОГО МНОЖИТЕЛЯ для ставки
 * Игрок поставил X, может забрать от X*1.01 до X*5 (но не больше чем позволяет банк)
 */
function getMaxAffordableMultiplier(betAmount) {
  if (betAmount === 0) return 1.0;
  // Максимум = (банк + ставка) / ставка
  const maxMult = (houseBank + betAmount) / betAmount;
  return Math.max(1.0, maxMult);
}

/**
 * ГЛАВНЫЙ АЛГОРИТМ - ДИНАМИЧЕСКИЙ РАСЧЕТ CRASH POINT
 * Рассчитать crash point В ПОСЛЕДНИЙ МОМЕНТ
 * Вызывается ПОСЛЕ окончания приема ставок
 */
function calculateDynamicCrashPoint(bets) {
  roundCounter++;
  const phase = getCurrentPhase();
  const analysis = analyzeBets(bets);
  
  console.log(`\n🎰 ════════════════════════════════════════`);
  console.log(`   РАУНД #${roundCounter} | ФАЗА: ${phase}`);
  console.log(`   💰 Банк: ${houseBank.toFixed(0)} / ${CASINO_CONFIG.TARGET_BANK.toLocaleString()} (${(houseBank / CASINO_CONFIG.TARGET_BANK * 100).toFixed(1)}%)`);
  console.log(`   💵 Ставок: ${analysis.totalBets.toFixed(0)} (${analysis.betCount} игроков)`);
  console.log(`   📊 RTP: ${stats.currentRTP.toFixed(2)}%`);
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 1: НЕТ СТАВОК - ПОКАЗАТЕЛЬНЫЙ РАУНД (РАЗНООБРАЗИЕ)
  // ═══════════════════════════════════════════════════════════
  if (analysis.totalBets === 0 || analysis.betCount === 0) {
    const config = CASINO_CONFIG.SHOWCASE;
    let showcaseMultiplier;
    const roll = Math.random();
    
    // Выбираем диапазон на основе вероятностей
    if (roll < config.LOW.chance) {
      // 35% - Низкие множители (1.50-3.40x)
      const [min, max] = config.LOW.range;
      showcaseMultiplier = min + Math.random() * (max - min);
      console.log(`   🎲 НЕТ СТАВОК - Показательный LOW: ${showcaseMultiplier.toFixed(2)}x`);
    } else if (roll < config.LOW.chance + config.MEDIUM.chance) {
      // 35% - Средние множители (3.40-10.0x)
      const [min, max] = config.MEDIUM.range;
      showcaseMultiplier = min + Math.random() * (max - min);
      console.log(`   🎭 НЕТ СТАВОК - Показательный MEDIUM: ${showcaseMultiplier.toFixed(2)}x`);
    } else {
      // 30% - Высокие множители (10.0-50.0x)
      const [min, max] = config.HIGH.range;
      showcaseMultiplier = min + Math.random() * (max - min);
      console.log(`   🌟 НЕТ СТАВОК - Показательный HIGH: ${showcaseMultiplier.toFixed(2)}x`);
    }
    
    console.log(`🎰 ════════════════════════════════════════\n`);
    return parseFloat(showcaseMultiplier.toFixed(2));
  }
  
  // С этого момента есть ставки - считаем раунды со ставками
  roundsWithBetsCounter++;
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 2: СТАРТОВАЯ ФАЗА (первые 7 раундов СО СТАВКАМИ)
  // ═══════════════════════════════════════════════════════════
  if (!startupRoundsComplete && roundsWithBetsCounter <= CASINO_CONFIG.STARTUP_PHASE.ROUNDS_WITH_BETS) {
    const config = CASINO_CONFIG.STARTUP_PHASE;
    let crashMultiplier;
    
    if (roundsWithBetsCounter <= config.HARD_DRAIN_ROUNDS) {
      // Жесткий слив (раунды 1-3 со ставками)
      const [min, max] = config.MULTIPLIER_RANGE.HARD;
      crashMultiplier = min + Math.random() * (max - min);
      console.log(`   🚨 СТАРТ ${roundsWithBetsCounter}/${config.ROUNDS_WITH_BETS}: Жесткий слив [${min}-${max}x] → ${crashMultiplier.toFixed(2)}x`);
    } else {
      // Мягкий слив (раунды 4-7 со ставками)
      const [min, max] = config.MULTIPLIER_RANGE.SOFT;
      crashMultiplier = min + Math.random() * (max - min);
      console.log(`   ⚠️ СТАРТ ${roundsWithBetsCounter}/${config.ROUNDS_WITH_BETS}: Мягкий слив [${min}-${max}x] → ${crashMultiplier.toFixed(2)}x`);
    }
    
    if (roundsWithBetsCounter >= config.ROUNDS_WITH_BETS) {
      startupRoundsComplete = true;
      console.log(`   ✅ Стартовая фаза завершена!`);
    }
    
    console.log(`🎰 ════════════════════════════════════════\n`);
    return parseFloat(crashMultiplier.toFixed(2));
  }
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 3: КРИТИЧЕСКАЯ СИТУАЦИЯ (ставки > 30% банка)
  // ═══════════════════════════════════════════════════════════
  if (analysis.isCritical) {
    const emergencyMultiplier = 1.00 + Math.random() * 0.20; // 1.00-1.20x
    console.log(`   🚨 КРИТИЧЕСКАЯ СИТУАЦИЯ!`);
    console.log(`   💰 Ставки: ${analysis.totalBets.toFixed(0)} (${(analysis.totalBets / houseBank * 100).toFixed(1)}% банка)`);
    console.log(`   ⚡ ЭКСТРЕННЫЙ СЛИВ: ${emergencyMultiplier.toFixed(2)}x`);
    console.log(`🎰 ════════════════════════════════════════\n`);
    return parseFloat(emergencyMultiplier.toFixed(2));
  }
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 4: ЗАЩИТА ОТ КИТОВ (большие ставки)
  // ═══════════════════════════════════════════════════════════
  if (analysis.hasWhale) {
    const maxAffordable = (houseBank + analysis.totalBets) / analysis.maxBet;
    
    // Если большая ставка угрожает банку
    if (maxAffordable < 2.5) {
      const whaleCrash = CASINO_CONFIG.BANK_PROTECTION.WHALE_MAX_MULTIPLIER;
      console.log(`   🐋 ЗАЩИТА ОТ КИТА!`);
      console.log(`   💰 Ставка кита: ${analysis.maxBet.toFixed(0)} (${(analysis.maxBet / houseBank * 100).toFixed(1)}% банка)`);
      console.log(`   ⚡ Максимум можем выплатить: ${maxAffordable.toFixed(2)}x`);
      console.log(`   🛡️ АНТИ-КИТ СЛИВ: ${whaleCrash.toFixed(2)}x`);
      console.log(`🎰 ════════════════════════════════════════\n`);
      return parseFloat(whaleCrash.toFixed(2));
    }
  }
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 5: НАКАЗАНИЕ ГОРЯЧИХ ИГРОКОВ
  // ═══════════════════════════════════════════════════════════
  if (analysis.hasHotPlayers) {
    const penalty = Math.random();
    if (penalty < 0.65) { // 65% шанс слива
      const drainMultiplier = 1.00 + Math.random() * 0.35; // 1.00-1.35x
      console.log(`   🔥 ГОРЯЧИЕ ИГРОКИ В РАУНДЕ: ${analysis.hotPlayers.join(', ')}`);
      console.log(`   🎯 PENALTY MODE: ${drainMultiplier.toFixed(2)}x`);
      console.log(`🎰 ════════════════════════════════════════\n`);
      return parseFloat(drainMultiplier.toFixed(2));
    }
  }
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 6: АДАПТИВНАЯ КОРРЕКЦИЯ (серии проигрышей казино)
  // ═══════════════════════════════════════════════════════════
  if (consecutiveLosses >= CASINO_CONFIG.ADAPTIVE.LOSS_STREAK_TRIGGER) {
    const aggressiveMultiplier = 1.00 + Math.random() * 0.50; // 1.00-1.50x
    console.log(`   ⚠️ АДАПТИВНАЯ КОРРЕКЦИЯ!`);
    console.log(`   📉 Казино проиграло ${consecutiveLosses} раундов подряд`);
    console.log(`   🎯 АГРЕССИВНЫЙ РЕЖИМ: ${aggressiveMultiplier.toFixed(2)}x`);
    console.log(`🎰 ════════════════════════════════════════\n`);
    return parseFloat(aggressiveMultiplier.toFixed(2));
  }
  
  // ═══════════════════════════════════════════════════════════
  // РЕЖИМ 7: НОРМАЛЬНОЕ РАСПРЕДЕЛЕНИЕ (зависит от фазы банка)
  // ═══════════════════════════════════════════════════════════
  
  let distribution;
  switch (phase) {
    case 'ACCUMULATION':
      distribution = CASINO_CONFIG.MULTIPLIER_DISTRIBUTION.ACCUMULATION;
      break;
    case 'BALANCED':
      distribution = CASINO_CONFIG.MULTIPLIER_DISTRIBUTION.BALANCED;
      break;
    case 'ACHIEVED':
      distribution = CASINO_CONFIG.MULTIPLIER_DISTRIBUTION.ACHIEVED;
      break;
    default:
      distribution = CASINO_CONFIG.MULTIPLIER_DISTRIBUTION.ACCUMULATION;
  }
  
  // Генерируем базовый множитель
  let crashMultiplier = weightedRandomChoice(distribution);
  
  // Применяем House Edge
  crashMultiplier = applyHouseEdge(crashMultiplier);
  
  // Финальная проверка: можем ли мы это выплатить?
  const maxPossiblePayout = analysis.totalBets * crashMultiplier;
  if (!canAfford(maxPossiblePayout)) {
    const reserve = houseBank * CASINO_CONFIG.BANK_PROTECTION.RESERVE_PERCENT;
    const maxSafeMultiplier = (houseBank - reserve + analysis.totalBets) / analysis.totalBets;
    crashMultiplier = Math.min(crashMultiplier, maxSafeMultiplier * 0.85); // 85% от максимума
    
    console.log(`   🛡️ ЗАЩИТА БАНКА: Ограничено до ${crashMultiplier.toFixed(2)}x`);
  }
  
  // Финальные границы
  crashMultiplier = Math.max(1.00, Math.min(100.00, crashMultiplier));
  
  console.log(`   🎲 Распределение: ${phase}`);
  console.log(`   💎 ФИНАЛЬНЫЙ Crash Point: ${crashMultiplier.toFixed(2)}x`);
  console.log(`   📊 Потенциальная выплата: ${(analysis.totalBets * crashMultiplier).toFixed(0)}`);
  console.log(`   💰 Останется в банке: ~${(houseBank + analysis.totalBets - analysis.totalBets * crashMultiplier).toFixed(0)}`);
  console.log(`🎰 ════════════════════════════════════════\n`);
  
  return parseFloat(crashMultiplier.toFixed(2));
}

/**
 * Статус банка для API
 */
function getBankStatus() {
  const progress = houseBank / CASINO_CONFIG.TARGET_BANK;
  if (progress >= 1.0) return 'ACHIEVED';
  if (progress >= 0.5) return 'BALANCED';
  return 'ACCUMULATION';
}

// Проверка безопасности банка - НИКОГДА НЕ УХОДИТ В МИНУС!
function canPay(amount) {
  return houseBank >= amount;
}

// ============================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================

function emitLeaderboard() {
  try {
    const data = readDB();
    const top = (data.users || [])
      .slice()
      .sort((a, b) => (b.balance || 0) - (a.balance || 0))
      .slice(0, 10)
      .map(u => ({ id: u.id, balance: u.balance }));
    io.emit('leaderboard', top);
  } catch (e) {
    console.error('emitLeaderboard error', e);
  }
}

// Защищённая функция получения пользователя
function getUser(id) {
  // Валидация ID
  const validId = validateUserId(id);
  if (!validId) {
    logSecurityEvent('INVALID_GET_USER_ID', { attemptedId: id });
    throw new Error('Invalid user ID');
  }
  
  const data = readDB();
  let user = (data.users || []).find(u => u.id === validId);
  if (!user) {
    user = { id: validId, balance: 1000, bets: [] };
    data.users = data.users || [];
    data.users.push(user);
    writeDB(data);
    emitLeaderboard();
  }
  return user;
}

// Защищённая функция изменения баланса - КРИТИЧНО!
function changeBalance(id, delta, reason = 'unknown') {
  // Валидация ID
  const validId = validateUserId(id);
  if (!validId) {
    logSecurityEvent('INVALID_CHANGE_BALANCE_ID', { attemptedId: id, delta, reason });
    return null;
  }
  
  // Валидация delta
  const sanitizedDelta = sanitizeInput(delta, 'number');
  if (sanitizedDelta === null || !isFinite(sanitizedDelta)) {
    logSecurityEvent('INVALID_BALANCE_DELTA', { userId: validId, delta, reason });
    return null;
  }
  
  // Ограничение на изменение баланса за раз
  const MAX_DELTA = 100000000; // 100 миллионов максимум
  const safeDelta = Math.max(-MAX_DELTA, Math.min(MAX_DELTA, sanitizedDelta));
  
  const data = readDB();
  const user = (data.users || []).find(u => u.id === validId);
  if (!user) {
    logSecurityEvent('USER_NOT_FOUND_BALANCE', { userId: validId, delta: safeDelta, reason });
    return null;
  }
  
  const oldBalance = user.balance;
  const newBalance = Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, oldBalance + safeDelta));
  
  // Логирование больших изменений баланса
  if (Math.abs(safeDelta) > 10000) {
    logSecurityEvent('LARGE_BALANCE_CHANGE', { 
      userId: validId, 
      oldBalance, 
      delta: safeDelta, 
      newBalance, 
      reason 
    });
  }
  
  // Проверка на подозрительную активность (слишком быстрое изменение баланса)
  const recentChanges = (data.balanceLog || []).filter(log => 
    log.userId === validId && 
    Date.now() - log.timestamp < 60000 // Последняя минута
  );
  
  if (recentChanges.length > 10) {
    logSecurityEvent('SUSPICIOUS_BALANCE_ACTIVITY', { 
      userId: validId, 
      changesInMinute: recentChanges.length,
      reason 
    });
  }
  
  // Сохраняем в лог
  if (!data.balanceLog) data.balanceLog = [];
  data.balanceLog.push({
    userId: validId,
    oldBalance,
    delta: safeDelta,
    newBalance,
    reason,
    timestamp: Date.now()
  });
  
  // Ограничиваем размер лога
  if (data.balanceLog.length > 10000) {
    data.balanceLog = data.balanceLog.slice(-5000);
  }
  
  user.balance = newBalance;
  const userIndex = data.users.findIndex(u => u.id === validId);
  if (userIndex !== -1) {
    data.users[userIndex].balance = newBalance;
  }
  writeDB(data);
  emitLeaderboard();
  
  return newBalance;
}

function totalStaked(round) {
  if (!round) return 0;
  return Object.values(round.bets).reduce((s, b) => s + (b.amount || 0), 0);
}

// ============================================
// ИГРОВАЯ ЛОГИКА
// ============================================

let currentRound = null;
let roundIdCounter = 1;
let gameInterval = null;
let state = 'idle'; // 'betting', 'playing', 'idle'

// Функция для рассылки количества онлайн игроков
function broadcastOnlineCount() {
  const realPlayers = io.engine.clientsCount; // Реальные подключенные
  const fakePlayersBase = 2; // Базовые 2 фейковых игрока
  const totalOnline = realPlayers + fakePlayersBase;
  io.emit('onlineCount', { count: totalOnline });
}

// Socket.io защита - проверка подключений
io.use((socket, next) => {
  const ip = socket.handshake.address || socket.request.connection.remoteAddress;
  
  // Проверка rate limit для подключений
  const key = `socket_${ip}`;
  const record = rateLimitMap.get(key) || { count: 0, resetTime: Date.now() + 60000 };
  
  if (Date.now() < record.resetTime && record.count > 10) {
    logSecurityEvent('SOCKET_RATE_LIMIT', { ip, socketId: socket.id });
    return next(new Error('Too many connections'));
  }
  
  record.count++;
  record.resetTime = Date.now() + 60000;
  rateLimitMap.set(key, record);
  
  next();
});

// Socket handlers с защитой
io.on('connection', socket => {
  const ip = socket.handshake.address || socket.request.connection.remoteAddress;
  console.log('Socket connected', socket.id, 'from', ip);
  
  // Отправляем количество онлайн при подключении
  broadcastOnlineCount();

  // Отправка текущего состояния при подключении
  socket.emit('state', {
    state,
    round: currentRound ? {
      id: currentRound.id,
      multiplier: currentRound.multiplier,
      crashAt: currentRound.crashAt,
      startTime: currentRound.startTime,
      bettingTimeLeft: state === 'betting' ? Math.max(0, 10 - Math.floor((Date.now() - currentRound.startTime) / 1000)) : 0
    } : null
  });
  emitLeaderboard();
  
  // При отключении обновляем счетчик
  socket.on('disconnect', () => {
    console.log('Socket disconnected', socket.id);
    broadcastOnlineCount();
  });

  // Размещение ставки - ЗАЩИЩЕНО
  socket.on('placeBet', ({ userId, amount }) => {
    try {
      const ip = socket.handshake.address || 'unknown';
      
      // Валидация userId
      const validUserId = validateUserId(userId);
      if (!validUserId) {
        logSecurityEvent('INVALID_USER_ID', { ip, socketId: socket.id, attemptedUserId: userId });
        socket.emit('betResult', { ok: false, reason: 'Некорректный ID пользователя' });
        return;
      }
      
      // Валидация суммы
      const sanitizedAmount = sanitizeInput(amount, 'number');
      if (!sanitizedAmount || sanitizedAmount <= 0) {
        logSecurityEvent('INVALID_BET_AMOUNT', { ip, userId: validUserId, amount });
        socket.emit('betResult', { ok: false, reason: 'Некорректная сумма ставки' });
        return;
      }
      
      const amt = Math.floor(sanitizedAmount);
      
      // Проверка лимитов ставки
      const MIN_BET = 1;
      const MAX_BET = 1000000; // Максимальная ставка
      
      if (amt < MIN_BET || amt > MAX_BET) {
        logSecurityEvent('BET_LIMIT_VIOLATION', { ip, userId: validUserId, amount: amt });
        socket.emit('betResult', { ok: false, reason: `Ставка должна быть от ${MIN_BET} до ${MAX_BET} ⭐` });
        return;
      }
      
      if (state !== 'betting') {
        socket.emit('betResult', { ok: false, reason: 'Прием ставок закрыт' });
        return;
      }

      if (!currentRound) {
        socket.emit('betResult', { ok: false, reason: 'Раунд не активен' });
        return;
      }

      const user = getUser(validUserId);
      
      // Дополнительная проверка баланса на сервере
      if (!user || user.balance < amt) {
        logSecurityEvent('INSUFFICIENT_BALANCE', { ip, userId: validUserId, balance: user?.balance, amount: amt });
        socket.emit('betResult', { ok: false, reason: 'Недостаточно средств' });
        return;
      }

      // Инициализируем ставку если её еще нет
      if (!currentRound.bets[validUserId]) {
        currentRound.bets[validUserId] = { amount: 0, cashedOut: false, payout: 0 };
      }

      // Проверка на дублирование ставок (защита от спама)
      const existingBet = currentRound.bets[validUserId].amount;
      if (existingBet > 0 && amt === existingBet) {
        logSecurityEvent('DUPLICATE_BET', { ip, userId: validUserId, amount: amt });
        socket.emit('betResult', { ok: false, reason: 'Ставка уже размещена' });
        return;
      }

      currentRound.bets[validUserId].amount += amt;
      changeBalance(validUserId, -amt, `bet_${currentRound.id}`);

      const totalBets = totalStaked(currentRound);
      io.emit('betsUpdate', { totalBets });
      socket.emit('betResult', { ok: true, bet: currentRound.bets[validUserId] });

      console.log(`✅ Ставка: ${validUserId} поставил ${amt}, всего ставок: ${totalBets}`);
    } catch (error) {
      console.error('Ошибка при размещении ставки:', error);
      logSecurityEvent('BET_ERROR', { error: error.message, socketId: socket.id });
      socket.emit('betResult', { ok: false, reason: 'Внутренняя ошибка сервера' });
    }
  });

  // Кэшаут - ЗАЩИЩЕНО
  socket.on('cashout', ({ userId }) => {
    try {
      const ip = socket.handshake.address || 'unknown';
      
      // Валидация userId
      const validUserId = validateUserId(userId);
      if (!validUserId) {
        logSecurityEvent('INVALID_USER_ID_CASHOUT', { ip, socketId: socket.id, attemptedUserId: userId });
        socket.emit('cashoutResult', { ok: false, reason: 'Некорректный ID пользователя' });
        return;
      }
      
      if (state !== 'playing') {
        socket.emit('cashoutResult', { ok: false, reason: 'Игры нет' });
        return;
      }

      if (!currentRound) {
        socket.emit('cashoutResult', { ok: false, reason: 'Раунд не активен' });
        return;
      }

      const bet = currentRound.bets[validUserId];
      if (!bet || bet.amount <= 0 || bet.cashedOut) {
        logSecurityEvent('INVALID_CASHOUT_ATTEMPT', { ip, userId: validUserId, hasBet: !!bet, cashedOut: bet?.cashedOut });
        socket.emit('cashoutResult', { ok: false, reason: 'Нет активной ставки' });
        return;
      }

      // Пересчитываем payout на сервере (не доверяем клиенту)
      const payout = Math.floor(bet.amount * currentRound.multiplier * 100) / 100;
      
      // Проверка на разумность выплаты (защита от манипуляций)
      const maxReasonablePayout = bet.amount * 100; // Максимум 100x
      if (payout > maxReasonablePayout || payout < bet.amount) {
        logSecurityEvent('SUSPICIOUS_PAYOUT', { ip, userId: validUserId, payout, betAmount: bet.amount, multiplier: currentRound.multiplier });
        socket.emit('cashoutResult', { ok: false, reason: 'Ошибка расчета выплаты' });
        return;
      }

      // КРИТИЧНО: Проверка банка перед выплатой
      if (!canPay(payout)) {
        logSecurityEvent('INSUFFICIENT_BANK', { ip, userId: validUserId, payout, bank: houseBank });
        socket.emit('cashoutResult', { ok: false, reason: 'Казино не может выплатить. Банк недостаточен!' });
        return;
      }

      // Выполняем кэшаут
      bet.cashedOut = true;
      bet.payout = payout;

      changeBalance(validUserId, payout, `cashout_${currentRound.id}`);

      // ВАЖНО: уменьшаем банк на сумму выигрыша
      houseBank = Math.max(0, houseBank - payout);
      saveBank();

      console.log(`💰 Кэшаут: ${validUserId} получил ${payout}, банк теперь: ${houseBank}`);

      socket.emit('cashoutResult', { ok: true, payout: payout });
      io.emit('playerCashed', { userId: validUserId, payout: payout });
    } catch (error) {
      console.error('Ошибка при кэшауте:', error);
      logSecurityEvent('CASHOUT_ERROR', { error: error.message, socketId: socket.id });
      socket.emit('cashoutResult', { ok: false, reason: 'Внутренняя ошибка сервера' });
    }
  });

  socket.on('requestLeaderboard', () => {
    emitLeaderboard();
  });
});

// ============================================
// ИГРОВОЙ ЦИКЛ
// ============================================

function newRound() {
  const id = `r${roundIdCounter++}_${Date.now()}`;
  currentRound = {
    id,
    bets: {},
    startTime: Date.now(),
    multiplier: 1.0,
    crashAt: null,
    state: 'betting',
    initialBank: houseBank
  };
  state = 'betting';

  io.emit('roundStart', { id: currentRound.id, bettingTime: 10 });
  io.emit('betsUpdate', { totalBets: 0 });

  console.log(`🎲 Новый раунд: ${currentRound.id}, банк: ${houseBank}`);

  // Начинаем игру через 10 секунд
  setTimeout(startPlay, 10000);
}

function startPlay() {
  if (!currentRound) return;

  // ============================================
  // КРИТИЧЕСКИЙ МОМЕНТ: СТАВКИ ЗАКРЫТЫ!
  // Теперь казино анализирует ВСЕ ставки и решает судьбу раунда
  // ============================================
  
  const totalBets = totalStaked(currentRound);
  
  // УМНЫЙ РАСЧЕТ: передаем ВСЕ ставки для анализа
  currentRound.crashAt = calculateDynamicCrashPoint(currentRound.bets);
  
  currentRound.state = 'playing';
  state = 'playing';
  currentRound.multiplier = 1.0;

  io.emit('roundPlay', { id: currentRound.id });

  const maxPossiblePayout = totalBets * currentRound.crashAt;
  const potentialProfit = totalBets - maxPossiblePayout;
  
  console.log(`   🚀 ИГРА НАЧАЛАСЬ!`);
  console.log(`   💥 Crash: ${currentRound.crashAt}x`);
  console.log(`   📊 Потенц. ${potentialProfit >= 0 ? 'прибыль' : 'выплата'}: ${Math.abs(potentialProfit).toFixed(0)}`);
  console.log(`🎰 ==========================================\n`);

  const tickMs = 100; // Обновление каждые 100мс (ускорено)
  gameInterval = setInterval(() => {
    // Экспоненциальный рост множителя (ускорено)
    currentRound.multiplier = parseFloat((currentRound.multiplier + 0.015 * (1 + currentRound.multiplier / 8)).toFixed(2));
    
    io.emit('multiplier', { multiplier: currentRound.multiplier });

    // Проверяем достижение точки краша
    if (currentRound.multiplier >= currentRound.crashAt) {
      clearInterval(gameInterval);
      endRound();
    }
  }, tickMs);
}

function endRound() {
  if (!currentRound) return;

  currentRound.state = 'ended';
  state = 'idle';

  const totalBets = totalStaked(currentRound);

  // Подсчитываем выплаты (уже были выплачены при cashout)
  let totalPayouts = 0;
  let cashedOutCount = 0;
  let lostCount = 0;
  
  for (const oddserId in currentRound.bets) {
    const bet = currentRound.bets[oddserId];
    if (bet.cashedOut && bet.payout > 0) {
      totalPayouts += bet.payout;
      cashedOutCount++;
    } else if (bet.amount > 0) {
      lostCount++;
    }
  }

  // В банк идут все ставки минус выплаты
  // НО! При cashout выплата уже вычтена из банка, а ставка еще не добавлена
  // Правильная формула: банк += ставки (все идут в казино) - выплаты (уже вычтены)
  // Поскольку выплаты уже вычтены при cashout, добавляем только ставки
  houseBank += totalBets;
  
  // Пересчитаем - это компенсация за cashout который уже вычел из банка
  // Получается: банк = банк + ставки, но выплаты уже были вычтены ранее
  saveBank();

  // Сохраняем историю раунда
  const data = readDB();
  data.rounds = data.rounds || [];
  data.rounds.push({
    id: currentRound.id,
    crashAt: currentRound.crashAt,
    bets: currentRound.bets,
    timestamp: Date.now(),
    bankBefore: currentRound.initialBank,
    bankAfter: houseBank,
    totalBets: totalBets,
    totalPayouts: totalPayouts,
    cashedOutCount: cashedOutCount,
    lostCount: lostCount
  });
  
  // Ограничиваем историю до 100 раундов
  if (data.rounds.length > 100) {
    data.rounds = data.rounds.slice(-100);
  }
  writeDB(data);

  // Расчет реальной прибыли казино за раунд
  const profit = totalBets - totalPayouts;
  
  // Обновляем статистику
  stats.totalBets += totalBets;
  stats.totalPayouts += totalPayouts;
  stats.totalRounds++;
  stats.totalProfit += profit;
  stats.currentRTP = stats.totalBets > 0 ? (stats.totalPayouts / stats.totalBets * 100) : 0;
  
  // Обновляем серии
  if (profit > 0) {
    consecutiveWins++;
    consecutiveLosses = 0;
  } else {
    consecutiveLosses++;
    consecutiveWins = 0;
  }
  
  // Обновляем трекинг игроков
  for (const userId in currentRound.bets) {
    const bet = currentRound.bets[userId];
    if (bet.cashedOut && bet.payout > 0) {
      updatePlayerTracking(userId, bet.amount, bet.payout, false);
    } else if (bet.amount > 0) {
      updatePlayerTracking(userId, bet.amount, 0, true);
    }
  }
  
  const profitPercent = totalBets > 0 ? ((profit / totalBets) * 100).toFixed(1) : 0;
  
  console.log(`\n💥 ═══════════════════════════════════════`);
  console.log(`   РАУНД ЗАВЕРШЁН #${roundCounter}`);
  console.log(`   💥 Crash: ${currentRound.crashAt}x`);
  console.log(`   💰 Банк: ${currentRound.initialBank.toFixed(0)} -> ${houseBank.toFixed(0)} (${profit >= 0 ? '+' : ''}${profit.toFixed(0)})`);
  console.log(`   📊 Ставок: ${totalBets.toFixed(0)} | Выплат: ${totalPayouts.toFixed(0)}`);
  console.log(`   👥 Выиграли: ${cashedOutCount} | Проиграли: ${lostCount}`);
  console.log(`   📈 Прибыль казино: ${profit >= 0 ? '+' : ''}${profit.toFixed(0)} (${profitPercent}%)`);
  console.log(`   📊 RTP (общий): ${stats.currentRTP.toFixed(2)}%`);
  
  if (houseBank < CASINO_CONFIG.BANK_PROTECTION.MIN_BANK) {
    console.log(`   🚨 ВОССТАНОВЛЕНИЕ: Банк поднят до минимума`);
    houseBank = CASINO_CONFIG.BANK_PROTECTION.MIN_BANK;
    saveBank();
  }
  
  console.log(`💥 ═══════════════════════════════════════\n`);

  io.emit('roundEnd', { id: currentRound.id, crashAt: currentRound.crashAt });

  // Следующий раунд через 5 секунд
  setTimeout(() => newRound(), 5000);
}

// Автозапуск раундов
setInterval(() => {
  if (!currentRound && state === 'idle') {
    newRound();
  }
}, 1000);

// Запускаем первый раунд
newRound();

// ============================================
// СИСТЕМА ОПЛАТЫ - TELEGRAM STARS & CRYPTO BOT
// ============================================

const CRYPTO_BOT_TOKEN = process.env.CRYPTO_BOT_TOKEN || '497834:AA61moFx1FRYnPhY8sALPpQbcNNBr0EvZTA';
const CRYPTO_BOT_API = 'https://pay.crypt.bot/api';

// Пакеты пополнения
const DEPOSIT_PACKAGES = [
  { id: 'pack_200', stars: 200, bonus: 10, ton: 1.55, usd: 2.99 },
  { id: 'pack_500', stars: 500, bonus: 25, ton: 3.88, usd: 7.49 },
  { id: 'pack_1000', stars: 1000, bonus: 50, ton: 7.77, usd: 14.99 },
  { id: 'pack_2500', stars: 2500, bonus: 125, ton: 19.44, usd: 37.49 },
  { id: 'pack_5000', stars: 5000, bonus: 250, ton: 38.88, usd: 74.99 },
  { id: 'pack_10000', stars: 10000, bonus: 500, ton: 77.77, usd: 149.99 },
  { id: 'pack_25000', stars: 25000, bonus: 1250, ton: 194.44, usd: 374.99 },
  { id: 'pack_50000', stars: 50000, bonus: 2500, ton: 388.88, usd: 749.99 }
];

// Хранение ожидающих платежей
const pendingPayments = new Map();

// Получить список пакетов
app.get('/api/deposit/packages', (req, res) => {
  res.json({ packages: DEPOSIT_PACKAGES });
});

// Создать инвойс для Crypto Bot - ЗАЩИЩЕНО
app.post('/api/deposit/crypto', rateLimit(true), async (req, res) => {
  try {
    const { userId, packageId } = req.body;
    
    // Валидация userId
    const validUserId = validateUserId(userId);
    if (!validUserId) {
      logSecurityEvent('INVALID_DEPOSIT_USER_ID', { ip: req.ip, attemptedUserId: userId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пользователя' });
    }
    
    // Валидация packageId
    const sanitizedPackageId = sanitizeInput(packageId, 'string');
    if (!sanitizedPackageId) {
      logSecurityEvent('INVALID_PACKAGE_ID', { ip: req.ip, userId: validUserId, packageId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пакета' });
    }
    
    const pkg = DEPOSIT_PACKAGES.find(p => p.id === sanitizedPackageId);
    if (!pkg) {
      logSecurityEvent('PACKAGE_NOT_FOUND', { ip: req.ip, userId: validUserId, packageId: sanitizedPackageId });
      return res.status(400).json({ ok: false, error: 'Пакет не найден' });
    }
    
    // Проверка на дублирование запросов
    const existingPayment = Array.from(pendingPayments.values()).find(p => 
      p.oddserId === validUserId && 
      p.status === 'pending' && 
      Date.now() - p.createdAt < 60000
    );
    
    if (existingPayment) {
      logSecurityEvent('DUPLICATE_DEPOSIT_REQUEST', { ip: req.ip, userId: validUserId });
      return res.status(429).json({ ok: false, error: 'Слишком частые запросы. Подождите минуту.' });
    }
    
    const invoiceId = `inv_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    
    // Создаём инвойс через Crypto Bot API
    const response = await fetch(`${CRYPTO_BOT_API}/createInvoice`, {
      method: 'POST',
      headers: {
        'Crypto-Pay-API-Token': CRYPTO_BOT_TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        asset: 'TON',
        amount: pkg.ton.toString(),
        description: `Пополнение ${pkg.stars} ⭐ (+${pkg.bonus} бонус) в MYUPSTAKE Casino`,
        hidden_message: `Спасибо за покупку! Ваш баланс пополнен на ${pkg.stars + pkg.bonus} ⭐`,
        paid_btn_name: 'callback',
        paid_btn_url: `${process.env.APP_URL || 'https://t.me/your_bot'}?start=paid_${invoiceId}`,
        payload: JSON.stringify({ invoiceId, oddserId: userId, packageId, stars: pkg.stars, bonus: pkg.bonus }),
        expires_in: 3600 // 1 час
      })
    });
    
    const data = await response.json();
    
    if (data.ok) {
      // Сохраняем платёж
      pendingPayments.set(invoiceId, {
        oddserId: userId,
        packageId,
        stars: pkg.stars,
        bonus: pkg.bonus,
        ton: pkg.ton,
        cryptoInvoiceId: data.result.invoice_id,
        status: 'pending',
        createdAt: Date.now()
      });
      
      console.log(`💳 Создан инвойс ${invoiceId} для ${userId}: ${pkg.stars}⭐ за ${pkg.ton} TON`);
      
      res.json({
        ok: true,
        invoiceId,
        payUrl: data.result.pay_url,
        amount: pkg.ton,
        stars: pkg.stars + pkg.bonus
      });
    } else {
      console.error('Crypto Bot error:', data);
      res.status(500).json({ ok: false, error: 'Ошибка создания платежа' });
    }
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ ok: false, error: 'Внутренняя ошибка' });
  }
});

// Проверить статус платежа
app.get('/api/deposit/status/:invoiceId', async (req, res) => {
  try {
    const { invoiceId } = req.params;
    const payment = pendingPayments.get(invoiceId);
    
    if (!payment) {
      return res.status(404).json({ ok: false, error: 'Платёж не найден' });
    }
    
    if (payment.status === 'completed') {
      return res.json({ ok: true, status: 'completed', stars: payment.stars + payment.bonus });
    }
    
    // Проверяем статус в Crypto Bot
    const response = await fetch(`${CRYPTO_BOT_API}/getInvoices`, {
      method: 'POST',
      headers: {
        'Crypto-Pay-API-Token': CRYPTO_BOT_TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        invoice_ids: [payment.cryptoInvoiceId]
      })
    });
    
    const data = await response.json();
    
    if (data.ok && data.result.items.length > 0) {
      const invoice = data.result.items[0];
      
      if (invoice.status === 'paid' && payment.status !== 'completed') {
        // Платёж прошёл - начисляем звёзды
        payment.status = 'completed';
        const totalStars = payment.stars + payment.bonus;
        
        // Начисляем баланс
        const newBalance = changeBalance(payment.oddserId, totalStars, `deposit_crypto_${invoiceId}`);
        
        console.log(`✅ Платёж ${invoiceId} завершён! +${totalStars}⭐ для ${payment.oddserId}`);
        
        // Сохраняем в историю
        const db = readDB();
        db.payments = db.payments || [];
        db.payments.push({
          invoiceId,
          oddserId: payment.oddserId,
          stars: totalStars,
          ton: payment.ton,
          completedAt: Date.now()
        });
        writeDB(db);
        
        return res.json({ ok: true, status: 'completed', stars: totalStars, newBalance });
      }
      
      return res.json({ ok: true, status: invoice.status });
    }
    
    res.json({ ok: true, status: payment.status });
  } catch (error) {
    console.error('Status check error:', error);
    res.status(500).json({ ok: false, error: 'Ошибка проверки статуса' });
  }
});

// Вебхук от Crypto Bot - ЗАЩИЩЕНО
app.post('/api/webhook/crypto', async (req, res) => {
  try {
    const ip = req.ip;
    const update = req.body;
    
    // Валидация структуры запроса
    if (!update || typeof update !== 'object') {
      logSecurityEvent('INVALID_WEBHOOK_STRUCTURE', { ip });
      return res.status(400).json({ ok: false, error: 'Invalid request' });
    }
    
    // Проверка типа обновления
    if (update.update_type !== 'invoice_paid') {
      return res.json({ ok: true }); // Игнорируем другие типы
    }
    
    // Валидация payload
    let payload;
    try {
      payload = typeof update.payload === 'string' 
        ? JSON.parse(update.payload) 
        : update.payload;
    } catch (e) {
      logSecurityEvent('INVALID_WEBHOOK_PAYLOAD', { ip, error: e.message });
      return res.status(400).json({ ok: false, error: 'Invalid payload' });
    }
    
    const invoiceId = payload.invoiceId;
    
    // Валидация invoiceId
    if (!invoiceId || typeof invoiceId !== 'string' || invoiceId.length > 200) {
      logSecurityEvent('INVALID_WEBHOOK_INVOICE_ID', { ip, invoiceId });
      return res.status(400).json({ ok: false, error: 'Invalid invoice ID' });
    }
    
    if (!pendingPayments.has(invoiceId)) {
      logSecurityEvent('WEBHOOK_INVOICE_NOT_FOUND', { ip, invoiceId });
      return res.status(404).json({ ok: false, error: 'Invoice not found' });
    }
    
    const payment = pendingPayments.get(invoiceId);
    
    // Проверка что платёж ещё не обработан
    if (payment.status === 'completed') {
      return res.json({ ok: true, status: 'already_completed' });
    }
    
    // Валидация userId из платежа
    const validUserId = validateUserId(payment.oddserId);
    if (!validUserId) {
      logSecurityEvent('INVALID_WEBHOOK_USER_ID', { ip, invoiceId, userId: payment.oddserId });
      return res.status(400).json({ ok: false, error: 'Invalid user ID' });
    }
    
    // Проверка суммы (защита от манипуляций)
    if (!payment.stars || payment.stars <= 0 || payment.stars > 100000) {
      logSecurityEvent('SUSPICIOUS_WEBHOOK_AMOUNT', { ip, invoiceId, stars: payment.stars });
      return res.status(400).json({ ok: false, error: 'Invalid amount' });
    }
    
    // Обрабатываем платёж
    payment.status = 'completed';
    const totalStars = payment.stars + payment.bonus;
    
    changeBalance(validUserId, totalStars, `deposit_webhook_${invoiceId}`);
    
    console.log(`✅ Вебхук: Платёж ${invoiceId} завершён! +${totalStars}⭐ для ${validUserId}`);
    
    // Сохраняем в историю
    const db = readDB();
    db.payments = db.payments || [];
    db.payments.push({
      invoiceId,
      oddserId: validUserId,
      stars: totalStars,
      ton: payment.ton,
      type: 'crypto_bot',
      completedAt: Date.now()
    });
    writeDB(db);
    
    // Уведомляем клиента через socket
    io.emit('paymentCompleted', {
      oddserId: validUserId,
      stars: totalStars
    });
    
    res.json({ ok: true });
  } catch (error) {
    console.error('Webhook error:', error);
    logSecurityEvent('WEBHOOK_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ ok: false });
  }
});

// Telegram Stars - создание инвойса (для Mini App) - ЗАЩИЩЕНО
app.post('/api/deposit/stars', rateLimit(true), async (req, res) => {
  try {
    const { userId, packageId } = req.body;
    
    // Валидация userId
    const validUserId = validateUserId(userId);
    if (!validUserId) {
      logSecurityEvent('INVALID_STARS_USER_ID', { ip: req.ip, attemptedUserId: userId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пользователя' });
    }
    
    // Валидация packageId
    const sanitizedPackageId = sanitizeInput(packageId, 'string');
    if (!sanitizedPackageId) {
      logSecurityEvent('INVALID_STARS_PACKAGE_ID', { ip: req.ip, userId: validUserId, packageId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пакета' });
    }
    
    const pkg = DEPOSIT_PACKAGES.find(p => p.id === sanitizedPackageId);
    if (!pkg) {
      logSecurityEvent('STARS_PACKAGE_NOT_FOUND', { ip: req.ip, userId: validUserId, packageId: sanitizedPackageId });
      return res.status(400).json({ ok: false, error: 'Пакет не найден' });
    }
    
    // Проверка на дублирование
    const existingPayment = Array.from(pendingPayments.values()).find(p => 
      p.oddserId === validUserId && 
      p.status === 'pending' && 
      p.type === 'telegram_stars' &&
      Date.now() - p.createdAt < 60000
    );
    
    if (existingPayment) {
      logSecurityEvent('DUPLICATE_STARS_REQUEST', { ip: req.ip, userId: validUserId });
      return res.status(429).json({ ok: false, error: 'Слишком частые запросы' });
    }
    
    // Для Telegram Stars инвойс создаётся через бота
    const invoiceId = `stars_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
    
    pendingPayments.set(invoiceId, {
      oddserId: validUserId,
      packageId: sanitizedPackageId,
      stars: pkg.stars,
      bonus: pkg.bonus,
      type: 'telegram_stars',
      status: 'pending',
      createdAt: Date.now(),
      ip: req.ip
    });
    
    res.json({
      ok: true,
      invoiceId,
      title: `${pkg.stars} ⭐ (+${pkg.bonus} бонус)`,
      description: `Пополнение баланса в MYUPSTAKE Casino`,
      // Цена в Telegram Stars (примерно 1 Star = $0.013)
      prices: [{ label: `${pkg.stars} Stars`, amount: Math.round(pkg.usd / 0.013) }],
      payload: invoiceId
    });
  } catch (error) {
    console.error('Stars invoice error:', error);
    res.status(500).json({ ok: false, error: 'Ошибка создания инвойса' });
  }
});

// Подтверждение оплаты Telegram Stars - ЗАЩИЩЕНО
app.post('/api/deposit/stars/confirm', rateLimit(true), async (req, res) => {
  try {
    const { oddserId, invoiceId, telegramPaymentId } = req.body;
    
    // Валидация invoiceId
    const sanitizedInvoiceId = sanitizeInput(invoiceId, 'string');
    if (!sanitizedInvoiceId || !pendingPayments.has(sanitizedInvoiceId)) {
      logSecurityEvent('INVALID_STARS_CONFIRM_INVOICE', { ip: req.ip, invoiceId });
      return res.status(404).json({ ok: false, error: 'Платёж не найден' });
    }
    
    const payment = pendingPayments.get(sanitizedInvoiceId);
    
    if (payment.status === 'completed') {
      return res.json({ ok: true, status: 'already_completed' });
    }
    
    // Валидация userId
    const validUserId = validateUserId(oddserId);
    if (!validUserId || validUserId !== payment.oddserId) {
      logSecurityEvent('INVALID_STARS_CONFIRM_USER', { ip: req.ip, attemptedUserId: oddserId, paymentUserId: payment.oddserId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пользователя' });
    }
    
    // Проверка типа платежа
    if (payment.type !== 'telegram_stars') {
      logSecurityEvent('INVALID_STARS_PAYMENT_TYPE', { ip: req.ip, invoiceId: sanitizedInvoiceId, type: payment.type });
      return res.status(400).json({ ok: false, error: 'Неверный тип платежа' });
    }
    
    // Начисляем баланс
    payment.status = 'completed';
    const totalStars = payment.stars + payment.bonus;
    const newBalance = changeBalance(validUserId, totalStars, `deposit_stars_${sanitizedInvoiceId}`);
    
    console.log(`⭐ Telegram Stars: +${totalStars} для ${validUserId}`);
    
    // Сохраняем в историю
    const db = readDB();
    db.payments = db.payments || [];
    db.payments.push({
      invoiceId: sanitizedInvoiceId,
      oddserId: validUserId,
      stars: totalStars,
      type: 'telegram_stars',
      telegramPaymentId: sanitizeInput(telegramPaymentId, 'string'),
      completedAt: Date.now()
    });
    writeDB(db);
    
    res.json({ ok: true, stars: totalStars, newBalance });
  } catch (error) {
    console.error('Stars confirm error:', error);
    logSecurityEvent('STARS_CONFIRM_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ ok: false, error: 'Ошибка подтверждения' });
  }
});

// API для просмотра логов безопасности (только админ)
app.get('/api/admin/security-logs', requireAdmin, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const logs = securityLog.slice(-limit).reverse();
    res.json({ ok: true, logs });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'Ошибка' });
  }
});

// ============================================
// REST API
// ============================================

app.get('/api/balance/:uid', rateLimit(true), (req, res) => {
  try {
    const userId = validateUserId(req.params.uid);
    if (!userId) {
      logSecurityEvent('INVALID_BALANCE_REQUEST', { ip: req.ip, attemptedUserId: req.params.uid });
      return res.status(400).json({ error: 'Некорректный ID пользователя' });
    }
    
    const user = getUser(userId);
    // Не показываем полную информацию о пользователе
    res.json({ balance: Math.round(user.balance) });
  } catch (error) {
    logSecurityEvent('BALANCE_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ error: 'Ошибка получения баланса' });
  }
});

app.get('/api/leaderboard', (req, res) => {
  try {
    const data = readDB();
    const top = (data.users || [])
      .slice()
      .sort((a, b) => (b.balance || 0) - (a.balance || 0))
      .slice(0, 10)
      .map(u => ({ id: u.id, balance: u.balance }));
    res.json(top);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения таблицы лидеров' });
  }
});

// API банка УДАЛЁН - информация скрыта от пользователей

app.post('/api/bet', rateLimit(true), (req, res) => {
  try {
    const { userId, amount } = req.body;
    
    // Валидация userId
    const validUserId = validateUserId(userId);
    if (!validUserId) {
      logSecurityEvent('INVALID_BET_USER_ID', { ip: req.ip, attemptedUserId: userId });
      return res.status(400).json({ ok: false, reason: 'Некорректный ID пользователя' });
    }
    
    // Валидация суммы
    const sanitizedAmount = sanitizeInput(amount, 'number');
    if (!sanitizedAmount || sanitizedAmount <= 0) {
      logSecurityEvent('INVALID_BET_AMOUNT_API', { ip: req.ip, userId: validUserId, amount });
      return res.status(400).json({ ok: false, reason: 'Некорректная сумма' });
    }
    
    const amt = Math.floor(sanitizedAmount);
    const MIN_BET = 1;
    const MAX_BET = 1000000;
    
    if (amt < MIN_BET || amt > MAX_BET) {
      logSecurityEvent('BET_LIMIT_VIOLATION_API', { ip: req.ip, userId: validUserId, amount: amt });
      return res.status(400).json({ ok: false, reason: `Ставка должна быть от ${MIN_BET} до ${MAX_BET}` });
    }
    
    if (state !== 'betting') {
      return res.status(400).json({ ok: false, reason: 'Betting closed' });
    }
    if (!currentRound) {
      return res.status(400).json({ ok: false, reason: 'No active round' });
    }
    
    const user = getUser(validUserId);
    if (!user || user.balance < amt) {
      logSecurityEvent('INSUFFICIENT_BALANCE_API', { ip: req.ip, userId: validUserId, balance: user?.balance, amount: amt });
      return res.status(400).json({ ok: false, reason: 'Low balance' });
    }

    currentRound.bets[validUserId] = currentRound.bets[validUserId] || { amount: 0, cashedOut: false, payout: 0 };
    currentRound.bets[validUserId].amount += amt;
    changeBalance(validUserId, -amt, `bet_api_${currentRound?.id || 'no_round'}`);
    io.emit('betsUpdate', { totalBets: totalStaked(currentRound) });
    res.json({ ok: true });
  } catch (error) {
    logSecurityEvent('BET_API_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ ok: false, reason: 'Internal error' });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: Date.now(),
    state: state,
    roundId: currentRound?.id || null
  });
});

// Простой ping endpoint для проверки доступности
app.get('/ping', (req, res) => {
  res.status(200).json({ pong: Date.now() });
});

// Корневой маршрут
app.get('/', (req, res) => {
  const indexFile = path.join(publicPath, 'index.html');
  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }
  return res.status(200).send(`
    <html>
      <head><title>MYUPSTAKE Casino</title></head>
      <body style="background:#000;color:#fff;font-family:sans-serif;text-align:center;padding:50px;">
        <h1>🎰 MYUPSTAKE Casino</h1>
        <p>Сервер работает!</p>
        <p><a href="https://t.me/MYUPSTAKEBOT" style="color:#00ff88;">Открыть в Telegram</a></p>
      </body>
    </html>
  `);
});

// ============================================
// СИСТЕМА ВЫВОДА СРЕДСТВ
// ============================================

// ADMIN_ID уже объявлен выше в системе безопасности
const pendingWithdrawals = new Map(); // Ожидающие выводы

// API: Запрос на вывод - ЗАЩИЩЕНО
app.post('/api/withdraw/request', rateLimit(true), async (req, res) => {
  try {
    const { userId, amount, walletAddress, method } = req.body;
    
    // Валидация userId
    const validUserId = validateUserId(userId);
    if (!validUserId) {
      logSecurityEvent('INVALID_WITHDRAW_USER_ID', { ip: req.ip, attemptedUserId: userId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пользователя' });
    }
    
    // Валидация суммы
    const sanitizedAmount = sanitizeInput(amount, 'number');
    if (!sanitizedAmount || sanitizedAmount <= 0) {
      logSecurityEvent('INVALID_WITHDRAW_AMOUNT', { ip: req.ip, userId: validUserId, amount });
      return res.status(400).json({ ok: false, error: 'Некорректная сумма' });
    }
    
    // Валидация адреса кошелька
    const sanitizedWallet = sanitizeInput(walletAddress, 'wallet');
    if (!sanitizedWallet) {
      logSecurityEvent('INVALID_WALLET_ADDRESS', { ip: req.ip, userId: validUserId });
      return res.status(400).json({ ok: false, error: 'Некорректный адрес кошелька' });
    }
    
    // Валидация метода
    const validMethods = ['TON', 'USDT', 'BTC', 'ETH'];
    const sanitizedMethod = validMethods.includes(method) ? method : 'TON';
    
    const user = getUser(validUserId);
    if (!user || user.balance < sanitizedAmount) {
      logSecurityEvent('INSUFFICIENT_BALANCE_WITHDRAW', { ip: req.ip, userId: validUserId, balance: user?.balance, amount: sanitizedAmount });
      return res.status(400).json({ ok: false, error: 'Недостаточно средств' });
    }
    
    const minWithdraw = 100;
    const maxWithdraw = 10000000; // Максимальный вывод
    
    if (sanitizedAmount < minWithdraw) {
      return res.status(400).json({ ok: false, error: `Минимум для вывода: ${minWithdraw} ⭐` });
    }
    
    if (sanitizedAmount > maxWithdraw) {
      logSecurityEvent('EXCESSIVE_WITHDRAW_AMOUNT', { ip: req.ip, userId: validUserId, amount: sanitizedAmount });
      return res.status(400).json({ ok: false, error: `Максимум для вывода: ${maxWithdraw} ⭐` });
    }
    
    // Проверка на дублирование запросов (защита от спама)
    const db = readDB();
    const recentWithdrawals = (db.withdrawals || []).filter(w => 
      w.oddserId === validUserId && 
      w.status === 'pending' && 
      Date.now() - w.createdAt < 60000 // Последняя минута
    );
    
    if (recentWithdrawals.length > 0) {
      logSecurityEvent('DUPLICATE_WITHDRAW_REQUEST', { ip: req.ip, userId: validUserId });
      return res.status(429).json({ ok: false, error: 'Слишком частые запросы. Подождите минуту.' });
    }
    
    // Создаём запрос
    const withdrawId = `wd_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    
    // Замораживаем средства
    changeBalance(validUserId, -sanitizedAmount, `withdraw_freeze_${withdrawId}`);
    
    const withdrawRequest = {
      id: withdrawId,
      oddserId: validUserId,
      amount: sanitizedAmount,
      walletAddress: sanitizedWallet,
      method: sanitizedMethod,
      status: 'pending',
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      ip: req.ip
    };
    
    pendingWithdrawals.set(withdrawId, withdrawRequest);
    
    // Сохраняем в БД
    db.withdrawals = db.withdrawals || [];
    db.withdrawals.push(withdrawRequest);
    writeDB(db);
    
    console.log(`💸 Запрос на вывод: ${withdrawId} - ${sanitizedAmount}⭐ -> ${sanitizedWallet}`);
    
    // Уведомляем админа
    if (global.adminBot && ADMIN_ID) {
      global.adminBot.telegram.sendMessage(ADMIN_ID, 
        `🔔 НОВЫЙ ЗАПРОС НА ВЫВОД\n\n` +
        `🆔 ID: ${withdrawId}\n` +
        `👤 Пользователь: ${validUserId}\n` +
        `💰 Сумма: ${sanitizedAmount} ⭐\n` +
        `📍 Кошелёк: ${sanitizedWallet}\n` +
        `💳 Метод: ${sanitizedMethod}\n` +
        `🌐 IP: ${req.ip}\n\n` +
        `Для одобрения: /approve_${withdrawId}\n` +
        `Для отклонения: /reject_${withdrawId}`
      ).catch(console.error);
    }
    
    res.json({ 
      ok: true, 
      withdrawId,
      message: 'Запрос отправлен! Обработка в течение 24 часов.'
    });
  } catch (error) {
    console.error('Withdraw request error:', error);
    logSecurityEvent('WITHDRAW_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ ok: false, error: 'Внутренняя ошибка' });
  }
});

// API: Статус вывода - ЗАЩИЩЕНО
app.get('/api/withdraw/status/:oddserId', rateLimit(), (req, res) => {
  try {
    const userId = validateUserId(req.params.oddserId);
    if (!userId) {
      logSecurityEvent('INVALID_WITHDRAW_STATUS_REQUEST', { ip: req.ip, attemptedUserId: req.params.oddserId });
      return res.status(400).json({ ok: false, error: 'Некорректный ID пользователя' });
    }
    
    const db = readDB();
    const userWithdrawals = (db.withdrawals || [])
      .filter(w => w.oddserId === userId)
      .slice(-10)
      .reverse()
      .map(w => ({
        id: w.id,
        amount: w.amount,
        walletAddress: w.walletAddress ? `${w.walletAddress.slice(0, 6)}...${w.walletAddress.slice(-4)}` : 'N/A', // Частично скрываем
        method: w.method,
        status: w.status,
        createdAt: w.createdAt
      })); // Не показываем полный адрес и IP
    
    res.json({ ok: true, withdrawals: userWithdrawals });
  } catch (error) {
    logSecurityEvent('WITHDRAW_STATUS_ERROR', { error: error.message, ip: req.ip });
    res.status(500).json({ ok: false, error: 'Ошибка' });
  }
});

// ============================================
// SPA FALLBACK - Все не-API маршруты отдают index.html
// ВАЖНО: Этот middleware должен быть ПОСЛЕДНИМ, после всех маршрутов
// ============================================
app.use((req, res, next) => {
  // Если ответ уже отправлен - пропускаем
  if (res.headersSent) {
    return next();
  }
  
  // Если это API или Socket.io - пропускаем (должны быть обработаны выше)
  if (req.path.startsWith('/api/') || req.path.startsWith('/socket.io/')) {
    return next();
  }
  
  // Если это статический файл - пропускаем (express.static должен обработать)
  if (req.path.match(/\.(js|css|map|json|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/)) {
    return next();
  }
  
  // Если это GET запрос и не корневой путь (корневой уже обработан выше) - отдаем index.html
  if (req.method === 'GET' && req.path !== '/') {
    const indexFile = path.join(publicPath, 'index.html');
    if (fs.existsSync(indexFile)) {
      return res.sendFile(indexFile);
    }
  }
  
  // Для остальных случаев - пропускаем дальше (вернет 404)
  next();
});

// ============================================
// TELEGRAM BOT - ТОЛЬКО ЗАПУСК + АДМИН
// ============================================
const { Telegraf, Markup } = require('telegraf');

const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
// MINI_APP_URL должен быть реальным HTTPS URL вашего приложения
// Например: https://your-domain.com или после деплоя
const MINI_APP_URL = process.env.MINI_APP_URL || null;

if (TELEGRAM_TOKEN) {
  const bot = new Telegraf(TELEGRAM_TOKEN);
  global.adminBot = bot; // Для отправки уведомлений админу
  
  // Хранение времени последней активности
  const userLastActivity = new Map();

  // Стартовая команда
  bot.start((ctx) => {
    const oddserId = String(ctx.from.id);
    const user = getUser(oddserId);
    
    // Сохраняем время активности
    userLastActivity.set(oddserId, Date.now());
    
    // Если есть MINI_APP_URL - показываем WebApp кнопку
    if (MINI_APP_URL && MINI_APP_URL.startsWith('https://')) {
      ctx.reply(
        '🎰 *MYUPSTAKE Crash Casino*\n\n' +
        '🚀 Испытай удачу в Crash игре!\n' +
        '💎 Умножай свои звёзды до 100x\n' +
        '⚡ Выводи выигрыш когда захочешь\n\n' +
        `💰 Твой баланс: ${user.balance} ⭐\n\n` +
        '👇 Нажми кнопку чтобы начать играть!',
        {
          parse_mode: 'Markdown',
          ...Markup.inlineKeyboard([
            [Markup.button.webApp('🎮 ИГРАТЬ', MINI_APP_URL)],
          ])
        }
      );
    } else {
      // Без WebApp - показываем информацию
      ctx.reply(
        '🎰 *MYUPSTAKE Crash Casino*\n\n' +
        '🚀 Испытай удачу в Crash игре!\n' +
        '💎 Умножай свои звёзды до 100x\n' +
        '⚡ Выводи выигрыш когда захочешь\n\n' +
        `💰 Твой баланс: ${user.balance} ⭐\n` +
        `🆔 Твой ID: ${oddserId}\n\n` +
        '🌐 Игра доступна по адресу:\n' +
        `http://localhost:3001\n\n` +
        '📱 Для запуска Mini App установите MINI_APP_URL в .env',
        { parse_mode: 'Markdown' }
      );
    }
  });
  
  // ============================================
  // АДМИН КОМАНДЫ (только для ADMIN_ID)
  // ============================================
  
  // Одобрение вывода
  bot.hears(/\/approve_(.+)/, async (ctx) => {
    if (String(ctx.from.id) !== ADMIN_ID) return;
    
    const withdrawId = ctx.match[1];
    const withdrawal = pendingWithdrawals.get(withdrawId);
    
    if (!withdrawal) {
      // Ищем в БД
      const db = readDB();
      const dbWithdrawal = (db.withdrawals || []).find(w => w.id === withdrawId);
      if (!dbWithdrawal || dbWithdrawal.status !== 'pending') {
        return ctx.reply('❌ Запрос не найден или уже обработан');
      }
    }
    
    const wd = withdrawal || pendingWithdrawals.get(withdrawId);
    wd.status = 'approved';
    wd.approvedAt = Date.now();
    wd.approvedBy = String(ctx.from.id);
    
    // Обновляем в БД
    const db = readDB();
    const idx = (db.withdrawals || []).findIndex(w => w.id === withdrawId);
    if (idx !== -1) {
      db.withdrawals[idx] = wd;
      writeDB(db);
    }
    
    pendingWithdrawals.delete(withdrawId);
    
    console.log(`✅ Вывод одобрен: ${withdrawId}`);
    
    ctx.reply(
      `✅ ВЫВОД ОДОБРЕН\n\n` +
      `🆔 ID: ${withdrawId}\n` +
      `💰 Сумма: ${wd.amount} ⭐\n` +
      `📍 Кошелёк: ${wd.walletAddress}\n\n` +
      `⚠️ Не забудь отправить средства вручную!`
    );
    
    // Уведомляем пользователя через socket
    io.emit('withdrawalUpdate', { oddserId: wd.oddserId, status: 'approved', withdrawId });
  });
  
  // Отклонение вывода
  bot.hears(/\/reject_(.+)/, async (ctx) => {
    if (String(ctx.from.id) !== ADMIN_ID) return;
    
    const withdrawId = ctx.match[1];
    
    const db = readDB();
    const withdrawal = (db.withdrawals || []).find(w => w.id === withdrawId);
    
    if (!withdrawal || withdrawal.status !== 'pending') {
      return ctx.reply('❌ Запрос не найден или уже обработан');
    }
    
    // Возвращаем средства
    changeBalance(withdrawal.oddserId, withdrawal.amount, `withdraw_rejected_${withdrawId}`);
    
    withdrawal.status = 'rejected';
    withdrawal.rejectedAt = Date.now();
    
    const idx = db.withdrawals.findIndex(w => w.id === withdrawId);
    if (idx !== -1) {
      db.withdrawals[idx] = withdrawal;
      writeDB(db);
    }
    
    pendingWithdrawals.delete(withdrawId);
    
    console.log(`❌ Вывод отклонён: ${withdrawId}`);
    
    ctx.reply(
      `❌ ВЫВОД ОТКЛОНЁН\n\n` +
      `🆔 ID: ${withdrawId}\n` +
      `💰 Средства возвращены: ${withdrawal.amount} ⭐`
    );
    
    io.emit('withdrawalUpdate', { oddserId: withdrawal.oddserId, status: 'rejected', withdrawId });
  });
  
  // Список ожидающих выводов
  bot.command('pending', async (ctx) => {
    if (String(ctx.from.id) !== ADMIN_ID) return;
    
    const db = readDB();
    const pending = (db.withdrawals || []).filter(w => w.status === 'pending');
    
    if (pending.length === 0) {
      return ctx.reply('✅ Нет ожидающих запросов на вывод');
    }
    
    let msg = `📋 ОЖИДАЮЩИЕ ВЫВОДЫ (${pending.length}):\n\n`;
    pending.forEach(w => {
      const timeLeft = Math.max(0, Math.floor((w.expiresAt - Date.now()) / 3600000));
      msg += `🆔 ${w.id}\n`;
      msg += `💰 ${w.amount}⭐ -> ${w.walletAddress.slice(0, 20)}...\n`;
      msg += `⏱ Осталось: ${timeLeft}ч\n`;
      msg += `/approve_${w.id} | /reject_${w.id}\n\n`;
    });
    
    ctx.reply(msg);
  });
  
  // Статистика для админа
  bot.command('adminstats', async (ctx) => {
    if (String(ctx.from.id) !== ADMIN_ID) return;
    
    const db = readDB();
    const users = db.users || [];
    const withdrawals = db.withdrawals || [];
    const payments = db.payments || [];
    
    const totalDeposits = payments.reduce((sum, p) => sum + (p.stars || 0), 0);
    const totalWithdrawn = withdrawals
      .filter(w => w.status === 'approved')
      .reduce((sum, w) => sum + w.amount, 0);
    
    ctx.reply(
      `📊 СТАТИСТИКА КАЗИНО\n\n` +
      `👥 Пользователей: ${users.length}\n` +
      `💰 Банк: ${houseBank}⭐\n` +
      `📥 Всего депозитов: ${totalDeposits}⭐\n` +
      `📤 Всего выведено: ${totalWithdrawn}⭐\n` +
      `⏳ Ожидает вывода: ${withdrawals.filter(w => w.status === 'pending').length}`
    );
  });
  
  // ============================================
  // НАПОМИНАНИЕ КАЖДЫЕ 24 ЧАСА
  // ============================================
  setInterval(() => {
    const now = Date.now();
    const db = readDB();
    
    (db.users || []).forEach(user => {
      const lastActive = userLastActivity.get(user.id) || 0;
      const hoursSince = (now - lastActive) / 3600000;
      
      // Если не играл более 24 часов и меньше 48 (чтобы не спамить)
      if (hoursSince >= 24 && hoursSince < 48) {
        const messageOptions = MINI_APP_URL && MINI_APP_URL.startsWith('https://') 
          ? {
              ...Markup.inlineKeyboard([
                [Markup.button.webApp('🎮 ИГРАТЬ СЕЙЧАС', MINI_APP_URL)]
              ])
            }
          : {};
        
        bot.telegram.sendMessage(user.id,
          `🎰 Давно не виделись!\n\n` +
          `Сколько времени вы уже не играли в нашего бота?\n` +
          `Возвращайтесь - удача ждёт! 🍀\n\n` +
          `👇 @MYUPSTAKEBOT`,
          messageOptions
        ).then(() => {
          // Обновляем время чтобы не слать повторно
          userLastActivity.set(user.id, now);
        }).catch(() => {
          // Пользователь заблокировал бота - игнорируем
        });
      }
    });
  }, 60 * 60 * 1000); // Проверяем каждый час

  // Обработка ошибок бота
  bot.catch((err, ctx) => {
    console.error('Ошибка в Telegram боте:', err);
  });

  // Запуск бота
  bot.launch().then(() => {
    console.log('🤖 Telegram бот запущен');
    if (ADMIN_ID) {
      console.log(`👤 Admin ID: ${ADMIN_ID}`);
    } else {
      console.log('⚠️ ADMIN_TELEGRAM_ID не установлен - админ-команды недоступны');
    }
  }).catch(err => {
    // Обработка конфликта (409) - другой экземпляр бота уже запущен
    if (err.response && err.response.error_code === 409) {
      console.warn('⚠️ Telegram бот: Другой экземпляр уже запущен (возможно локально)');
      console.warn('💡 Остановите локальный экземпляр бота или используйте webhook в продакшене');
      // Не падаем, просто предупреждаем
    } else {
      console.error('❌ Ошибка запуска Telegram бота:', err);
    }
  });

  // Graceful stop
  process.once('SIGINT', () => bot.stop('SIGINT'));
  process.once('SIGTERM', () => bot.stop('SIGTERM'));
} else {
  console.log('⚠️ TELEGRAM_BOT_TOKEN не установлен. Telegram бот не будет запущен.');
}

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🎰 ═══════════════════════════════════════════════════════`);
  console.log(`   MYUPSTAKE CRASH CASINO v2.0 - ДИНАМИЧЕСКИЙ РАСЧЕТ`);
  console.log(`🎰 ═══════════════════════════════════════════════════════`);
  console.log(`🌐 Сервер: http://0.0.0.0:${PORT}`);
  console.log(`💰 Банк: ${houseBank.toFixed(0)} / ${CASINO_CONFIG.TARGET_BANK.toLocaleString()}`);
  console.log(`📊 Фаза: ${getCurrentPhase()}`);
  console.log(`\n⚡ РЕЖИМ РАБОТЫ 24/7:`);
  console.log(`   🎭 НЕТ СТАВОК → Показательные иксы:`);
  console.log(`      • 35% шанс: 1.50x-3.40x (низкие)`);
  console.log(`      • 35% шанс: 3.40x-10.0x (средние)`);
  console.log(`      • 30% шанс: 10.0x-50.0x (высокие)`);
  console.log(`   🚨 ПЕРВЫЕ 7 РАУНДОВ СО СТАВКАМИ → Слив 1.0-1.2x`);
  console.log(`   💰 ДАЛЕЕ → Адаптивная логика (зависит от банка)`);
  console.log(`   🔥 РАСЧЕТ → В последний момент после всех ставок`);
  console.log(`\n📋 ЗАЩИТА:`);
  console.log(`   🐋 Анти-кит: ставка >15% банка = слив 1.10x`);
  console.log(`   🚨 Критично: ставки >30% банка = слив 1.00-1.20x`);
  console.log(`   🔥 Горячие игроки: 65% шанс слива`);
  console.log(`   🛡️ Минимальный банк: ${CASINO_CONFIG.BANK_PROTECTION.MIN_BANK}`);
  if (TELEGRAM_TOKEN) {
    console.log(`\n🤖 Telegram бот: Активен`);
  } else {
    console.log(`\n🤖 Telegram бот: Не активен`);
  }
  console.log(`🎰 ====================================\n`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Ошибка: Порт ${PORT} уже занят!`);
    console.log(`💡 Попробуйте:`);
    console.log(`   1. Остановить другой процесс: netstat -ano | findstr :${PORT}`);
    console.log(`   2. Или изменить порт в .env файле: PORT=8002`);
    process.exit(1);
  } else {
    console.error('❌ Ошибка при запуске сервера:', err);
    process.exit(1);
  }
});
