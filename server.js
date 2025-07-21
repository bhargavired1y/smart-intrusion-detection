const express = require('express');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const useragent = require('useragent');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
app.set('trust proxy', 1); // trust first proxy
const PORT = 3000;

// Config
const LOG_FILE = path.join(__dirname, 'logs', 'login_attempts.json');
const MAX_FAILED_ATTEMPTS = 5;
const BLOCK_TIME_MINUTES = 30;

// Ensure logs directory exists
const LOG_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR);
}

// In-memory store for failed attempts and blocked IPs
const failedAttempts = {};
const blockedIPs = {};

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Rate limiter (basic protection)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 requests per minute
});
app.use(limiter);

// Helper: Load logs
function loadLogs() {
  if (!fs.existsSync(LOG_FILE)) return [];
  const data = fs.readFileSync(LOG_FILE, 'utf8');
  try {
    return JSON.parse(data);
  } catch {
    return [];
  }
}

// Helper: Save logs
function saveLog(entry) {
  const logs = loadLogs();
  logs.push(entry);
  fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
}

// Helper: Get IP address
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',').shift() ||
    req.socket?.remoteAddress ||
    null
  );
}

// Helper: Geo-IP lookup
async function getGeoInfo(ip) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await res.json();
    return {
      country: data.country || 'Unknown',
      city: data.city || 'Unknown',
      region: data.regionName || 'Unknown',
    };
  } catch {
    return { country: 'Unknown', city: 'Unknown', region: 'Unknown' };
  }
}

// Helper: Risk scoring
function getRiskScore({ geoMismatch, blocked, failedCount }) {
  let score = 0;
  if (geoMismatch) score += 5;
  if (blocked) score += 10;
  if (failedCount >= MAX_FAILED_ATTEMPTS) score += 10;
  return score;
}

// Helper: Check if IP is blocked
function isBlocked(ip) {
  if (!blockedIPs[ip]) return false;
  const blockTime = blockedIPs[ip];
  if (Date.now() - blockTime > BLOCK_TIME_MINUTES * 60 * 1000) {
    delete blockedIPs[ip];
    failedAttempts[ip] = 0;
    return false;
  }
  return true;
}

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = getIP(req);
  const userAgent = req.headers['user-agent'];
  const agent = useragent.parse(userAgent);
  const browser = `${agent.family} ${agent.major}`;
  const timestamp = new Date().toISOString();

  // Blocked IP check
  if (isBlocked(ip)) {
    saveLog({
      username,
      ip,
      timestamp,
      browser,
      geo: {},
      success: false,
      reason: 'Blocked IP',
      risk: 10,
    });
    return res.json({ success: false, message: 'Your IP is temporarily blocked due to suspicious activity.' });
  }

  // Geo-IP lookup
  const geo = await getGeoInfo(ip);

  // For demo: hardcoded user
  const validUser = { username: 'admin', password: 'password123', lastCountry: 'India' };

  // Check geo mismatch (for demo, compare to validUser.lastCountry)
  const geoMismatch = geo.country !== validUser.lastCountry;

  // Check credentials
  let success = username === validUser.username && password === validUser.password;

  // Track failed attempts
  if (!failedAttempts[ip]) failedAttempts[ip] = 0;
  if (!success) {
    failedAttempts[ip]++;
    if (failedAttempts[ip] >= MAX_FAILED_ATTEMPTS) {
      blockedIPs[ip] = Date.now();
    }
  } else {
    failedAttempts[ip] = 0; // reset on success
  }

  // Risk scoring
  const risk = getRiskScore({
    geoMismatch,
    blocked: isBlocked(ip),
    failedCount: failedAttempts[ip],
  });

  // Log the attempt
  saveLog({
    username,
    ip,
    timestamp,
    browser,
    geo,
    success,
    reason: success ? (geoMismatch ? 'Geo-IP mismatch' : 'Login OK') : 'Invalid credentials',
    risk,
  });

  // Respond
  if (success) {
    let msg = 'Login successful!';
    if (geoMismatch) msg += ' (Unusual location detected)';
    return res.json({ success: true, message: msg });
  } else if (isBlocked(ip)) {
    return res.json({ success: false, message: 'Too many failed attempts. Your IP is temporarily blocked.' });
  } else {
    return res.json({ success: false, message: 'Invalid username or password.' });
  }
});

// GET /logs (review logs)
app.get('/logs', (req, res) => {
  const logs = loadLogs();
  res.json(logs);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
