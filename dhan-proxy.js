// save as dhan-proxy.js, then run: node dhan-proxy.js
// Relays BOTH Dhan (default) and Yahoo Finance (paths starting with /yahoo/*) requests.
// Can automatically inject Owner credentials if subscribers do not enter their own.
// Automatically self-heals by renewing tokens daily if they expire.
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load environment variables from .env or .env.txt if they exist
const envPath = path.join(__dirname, '.env');
const envFallbackPath = path.join(__dirname, '.env.txt');
const activeEnvPath = fs.existsSync(envPath) ? envPath : (fs.existsSync(envFallbackPath) ? envFallbackPath : null);

if (activeEnvPath) {
  const content = fs.readFileSync(activeEnvPath, 'utf8');
  content.split('\n').forEach(line => {
    const parts = line.match(/^\s*([\w\.\-]+)\s*=\s*(.*)?\s*$/);
    if (parts) {
      const key = parts[1];
      let value = parts[2] || '';
      if (value.length > 0 && value[0] === '"' && value[value.length - 1] === '"') {
        value = value.substring(1, value.length - 1);
      }
      process.env[key] = value.trim();
    }
  });
}

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'access-control-allow-headers': '*'
};

// Base32 Decoder for TOTP Secret
function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let clean = base32.toUpperCase().replace(/[\s=]/g, '');
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) throw new Error('Invalid base32 character: ' + clean[i]);
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    if (i + 8 <= bits.length) {
      bytes.push(parseInt(bits.substr(i, 8), 2));
    }
  }
  return Buffer.from(bytes);
}

// Native TOTP Code Generator
function generateTOTP(secret) {
  const key = base32Decode(secret);
  const epoch = Math.floor(Date.now() / 30000);
  const timeBuf = Buffer.alloc(8);
  timeBuf.writeUInt32BE(Math.floor(epoch / 0x100000000), 0);
  timeBuf.writeUInt32BE(epoch % 0x100000000, 4);

  const hmac = crypto.createHmac('sha1', key);
  hmac.update(timeBuf);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);

  return String(binary % 1000000).padStart(6, '0');
}

// Owner in-memory caching token
let cachedOwnerToken = '';

async function getOrRenewOwnerToken(forceRenew = false) {
  const clientId = process.env.DHAN_CLIENT_ID || '';
  const pin = process.env.DHAN_PIN || '';
  const secret = process.env.DHAN_TOTP_SECRET || '';

  if (!clientId || !pin || !secret) {
    return null; // Owner credentials are not configured on server env
  }

  if (cachedOwnerToken && !forceRenew) {
    return { token: cachedOwnerToken, clientId };
  }

  return new Promise((resolve, reject) => {
    try {
      console.log('Generating fresh owner Dhan Access Token via backend auto-login...');
      const totp = generateTOTP(secret);
      const authPath = `/app/generateAccessToken?dhanClientId=${clientId}&pin=${pin}&totp=${totp}`;

      const authReq = https.request({
        hostname: 'auth.dhan.co',
        path: authPath,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': 0 }
      }, (authRes) => {
        const chunks = [];
        authRes.on('data', c => chunks.push(c));
        authRes.on('end', () => {
          try {
            const resObj = JSON.parse(Buffer.concat(chunks).toString());
            if (resObj.accessToken) {
              cachedOwnerToken = resObj.accessToken;
              console.log('Owner Access Token successfully generated/renewed!');
              resolve({ token: cachedOwnerToken, clientId });
            } else {
              const errMsg = resObj.errorMessage || resObj.remarks || resObj.message || ('No token in auth response. Response: ' + JSON.stringify(resObj));
              reject(new Error(errMsg));
            }
          } catch (e) {
            reject(new Error('JSON parse failed: ' + e.message));
          }
        });
      });

      authReq.on('error', (e) => reject(e));
      authReq.end();
    } catch (err) {
      reject(err);
    }
  });
}

http.createServer((req, res) => {
  if (req.url === '/ping') {
    res.writeHead(200, { ...CORS_HEADERS, 'content-type': 'text/plain' });
    return res.end('ok');
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    return res.end();
  }

  // Intercept Auto Token Renew Endpoint (Frontend-driven)
  if (req.url === '/auth/generateToken' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const { dhanClientId, pin, totpSecret } = body;
        
        if (!dhanClientId || !pin || !totpSecret) {
          res.writeHead(400, { ...CORS_HEADERS, 'content-type': 'application/json' });
          return res.end(JSON.stringify({ errorMessage: 'dhanClientId, pin, and totpSecret are required.' }));
        }

        const totp = generateTOTP(totpSecret);
        const authPath = `/app/generateAccessToken?dhanClientId=${dhanClientId}&pin=${pin}&totp=${totp}`;
        
        const authReq = https.request({
          hostname: 'auth.dhan.co',
          path: authPath,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': 0 }
        }, (authRes) => {
          const authChunks = [];
          authRes.on('data', c => authChunks.push(c));
          authRes.on('end', () => {
            const authBody = Buffer.concat(authChunks);
            res.writeHead(authRes.statusCode, { ...CORS_HEADERS, 'content-type': 'application/json' });
            res.end(authBody);
          });
        });

        authReq.on('error', e => {
          res.writeHead(502, { ...CORS_HEADERS, 'content-type': 'application/json' });
          res.end(JSON.stringify({ errorMessage: 'Failed to contact auth.dhan.co: ' + e.message }));
        });
        authReq.end();
      } catch (err) {
        res.writeHead(500, { ...CORS_HEADERS, 'content-type': 'application/json' });
        res.end(JSON.stringify({ errorMessage: 'Auto-Token Renew Error: ' + err.message }));
      }
    });
    return;
  }

  // Intercept Feedback Relay Endpoint
  if (req.url === '/feedback' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const { email, rating, comments } = body;
        
        const tgToken = process.env.TELEGRAM_BOT_TOKEN || '';
        const tgChatId = process.env.TELEGRAM_CHAT_ID || '';
        
        if (tgToken && tgChatId) {
          const starEmoji = '⭐'.repeat(rating || 5);
          const tgMessage = `✍ *New OptionPulse Feedback Submission*\n\n` +
                            `• *User Email:* ${email}\n` +
                            `• *Rating:* ${starEmoji} (${rating}/5)\n\n` +
                            `• *Comments:* "${comments}"`;
                            
          const url = `https://api.telegram.org/bot${tgToken}/sendMessage`;
          const upReq = https.request(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          }, (upRes) => {
            res.writeHead(200, { ...CORS_HEADERS, 'content-type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
          });
          upReq.on('error', e => {
            res.writeHead(502, CORS_HEADERS);
            res.end(JSON.stringify({ success: false, error: e.message }));
          });
          upReq.write(JSON.stringify({
            chat_id: tgChatId,
            text: tgMessage,
            parse_mode: 'Markdown'
          }));
          upReq.end();
        } else {
          res.writeHead(200, { ...CORS_HEADERS, 'content-type': 'application/json' });
          res.end(JSON.stringify({ success: true, warning: 'Telegram credentials missing on proxy server.' }));
        }
      } catch (err) {
        res.writeHead(500, { ...CORS_HEADERS, 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // Forward standard Dhan / Yahoo Finance API Requests
  const isYahoo = req.url.startsWith('/yahoo/');
  const upstreamHost = isYahoo ? 'query1.finance.yahoo.com' : 'api.dhan.co';
  const upstreamPath = isYahoo ? req.url.replace(/^\/yahoo/, '') : req.url;

  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const body = Buffer.concat(chunks);
    
    let clientToken = req.headers['access-token'] || '';
    let clientId = req.headers['client-id'] || '';

    // If client credentials are blank and this is a Dhan request, try injecting Owner's credentials
    if (!isYahoo && (!clientToken || !clientId)) {
      try {
        const ownerCreds = await getOrRenewOwnerToken();
        if (ownerCreds) {
          clientToken = ownerCreds.token;
          clientId = ownerCreds.clientId;
        }
      } catch (err) {
        console.error('Auto-inject owner credentials failed:', err.message);
      }
    }

    const headers = isYahoo
      ? { 'user-agent': 'Mozilla/5.0' }
      : {
          'content-type': 'application/json',
          'access-token': clientToken,
          'client-id': clientId,
          'content-length': Buffer.byteLength(body)
        };

    const makeRequest = (isRetry = false) => {
      const upstreamReq = https.request({
        hostname: upstreamHost,
        path: upstreamPath,
        method: req.method,
        headers
      }, (upRes) => {
        // If unauthorized and we used cached owner credentials, auto-renew on backend and retry once
        if (!isYahoo && upRes.statusCode === 401 && !isRetry && (process.env.DHAN_CLIENT_ID)) {
          console.warn('Dhan returned 401 Unauthorized. Retrying with fresh owner token...');
          getOrRenewOwnerToken(true)
            .then(ownerCreds => {
              if (ownerCreds) {
                headers['access-token'] = ownerCreds.token;
                headers['client-id'] = ownerCreds.clientId;
                makeRequest(true); // retry request
              } else {
                pipeResponseDirectly(upRes);
              }
            })
            .catch(() => {
              pipeResponseDirectly(upRes);
            });
          return;
        }
        pipeResponseDirectly(upRes);
      });

      upstreamReq.on('error', e => {
        res.writeHead(502, CORS_HEADERS);
        res.end(JSON.stringify({ errorMessage: 'Proxy could not reach ' + upstreamHost + ': ' + e.message }));
      });

      if (body.length) upstreamReq.write(body);
      upstreamReq.end();
    };

    const pipeResponseDirectly = (upRes) => {
      const resHeaders = { ...upRes.headers, ...CORS_HEADERS };
      delete resHeaders['content-encoding'];
      res.writeHead(upRes.statusCode, resHeaders);
      upRes.pipe(res);
    };

    makeRequest();
  });
}).listen(process.env.PORT || 8787, () => console.log('Dhan/Yahoo proxy running - ready for cloud hosting'));