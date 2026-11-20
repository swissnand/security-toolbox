// Infosphera Security Toolbox — Electron-Hauptprozess
// Fenster, Menü und drei bewusst eng begrenzte Dienste für die Oberfläche:
//   net:get / net:probe   HTTP(S)-GET auf öffentliche Adressen (passiv, ohne Cookies)
//   net:tls-versions      welche TLS-Versionen ein Server akzeptiert
//   mac:audit             lesende Systemabfragen für den macOS-Härtungscheck
const { app, BrowserWindow, Menu, shell, nativeTheme, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const https = require('https');
const tls = require('tls');
const { isIP } = require('net');
const { execFile } = require('child_process');

const UA = 'InfospheraSecurityToolbox/' + app.getVersion() + ' (+https://infosphera.swissnand.com)';
let win;

function createWindow() {
  win = new BrowserWindow({
    width: 1340,
    height: 880,
    minWidth: 920,
    minHeight: 620,
    title: 'Infosphera Security Toolbox',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 18, y: 18 },
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0B1220' : '#f4f5f8',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  win.loadFile(path.join(__dirname, 'src', 'index.html'));
  win.once('ready-to-show', () => win.show());

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith('file://')) { e.preventDefault(); if (/^https?:/.test(url)) shell.openExternal(url); }
  });
}

/* ---------- HTTP(S) ---------- */
function checkUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Ungültige Adresse'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Nur http und https sind erlaubt');
  return u;
}

function certInfo(c) {
  if (!c || !c.subject) return null;
  return {
    subject: c.subject, issuer: c.issuer, subjectaltname: c.subjectaltname || '',
    valid_from: c.valid_from, valid_to: c.valid_to, serialNumber: c.serialNumber,
    fingerprint256: c.fingerprint256, bits: c.bits || null, asn1Curve: c.asn1Curve || null,
    nistCurve: c.nistCurve || null, pubkeyType: c.pubkey ? (c.asn1Curve ? 'EC' : 'RSA') : null,
    issuerCert: c.issuerCertificate && c.issuerCertificate !== c ? { subject: c.issuerCertificate.subject, issuer: c.issuerCertificate.issuer, valid_to: c.issuerCertificate.valid_to } : null,
  };
}

function requestOnce(u, { maxBytes, timeout }) {
  return new Promise((resolve, reject) => {
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, {
      method: 'GET',
      headers: { 'user-agent': UA, accept: '*/*', 'accept-language': 'de-CH,de;q=0.9,en;q=0.6' },
      timeout,
      rejectUnauthorized: false, // Zertifikat trotzdem lesen und Fehler selbst melden
      servername: isIP(u.hostname) ? undefined : u.hostname,
    }, (res) => {
      const sock = res.socket;
      let tlsInfo = null;
      if (u.protocol === 'https:' && sock && sock.getPeerCertificate) {
        tlsInfo = {
          protocol: sock.getProtocol ? sock.getProtocol() : null,
          cipher: sock.getCipher ? sock.getCipher() : null,
          authorized: sock.authorized,
          authError: sock.authorizationError ? String(sock.authorizationError) : null,
          cert: certInfo(sock.getPeerCertificate(true)),
        };
      }
      const chunks = []; let size = 0; let truncated = false;
      res.on('data', (d) => {
        if (size >= maxBytes) { truncated = true; res.destroy(); return; }
        chunks.push(d); size += d.length;
      });
      const done = () => resolve({
        status: res.statusCode, statusText: res.statusMessage, headers: res.headers,
        rawHeaders: res.rawHeaders, body: Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8'),
        truncated, tls: tlsInfo, remoteAddress: sock && sock.remoteAddress,
      });
      res.on('end', done);
      res.on('close', done);
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Zeitüberschreitung')));
    req.on('error', (e) => reject(new Error(e.code === 'ENOTFOUND' ? 'Domain nicht gefunden' : e.code === 'ECONNREFUSED' ? 'Verbindung abgelehnt' : e.message)));
    req.end();
  });
}

async function fetchFollow(raw, opts = {}) {
  const maxBytes = Math.min(opts.maxBytes || 512 * 1024, 4 * 1024 * 1024);
  const timeout = Math.min(opts.timeout || 12000, 30000);
  const follow = opts.follow !== false;
  let u = checkUrl(raw);
  const chain = [];
  for (let i = 0; i < 8; i++) {
    const r = await requestOnce(u, { maxBytes, timeout });
    chain.push({ url: u.href, status: r.status, location: r.headers.location || null, tls: r.tls ? { protocol: r.tls.protocol, authorized: r.tls.authorized } : null });
    if (follow && r.status >= 300 && r.status < 400 && r.headers.location) {
      u = checkUrl(new URL(r.headers.location, u).href);
      continue;
    }
    // JSON-Roundtrip: Zertifikatsobjekte ohne Prototyp sicher über IPC übertragen
    return JSON.parse(JSON.stringify({ ...r, url: u.href, chain }));
  }
  throw new Error('Zu viele Weiterleitungen');
}

ipcMain.handle('net:get', (e, url, opts) => fetchFollow(url, opts));
ipcMain.handle('net:probe', (e, url, opts) => fetchFollow(url, { ...opts, maxBytes: 256 * 1024 }));

/* ---------- TLS-Versionen ---------- */
// Electron nutzt BoringSSL: keine OpenSSL-Cipher-Strings, alte Versionen aber weiterhin aushandelbar
function tryTls(host, port, version) {
  return new Promise((resolve) => {
    let sock;
    try {
      sock = tls.connect({
        host, port, servername: isIP(host) ? undefined : host, minVersion: version, maxVersion: version,
        rejectUnauthorized: false, timeout: 7000,
      }, () => { const p = sock.getProtocol(); const c = sock.getCipher(); sock.end(); resolve({ version, ok: p === version, cipher: c && c.name }); });
    } catch (err) { resolve({ version, ok: false, error: err.code || err.message }); return; }
    sock.on('error', (err) => resolve({ version, ok: false, error: err.code || err.message }));
    sock.on('timeout', () => { sock.destroy(); resolve({ version, ok: false, error: 'Zeitüberschreitung' }); });
  });
}
ipcMain.handle('net:tls-versions', async (e, host, port) => {
  if (!/^[a-z0-9.-]+$/i.test(String(host))) throw new Error('Ungültiger Host');
  const versions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
  return Promise.all(versions.map((v) => tryTls(host, Number(port) || 443, v)));
});

/* ---------- macOS-Härtungscheck (nur lesend) ---------- */
const run = (cmd, args) => new Promise((resolve) => {
  execFile(cmd, args, { timeout: 10000, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec' } }, (err, stdout, stderr) => {
    resolve({ ok: !err, out: String(stdout || '').trim(), err: String(stderr || '').trim(), code: err ? err.code : 0 });
  });
});
ipcMain.handle('mac:audit', async () => {
  if (process.platform !== 'darwin') return { platform: process.platform, results: {} };
  const checks = {
    swVers: ['/usr/bin/sw_vers', []],
    filevault: ['/usr/bin/fdesetup', ['status']],
    firewall: ['/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']],
    stealth: ['/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getstealthmode']],
    gatekeeper: ['/usr/sbin/spctl', ['--status']],
    sip: ['/usr/bin/csrutil', ['status']],
    autoCheck: ['/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticCheckEnabled']],
    autoDownload: ['/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticDownload']],
    autoMacOS: ['/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticallyInstallMacOSUpdates']],
    critical: ['/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'CriticalUpdateInstall']],
    guest: ['/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'GuestEnabled']],
    autoLogin: ['/usr/bin/defaults', ['read', '/Library/Preferences/com.apple.loginwindow', 'autoLoginUser']],
    screenLock: ['/usr/sbin/sysadminctl', ['-screenLock', 'status']],
    sshd: ['/bin/launchctl', ['print-disabled', 'system']],
    sharing: ['/usr/bin/pgrep', ['-x', 'ARDAgent']],
    smb: ['/usr/bin/pgrep', ['-x', 'smbd']],
  };
  const entries = await Promise.all(Object.entries(checks).map(async ([k, [c, a]]) => [k, await run(c, a)]));
  return { platform: 'darwin', arch: process.arch, results: Object.fromEntries(entries) };
});

/* ---------- Menü ---------- */
function buildMenu() {
  const isMac = process.platform === 'darwin';
  const js = (code) => () => win && win.webContents.executeJavaScript(code);
  const template = [
    ...(isMac ? [{ role: 'appMenu', label: app.name }] : []),
    { role: 'editMenu', label: 'Bearbeiten' },
    {
      label: 'Ansicht',
      submenu: [
        { label: 'Tool suchen …', accelerator: 'CmdOrCtrl+K', click: js("window.dispatchEvent(new Event('is:search'))") },
        { label: 'Übersicht', accelerator: 'CmdOrCtrl+0', click: js("location.hash='#/'") },
        { type: 'separator' },
        { label: 'Notfallkarte', accelerator: 'CmdOrCtrl+Shift+N', click: js("location.hash='#/tool/notfallkarte'") },
        { label: 'Incident Playbooks', accelerator: 'CmdOrCtrl+Shift+P', click: js("location.hash='#/tool/playbooks'") },
        { type: 'separator' },
        { role: 'reload', label: 'Neu laden' },
        { role: 'toggleDevTools', label: 'Entwicklertools' },
        { type: 'separator' },
        { role: 'resetZoom', label: 'Originalgrösse' },
        { role: 'zoomIn', label: 'Vergrössern' },
        { role: 'zoomOut', label: 'Verkleinern' },
        { type: 'separator' },
        { role: 'togglefullscreen', label: 'Vollbild' },
      ],
    },
    { role: 'windowMenu', label: 'Fenster' },
    {
      role: 'help',
      label: 'Hilfe',
      submenu: [
        { label: 'Infosphera', click: () => shell.openExternal('https://infosphera.swissnand.com') },
        { label: 'Projekt auf GitHub', click: () => shell.openExternal('https://github.com/swissnand/security-toolbox') },
        { label: 'Fehler melden', click: () => shell.openExternal('https://github.com/swissnand/security-toolbox/issues') },
        { type: 'separator' },
        { label: 'BACS: Cyberangriff melden', click: () => shell.openExternal('https://www.ncsc.admin.ch/ncsc/de/home/meldepflicht/meldepflicht-info.html') },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(() => {
  buildMenu();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// Kein Nachladen fremder Inhalte in neue Fenster
app.on('web-contents-created', (e, contents) => {
  contents.on('will-attach-webview', (ev) => ev.preventDefault());
});
