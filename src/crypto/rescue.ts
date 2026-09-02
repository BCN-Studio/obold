import { randomBytes, createCipheriv, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { ShamirSecretSharing } from './shamir.ts';

export interface RescueBundleOptions {
  payload: string | Buffer;
  totalShares?: number;
  threshold?: number;
  title?: string;
  instructions?: string;
  filename?: string;
}

export interface RescueBundleManifest {
  version: string;
  bundleId: string;
  createdAt: string;
  title: string;
  threshold: number;
  totalShares: number;
  cipherSha256: string;
  appSha256: string;
  iv: string;
  filename: string;
}

export interface RescueBundleResult {
  html: string;
  shares: string[];
  totalShares: number;
  threshold: number;
  manifest: RescueBundleManifest;
}

export function sanitizeRescueFilename(filename?: string): string {
  if (!filename || typeof filename !== 'string') return 'decrypted_vault.txt';
  const clean = filename.replace(/[/\\?%*:|"<>]/g, '_').replace(/\.\./g, '_').trim();
  return clean.length > 0 ? clean : 'decrypted_vault.txt';
}

export function generateRescueBundle(options: RescueBundleOptions): RescueBundleResult {
  const threshold = options.threshold || 3;
  const totalShares = options.totalShares || 5;
  const title = options.title || 'Sovereign Emergency Recovery Vault';
  const instructions = options.instructions || 'Enter the required number of Shamir secret shares below to reconstruct the master key and decrypt this emergency inheritance payload offline.';
  const filename = sanitizeRescueFilename(options.filename);

  const payloadBuffer = Buffer.isBuffer(options.payload) ? options.payload : Buffer.from(options.payload, 'utf-8');

  const masterKey = randomBytes(32);
  const iv = randomBytes(12);

  const cipher = createCipheriv('aes-256-gcm', masterKey, iv, { authTagLength: 16 } as any);
  const encrypted = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
  const tag = (cipher as any).getAuthTag();

  const combinedCipherWithTag = Buffer.concat([encrypted, tag]);
  const cipherHex = combinedCipherWithTag.toString('hex');
  const cipherSha256 = createHash('sha256').update(combinedCipherWithTag).digest('hex');

  const masterKeyHex = masterKey.toString('hex');
  const shares = ShamirSecretSharing.split(masterKeyHex, totalShares, threshold);
  const bundleId = randomBytes(8).toString('hex');
  const createdAt = new Date().toISOString();

  const decoderScript = `
    const vaultData = JSON.parse(document.getElementById('obold-vault-data').textContent);

    const EXP_TABLE = new Uint8Array(512);
    const LOG_TABLE = new Uint8Array(256);
    (function initGF() {
      let x = 1;
      for (let i = 0; i < 255; i++) {
        EXP_TABLE[i] = x;
        LOG_TABLE[x] = i;
        let next = (x << 1) ^ x;
        if (next & 0x100) next ^= 0x11b;
        x = next & 0xff;
      }
      for (let i = 255; i < 512; i++) {
        EXP_TABLE[i] = EXP_TABLE[i - 255];
      }
      LOG_TABLE[0] = 0;
    })();

    function gfMultiply(a, b) {
      if (a === 0 || b === 0) return 0;
      return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
    }

    function gfDivide(a, b) {
      if (b === 0) throw new Error('Division by zero in GF(2^8)');
      if (a === 0) return 0;
      return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
    }

    function hexToBytes(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
      }
      return bytes;
    }

    function combineShamirShares(shares) {
      const parsed = [];
      const seenX = new Set();
      let expectedK = 0;

      for (const shareStr of shares) {
        const trimmed = shareStr.trim();
        if (!trimmed) continue;
        const v1Match = trimmed.match(/^obold-shamir-v1-([0-9a-fA-F]{8})-(\\d+)-of-(\\d+)-(\\d+)-([0-9a-fA-F]+)-([0-9a-fA-F]{8})$/);
        const legacyMatch = trimmed.match(/^obold-share-(\\d+)-of-(\\d+)-(\\d+)-([0-9a-fA-F]+)$/);

        if (!v1Match && !legacyMatch) continue;

        let t, xVal, hexData;
        if (v1Match) {
          t = parseInt(v1Match[2], 10);
          xVal = parseInt(v1Match[4], 10);
          hexData = v1Match[5];
        } else {
          t = parseInt(legacyMatch[1], 10);
          xVal = parseInt(legacyMatch[3], 10);
          hexData = legacyMatch[4];
        }

        if (seenX.has(xVal)) continue;
        seenX.add(xVal);
        expectedK = t;
        parsed.push({ x: xVal, y: hexToBytes(hexData) });
      }

      if (parsed.length < expectedK || expectedK === 0) {
        throw new Error('Insufficient valid shares. Need at least ' + (expectedK || vaultData.threshold) + ' shares, but got ' + parsed.length + '.');
      }

      const subset = parsed.slice(0, expectedK);
      const secretLen = subset[0].y.length;
      const secretBytes = new Uint8Array(secretLen);

      for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
        let secretByte = 0;
        for (let i = 0; i < subset.length; i++) {
          const xi = subset[i].x;
          const yi = subset[i].y[byteIdx];
          let basis = 1;
          for (let j = 0; j < subset.length; j++) {
            if (i === j) continue;
            const xj = subset[j].x;
            basis = gfMultiply(basis, gfDivide(xj, xi ^ xj));
          }
          secretByte ^= gfMultiply(yi, basis);
        }
        secretBytes[byteIdx] = secretByte;
      }

      return new TextDecoder().decode(secretBytes);
    }

    const inputsContainer = document.getElementById('shares-inputs');
    const thresholdBar = document.getElementById('threshold-bar');
    const counterText = document.getElementById('share-counter');
    const errorBox = document.getElementById('error-box');
    const decryptedSection = document.getElementById('decrypted-section');
    const decryptedContent = document.getElementById('decrypted-content');
    let decryptedTextGlobal = '';

    function updateProgress() {
      const inputs = Array.from(document.querySelectorAll('.share-input'));
      const filled = inputs.filter(i => i.value.trim().length > 0).length;
      const pct = Math.min(100, Math.round((filled / vaultData.threshold) * 100));
      thresholdBar.style.width = pct + '%';
      counterText.textContent = filled + ' / ' + vaultData.threshold + ' Shares Provided';
    }

    inputsContainer.addEventListener('input', updateProgress);

    document.getElementById('add-share-btn').addEventListener('click', () => {
      const count = document.querySelectorAll('.share-input').length + 1;
      const row = document.createElement('div');
      row.className = 'share-input-row';
      row.innerHTML = '<input type="text" class="share-input" placeholder="Paste Shamir share #' + count + '..." />';
      inputsContainer.appendChild(row);
      updateProgress();
    });

    document.getElementById('decrypt-btn').addEventListener('click', async () => {
      errorBox.style.display = 'none';
      errorBox.textContent = '';
      decryptedSection.style.display = 'none';

      const inputs = Array.from(document.querySelectorAll('.share-input'));
      const rawShares = inputs.map(i => i.value.trim()).filter(v => v.length > 0);

      try {
        const reconstructedKeyHex = combineShamirShares(rawShares);
        const masterKeyBytes = hexToBytes(reconstructedKeyHex);
        const ivBytes = hexToBytes(vaultData.iv);
        const cipherBytes = hexToBytes(vaultData.cipher);

        const cryptoKey = await window.crypto.subtle.importKey(
          'raw',
          masterKeyBytes,
          'AES-GCM',
          false,
          ['decrypt']
        );

        const decryptedBuffer = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
          cryptoKey,
          cipherBytes
        );

        decryptedTextGlobal = new TextDecoder().decode(decryptedBuffer);
        decryptedContent.textContent = decryptedTextGlobal;
        decryptedSection.style.display = 'block';
        decryptedSection.scrollIntoView({ behavior: 'smooth' });
      } catch (err) {
        errorBox.textContent = 'Decryption Failed: ' + (err.message || 'Invalid shares or corrupted payload');
        errorBox.style.display = 'block';
      }
    });

    document.getElementById('copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(decryptedTextGlobal);
      alert('Vault payload copied to clipboard!');
    });

    document.getElementById('download-btn').addEventListener('click', () => {
      const safeFilename = (vaultData.filename || 'decrypted_vault.txt').replace(/[/\\\\?%*:|"<>]/g, '_').replace(/^\\.+/, '');
      const blob = new Blob([decryptedTextGlobal], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = safeFilename;
      a.click();
      URL.revokeObjectURL(url);
    });
  `;

  const appSha256 = createHash('sha256').update(decoderScript.trim()).digest('hex');

  const manifest: RescueBundleManifest = {
    version: '1.0.0-beta',
    bundleId,
    createdAt,
    title,
    threshold,
    totalShares,
    cipherSha256,
    appSha256,
    iv: iv.toString('hex'),
    filename,
  };

  const bundleData = {
    title,
    instructions,
    filename,
    threshold,
    totalShares,
    iv: iv.toString('hex'),
    cipher: cipherHex,
    manifest,
    createdAt,
  };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'none';">
  <title>${escapeHtml(title)} — Offline Rescue Bundle | obold</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --accent: #00ffcc;
      --accent-glow: rgba(0, 255, 204, 0.15);
      --danger: #ef4444;
      --success: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    body {
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .vault-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 100%;
      max-width: 680px;
      padding: 2rem;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .badge {
      display: inline-block;
      background: var(--accent-glow);
      color: var(--accent);
      border: 1px solid var(--accent);
      padding: 0.25rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      margin-bottom: 0.75rem;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 0.5rem;
    }
    p.instructions {
      font-size: 0.875rem;
      color: var(--muted);
      line-height: 1.5;
    }
    .progress-section {
      margin: 1.5rem 0;
    }
    .progress-bar-bg {
      background: #1f293d;
      border-radius: 9999px;
      height: 8px;
      overflow: hidden;
      margin-bottom: 0.5rem;
    }
    .progress-bar-fill {
      background: var(--accent);
      height: 100%;
      width: 0%;
      transition: width 0.3s ease;
    }
    .progress-label {
      font-size: 0.75rem;
      color: var(--muted);
      display: flex;
      justify-content: space-between;
    }
    .inputs-group {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    .share-input-row {
      display: flex;
      gap: 0.5rem;
    }
    input.share-input {
      flex: 1;
      background: #0d131f;
      border: 1px solid var(--border);
      color: #ffffff;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-size: 0.8rem;
      outline: none;
      transition: border-color 0.2s ease;
    }
    input.share-input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--accent-glow);
    }
    .btn-row {
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    button {
      background: var(--accent);
      color: #090d16;
      border: none;
      padding: 0.75rem 1.25rem;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 700;
      cursor: pointer;
      transition: opacity 0.2s ease, transform 0.1s ease;
    }
    button:hover {
      opacity: 0.9;
    }
    button:active {
      transform: scale(0.98);
    }
    button.btn-secondary {
      background: #1f293d;
      color: var(--text);
    }
    .error-box {
      display: none;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid var(--danger);
      color: #fca5a5;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-size: 0.8rem;
      margin-bottom: 1.5rem;
    }
    .decrypted-section {
      display: none;
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      margin-top: 1.5rem;
    }
    .decrypted-box {
      background: #0d131f;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      font-size: 0.85rem;
      max-height: 250px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-bottom: 1rem;
      color: #a7f3d0;
    }
    .footer {
      font-size: 0.7rem;
      color: var(--muted);
      border-top: 1px solid var(--border);
      padding-top: 1rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="vault-card">
    <div class="header">
      <div class="badge">OFFLINE EMERGENCY RESCUE VAULT</div>
      <h1>${escapeHtml(title)}</h1>
      <p class="instructions">${escapeHtml(instructions)}</p>
    </div>

    <div class="progress-section">
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" id="threshold-bar"></div>
      </div>
      <div class="progress-label">
        <span id="share-counter">0 / ${threshold} Shares Provided</span>
        <span>Threshold: ${threshold} of ${totalShares}</span>
      </div>
    </div>

    <div class="inputs-group" id="shares-inputs">
      <div class="share-input-row">
        <input type="text" class="share-input" placeholder="Paste Shamir share #1..." />
      </div>
      <div class="share-input-row">
        <input type="text" class="share-input" placeholder="Paste Shamir share #2..." />
      </div>
      <div class="share-input-row">
        <input type="text" class="share-input" placeholder="Paste Shamir share #3..." />
      </div>
    </div>

    <div class="btn-row">
      <button type="button" id="decrypt-btn">🔓 Reconstruct Key & Decrypt</button>
      <button type="button" class="btn-secondary" id="add-share-btn">+ Add Another Share Input</button>
    </div>

    <div class="error-box" id="error-box"></div>

    <div class="decrypted-section" id="decrypted-section">
      <h2 style="font-size: 1.1rem; color: #10b981; margin-bottom: 0.5rem;">✓ Emergency Vault Decrypted Successfully</h2>
      <div class="decrypted-box" id="decrypted-content"></div>
      <div class="btn-row">
        <button type="button" id="copy-btn">📋 Copy Payload to Clipboard</button>
        <button type="button" class="btn-secondary" id="download-btn">💾 Download File (${escapeHtml(filename)})</button>
      </div>
    </div>

    <div class="footer">
      Generated by obold v1.0.0-beta &bull; Bundle ID: ${bundleId} &bull; Self-contained offline HTML vault &bull; Zero network egress required
    </div>
  </div>

  <script id="obold-vault-data" type="application/json">${JSON.stringify(bundleData)}</script>
  <script id="obold-rescue-manifest" type="application/json">${JSON.stringify(manifest)}</script>

  <script id="obold-rescue-app">${decoderScript}</script>
</body>
</html>`;

  return {
    html,
    shares,
    totalShares,
    threshold,
    manifest,
  };
}

export function verifyRescueBundle(htmlContent: string): { valid: boolean; manifest?: RescueBundleManifest; error?: string } {
  try {
    const manifestMatch = htmlContent.match(/<script id="obold-rescue-manifest" type="application\/json">([\s\S]*?)<\/script>/);
    const vaultMatch = htmlContent.match(/<script id="obold-vault-data" type="application\/json">([\s\S]*?)<\/script>/);
    const appMatch = htmlContent.match(/<script id="obold-rescue-app">([\s\S]*?)<\/script>/);

    if (!manifestMatch || !vaultMatch || !appMatch) {
      return { valid: false, error: 'Rescue bundle HTML is missing cryptographic manifest, vault data, or application runtime elements.' };
    }

    const manifest: RescueBundleManifest = JSON.parse(manifestMatch[1]);
    const vaultData = JSON.parse(vaultMatch[1]);

    if (!vaultData.cipher || !vaultData.iv) {
      return { valid: false, error: 'Rescue bundle vault data missing cipher or IV payload.' };
    }

    const cipherBytes = Buffer.from(vaultData.cipher, 'hex');
    const calculatedSha256 = createHash('sha256').update(cipherBytes).digest('hex');

    if (calculatedSha256 !== manifest.cipherSha256) {
      return {
        valid: false,
        error: `Cryptographic cipher SHA-256 digest mismatch! Expected ${manifest.cipherSha256} but computed ${calculatedSha256}. Ciphertext may be corrupted or tampered.`,
      };
    }

    const calculatedAppSha256 = createHash('sha256').update(appMatch[1].trim()).digest('hex');
    if (manifest.appSha256 && calculatedAppSha256 !== manifest.appSha256) {
      return {
        valid: false,
        error: `Security violation: Application code SHA-256 digest mismatch! Expected ${manifest.appSha256} but computed ${calculatedAppSha256}. JavaScript runtime in HTML bundle has been modified or tampered!`,
      };
    }

    const externalScriptMatch = htmlContent.match(/<script[^>]+src=["'][^"']+["']/i);
    if (externalScriptMatch) {
      return {
        valid: false,
        error: 'Security policy violation: Unauthorized external script inclusion detected in rescue bundle HTML!',
      };
    }

    const iframeMatch = htmlContent.match(/<iframe/i);
    if (iframeMatch) {
      return {
        valid: false,
        error: 'Security policy violation: Unauthorized iframe element detected in rescue bundle HTML!',
      };
    }

    if (!htmlContent.includes('Content-Security-Policy') || !htmlContent.includes("default-src 'none'")) {
      return {
        valid: false,
        error: 'Security policy violation: Missing or weakened Content-Security-Policy meta header in rescue bundle HTML!',
      };
    }

    if (/navigator\.sendBeacon|fetch\s*\(|XMLHttpRequest|WebSocket/i.test(appMatch[1])) {
      return {
        valid: false,
        error: 'Security policy violation: Network communication APIs detected in offline rescue app script!',
      };
    }

    if (manifest.threshold < 2 || manifest.totalShares < manifest.threshold) {
      return { valid: false, error: 'Invalid threshold or share parameters in manifest.' };
    }

    return { valid: true, manifest };
  } catch (err: any) {
    return { valid: false, error: `Failed to parse rescue bundle HTML: ${err?.message || err}` };
  }
}

export function generateRescueSignature(htmlContent: string, secretKey: string | Buffer): string {
  const keyBuf = Buffer.isBuffer(secretKey) ? secretKey : Buffer.from(secretKey, 'utf-8');
  return createHmac('sha256', keyBuf).update(Buffer.from(htmlContent, 'utf-8')).digest('hex');
}

export function verifyRescueSignature(htmlContent: string, signatureHex: string, secretKey: string | Buffer): boolean {
  try {
    const keyBuf = Buffer.isBuffer(secretKey) ? secretKey : Buffer.from(secretKey, 'utf-8');
    const computed = createHmac('sha256', keyBuf).update(Buffer.from(htmlContent, 'utf-8')).digest();
    const provided = Buffer.from(signatureHex.trim(), 'hex');
    if (computed.length !== provided.length) return false;
    return timingSafeEqual(computed, provided);
  } catch {
    return false;
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
