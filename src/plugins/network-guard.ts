import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';

function isIpPrivate(rawIp: string): boolean {
  let ip = rawIp.trim().toLowerCase();
  const zoneIndex = ip.indexOf('%');
  if (zoneIndex !== -1) {
    ip = ip.substring(0, zoneIndex);
  }

  if (/^\d+$/.test(ip)) {
    const num = parseInt(ip, 10);
    if (num >= 0 && num <= 0xffffffff) {
      ip = `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  } else if (/^0x[0-9a-f]+$/i.test(ip)) {
    const num = parseInt(ip, 16);
    if (num >= 0 && num <= 0xffffffff) {
      ip = `${(num >>> 24) & 255}.${(num >>> 16) & 255}.${(num >>> 8) & 255}.${num & 255}`;
    }
  }

  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
    return true;
  }

  if (ip.startsWith('::ffff:')) {
    const mapped = ip.substring(7);
    if (mapped.includes('.')) {
      return isIpPrivate(mapped);
    }
    const hexParts = mapped.split(':');
    if (hexParts.length === 2) {
      const p1 = parseInt(hexParts[0], 16);
      const p2 = parseInt(hexParts[1], 16);
      if (!isNaN(p1) && !isNaN(p2)) {
        return isIpPrivate(`${(p1 >> 8) & 255}.${p1 & 255}.${(p2 >> 8) & 255}.${p2 & 255}`);
      }
    }
    return true;
  }

  if (ip.startsWith('127.') || ip.startsWith('0.') || ip === '255.255.255.255' || ip === '0.0.0.0') {
    return true;
  }

  if (ip.startsWith('169.254.')) {
    return true;
  }

  if (ip.startsWith('10.')) {
    return true;
  }

  if (ip.startsWith('192.168.')) {
    return true;
  }

  const octets = ip.split('.').map((p) => parseInt(p, 10));
  if (octets.length === 4 && octets.every((o) => !isNaN(o) && o >= 0 && o <= 255)) {
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
      return true;
    }
    if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) {
      return true;
    }
    if (octets[0] === 192 && octets[1] === 0 && (octets[2] === 0 || octets[2] === 2)) {
      return true;
    }
    if (octets[0] === 198 && (octets[1] === 18 || octets[1] === 19)) {
      return true;
    }
    if (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) {
      return true;
    }
    if (octets[0] === 203 && octets[1] === 0 && octets[2] === 113) {
      return true;
    }
    if (octets[0] >= 224) {
      return true;
    }
  }

  if (
    ip === '::' ||
    /^fe[89ab]/i.test(ip) ||
    /^f[cd]/i.test(ip) ||
    /^ff/i.test(ip) ||
    ip.startsWith('2001:db8:') ||
    ip.startsWith('64:ff9b:')
  ) {
    return true;
  }

  return false;
}

export async function validateTargetUrl(
  rawUrl: string,
  allowPrivate: boolean = false
): Promise<{ valid: boolean; error?: string; url?: URL; pinnedIp?: string }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, error: `Invalid URL format: "${rawUrl}"` };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: `Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
  }

  const rawHostname = parsed.hostname.toLowerCase();
  const cleanHost = rawHostname.startsWith('[') && rawHostname.endsWith(']') ? rawHostname.slice(1, -1) : rawHostname;

  if (cleanHost === 'localhost' || cleanHost.endsWith('.localhost') || cleanHost.endsWith('.local') || cleanHost.endsWith('.internal')) {
    if (!allowPrivate) {
      return { valid: false, error: `Blocked localhost/local network target: "${rawHostname}".` };
    }
  }

  if (isIpPrivate(cleanHost)) {
    if (!allowPrivate) {
      return {
        valid: false,
        error: `Blocked private/link-local SSRF network destination: ${rawHostname} is a private IP.`,
      };
    }
    return { valid: true, url: parsed, pinnedIp: cleanHost };
  }

  if (isIP(cleanHost) !== 0) {
    return { valid: true, url: parsed, pinnedIp: cleanHost };
  }

  let pinnedIp: string | undefined;
  if (!allowPrivate) {
    try {
      const records = await dns.lookup(cleanHost, { all: true });
      if (!records || records.length === 0) {
        return { valid: false, error: `DNS lookup returned no records for hostname "${cleanHost}".` };
      }
      for (const record of records) {
        if (isIpPrivate(record.address)) {
          return {
            valid: false,
            error: `Blocked private/link-local SSRF network destination: ${cleanHost} resolved to ${record.address}.`,
          };
        }
      }
      pinnedIp = records[0].address;
    } catch (err: any) {
      return { valid: false, error: `DNS lookup failed for hostname "${cleanHost}": ${err?.message || err}` };
    }
  }

  return { valid: true, url: parsed, pinnedIp };
}

export async function fetchWithSsrfGuard(
  targetUrl: string,
  init?: RequestInit,
  allowPrivate: boolean = false,
  maxRedirects: number = 5
): Promise<Response> {
  let currentUrl = targetUrl;
  let redirectsCount = 0;

  while (true) {
    const validation = await validateTargetUrl(currentUrl, allowPrivate);
    if (!validation.valid || !validation.url) {
      throw new Error(validation.error || `SSRF validation failed for target URL: ${currentUrl}`);
    }

    let requestUrl = currentUrl;
    const fetchInit: RequestInit = {
      ...init,
      redirect: 'manual',
    };

    if (!allowPrivate && validation.pinnedIp) {
      const parsed = validation.url;
      const originalHost = parsed.host;
      const pinnedHost = validation.pinnedIp.includes(':') ? `[${validation.pinnedIp}]` : validation.pinnedIp;
      const portPart = parsed.port ? `:${parsed.port}` : '';
      requestUrl = `${parsed.protocol}//${pinnedHost}${portPart}${parsed.pathname}${parsed.search}`;

      const headers = new Headers(init?.headers);
      if (!headers.has('Host')) {
        headers.set('Host', originalHost);
      }
      fetchInit.headers = headers;

      if (parsed.protocol === 'https:') {
        (fetchInit as any).tls = {
          ...((fetchInit as any).tls || {}),
          serverName: parsed.hostname,
        };
      }
    }

    const response = await fetch(requestUrl, fetchInit);

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      redirectsCount++;
      if (redirectsCount > maxRedirects) {
        throw new Error(`SSRF guard error: Exceeded maximum allowed redirects (${maxRedirects})`);
      }

      const location = response.headers.get('Location');
      if (!location) {
        throw new Error(`SSRF guard error: Received redirect status ${response.status} with missing Location header`);
      }

      const resolvedRedirectUrl = new URL(location, currentUrl).toString();
      currentUrl = resolvedRedirectUrl;
      continue;
    }

    return response;
  }
}

export async function validateWebSocketUrl(
  rawUrl: string,
  allowPrivate: boolean = false
): Promise<{ valid: boolean; error?: string; url?: URL; pinnedIp?: string }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, error: `Invalid WebSocket URL format: "${rawUrl}"` };
  }

  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    return { valid: false, error: `Unsupported protocol "${parsed.protocol}". Only ws:// and wss:// are permitted.` };
  }

  const rawHostname = parsed.hostname.toLowerCase();
  const cleanHost = rawHostname.startsWith('[') && rawHostname.endsWith(']') ? rawHostname.slice(1, -1) : rawHostname;

  if (cleanHost === 'localhost' || cleanHost.endsWith('.localhost') || cleanHost.endsWith('.local') || cleanHost.endsWith('.internal')) {
    if (!allowPrivate) {
      return { valid: false, error: `Blocked localhost/local network target: "${rawHostname}".` };
    }
  }

  if (isIpPrivate(cleanHost)) {
    if (!allowPrivate) {
      return {
        valid: false,
        error: `Blocked private/link-local SSRF network destination: ${rawHostname} is a private IP.`,
      };
    }
    return { valid: true, url: parsed, pinnedIp: cleanHost };
  }

  if (isIP(cleanHost) !== 0) {
    return { valid: true, url: parsed, pinnedIp: cleanHost };
  }

  let pinnedIp: string | undefined;
  if (!allowPrivate) {
    try {
      const records = await dns.lookup(cleanHost, { all: true });
      if (!records || records.length === 0) {
        return { valid: false, error: `DNS lookup returned no records for hostname "${cleanHost}".` };
      }
      for (const record of records) {
        if (isIpPrivate(record.address)) {
          return {
            valid: false,
            error: `Blocked private/link-local SSRF network destination: ${cleanHost} resolved to ${record.address}.`,
          };
        }
      }
      pinnedIp = records[0].address;
    } catch (err: any) {
      return { valid: false, error: `DNS lookup failed for hostname "${cleanHost}": ${err?.message || err}` };
    }
  }

  return { valid: true, url: parsed, pinnedIp };
}

export interface WebSocketSsrfOptions {
  headers?: Record<string, string>;
  tls?: Record<string, any>;
  [key: string]: any;
}

export async function createWebSocketWithSsrfGuard(
  rawUrl: string,
  allowPrivate: boolean = false,
  protocols?: string | string[],
  options?: WebSocketSsrfOptions
): Promise<{ ws: WebSocket; url: URL; pinnedIp?: string }> {
  const validation = await validateWebSocketUrl(rawUrl, allowPrivate);
  if (!validation.valid || !validation.url) {
    throw new Error(validation.error || `SSRF validation failed for WebSocket URL: ${rawUrl}`);
  }

  const parsed = validation.url;
  let connectUrl = rawUrl;
  const wsOptions: Record<string, any> = { ...(options || {}) };

  if (!allowPrivate && validation.pinnedIp) {
    const originalHost = parsed.host;
    const pinnedHost = validation.pinnedIp.includes(':') ? `[${validation.pinnedIp}]` : validation.pinnedIp;
    const portPart = parsed.port ? `:${parsed.port}` : '';
    connectUrl = `${parsed.protocol}//${pinnedHost}${portPart}${parsed.pathname}${parsed.search}`;

    wsOptions.headers = {
      Host: originalHost,
      ...(wsOptions.headers || {}),
    };

    if (parsed.protocol === 'wss:') {
      wsOptions.tls = {
        serverName: parsed.hostname,
        ...(wsOptions.tls || {}),
      };
    }
  }

  const ws: WebSocket = protocols !== undefined
    ? new (WebSocket as any)(connectUrl, protocols, wsOptions)
    : new (WebSocket as any)(connectUrl, wsOptions);

  return { ws, url: parsed, pinnedIp: validation.pinnedIp };
}
