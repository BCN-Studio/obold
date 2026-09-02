import { promises as dns } from 'node:dns';

function isIpPrivate(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
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
  if (octets.length === 4) {
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
      return true;
    }
    if (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) {
      return true;
    }
    if (octets[0] === 198 && (octets[1] === 18 || octets[1] === 19)) {
      return true;
    }
  }

  const lower = ip.toLowerCase();
  if (
    lower.startsWith('fe80:') ||
    lower.startsWith('fc00:') ||
    lower.startsWith('fd00:') ||
    lower.startsWith('::ffff:127.') ||
    lower.startsWith('::ffff:10.') ||
    lower.startsWith('::ffff:192.168.') ||
    lower.startsWith('::ffff:169.254.') ||
    lower.startsWith('::ffff:0.') ||
    lower === '::'
  ) {
    return true;
  }

  return false;
}

export async function validateTargetUrl(
  rawUrl: string,
  allowPrivate: boolean = false
): Promise<{ valid: boolean; error?: string; url?: URL }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, error: `Invalid URL format: "${rawUrl}"` };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: `Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    if (!allowPrivate) {
      return { valid: false, error: `Blocked localhost/local network target: "${hostname}".` };
    }
  }

  if (!allowPrivate) {
    try {
      const records = await dns.lookup(hostname, { all: true });
      for (const record of records) {
        if (isIpPrivate(record.address)) {
          return {
            valid: false,
            error: `Blocked private/link-local SSRF network destination: ${hostname} resolved to ${record.address}.`,
          };
        }
      }
    } catch (err: any) {
      return { valid: false, error: `DNS lookup failed for hostname "${hostname}": ${err?.message || err}` };
    }
  }

  return { valid: true, url: parsed };
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

    const fetchInit: RequestInit = {
      ...init,
      redirect: 'manual',
    };

    const response = await fetch(currentUrl, fetchInit);

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
