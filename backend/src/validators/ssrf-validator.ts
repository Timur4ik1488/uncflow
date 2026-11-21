/**
 * SSRF Protection Validator for Webhook dispatch and external HTTP requests.
 * Blocks private and loopback IP ranges, cloud metadata services, and internal hostnames.
 */
export function isPrivateOrLoopbackUrl(urlStr: string): boolean {
  if (process.env.ALLOW_PRIVATE_WEBHOOKS === 'true') {
    return false;
  }

  try {
    const parsed = new URL(urlStr);
    const host = parsed.hostname.toLowerCase();

    // 1. Loopback and localhost
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '0.0.0.0' ||
      host.endsWith('.localhost')
    ) {
      return true;
    }

    // 2. Cloud metadata endpoints
    if (
      host === '169.254.169.254' ||
      host === 'metadata.google.internal' ||
      host === 'instance-data'
    ) {
      return true;
    }

    // 3. IPv4 Private Subnets
    const ipv4Match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipv4Match) {
      const o1 = parseInt(ipv4Match[1], 10);
      const o2 = parseInt(ipv4Match[2], 10);

      // 10.0.0.0/8
      if (o1 === 10) return true;
      // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
      if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
      // 192.168.0.0/16
      if (o1 === 192 && o2 === 168) return true;
      // 127.0.0.0/8
      if (o1 === 127) return true;
      // 169.254.0.0/16
      if (o1 === 169 && o2 === 254) return true;
      // 0.0.0.0/8
      if (o1 === 0) return true;
    }

    // 4. Internal TLDs
    if (
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host.endsWith('.lan') ||
      host.endsWith('.corp')
    ) {
      return true;
    }

    return false;
  } catch {
    return true; // Malformed URLs are blocked
  }
}
