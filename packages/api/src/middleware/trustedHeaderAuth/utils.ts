/** Mask the local part of an email address for safe logging. */
export function redactEmail(email: string): string {
  const atIndex = email.indexOf('@');
  if (atIndex <= 0) {
    return '***';
  }
  return `${email[0]}***${email.slice(atIndex)}`;
}

/**
 * Mask the last octet (IPv4) or last group (IPv6) of an IP address for safe logging.
 * IPv4: 192.168.1.100 -> 192.168.1.xxx
 * IPv6: 2001:db8::1 -> 2001:db8::xxx
 */
export function redactIp(ip: string): string {
  if (ip.includes(':')) {
    const lastColon = ip.lastIndexOf(':');
    return `${ip.slice(0, lastColon + 1)}xxx`;
  }
  const lastDot = ip.lastIndexOf('.');
  if (lastDot === -1) {
    return 'xxx';
  }
  return `${ip.slice(0, lastDot + 1)}xxx`;
}

/**
 * Decode a base64url-encoded string, handling missing padding.
 */
export function base64UrlDecode(raw: string): Buffer {
  const padded = raw + '='.repeat((4 - (raw.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

const POISONED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Traverse an object by dot-delimited path, replacing lodash/get. */
export function getByPath(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>(
    (acc, key) => {
      if (POISONED_KEYS.has(key)) {
        return undefined;
      }
      return acc != null && typeof acc === 'object'
        ? (acc as Record<string, unknown>)[key]
        : undefined;
    },
    obj,
  );
}
