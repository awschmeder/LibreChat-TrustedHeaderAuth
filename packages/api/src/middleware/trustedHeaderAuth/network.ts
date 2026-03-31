import net from 'net';
import { logger } from '@librechat/data-schemas';
import type { Request } from 'express';
import type { FrozenConfig } from './types';
import { env } from './env';
import { redactIp } from './utils';

/**
 * Parse a CIDR notation string into address and prefix length.
 */
export function parseCidr(cidr: string): { address: string; prefixLen: number } | null {
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) {
    return null;
  }
  const prefixLen = parseInt(parts[1], 10);
  if (isNaN(prefixLen)) {
    return null;
  }
  const address = parts[0];
  if (!net.isIPv4(address) && !net.isIPv6(address)) {
    return null;
  }
  if (net.isIPv4(address) && (prefixLen < 0 || prefixLen > 32)) {
    return null;
  }
  if (net.isIPv6(address) && (prefixLen < 0 || prefixLen > 128)) {
    return null;
  }
  return { address, prefixLen };
}

/**
 * Check if an IPv4 address falls within a CIDR range.
 */
export function ipv4InCidr(ip: string, cidrAddr: string, prefixLen: number): boolean {
  if (prefixLen === 0) {
    return true;
  }

  const ipParts = ip.split('.').map(Number);
  const cidrParts = cidrAddr.split('.').map(Number);

  const ipNum =
    (((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0);
  const cidrNum =
    (((cidrParts[0] << 24) | (cidrParts[1] << 16) | (cidrParts[2] << 8) | cidrParts[3]) >>> 0);

  const mask = prefixLen === 32
    ? 0xFFFFFFFF
    : (~(0xFFFFFFFF >>> prefixLen)) >>> 0;
  return (ipNum & mask) === (cidrNum & mask);
}

/**
 * Expand an IPv6 address with :: shorthand into its full 8-group form.
 * Returns null if the input is malformed.
 */
function expandIPv6(ip: string): string | null {
  if (ip.includes('::')) {
    const parts = ip.split('::');
    if (parts.length > 2) {
      return null;
    }
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0) {
      return null;
    }
    const middle = Array(missing).fill('0000') as string[];
    const all = [...left, ...middle, ...right];
    return all.map((g) => g.padStart(4, '0')).join(':');
  }
  const groups = ip.split(':');
  if (groups.length !== 8) {
    return null;
  }
  return groups.map((g) => g.padStart(4, '0')).join(':');
}

/**
 * Convert an IPv6 address string into a 16-byte Uint8Array.
 * Returns null if the address cannot be parsed.
 */
function ipv6ToBytes(ip: string): Uint8Array | null {
  const expanded = expandIPv6(ip);
  if (!expanded) {
    return null;
  }
  const groups = expanded.split(':');
  if (groups.length !== 8) {
    return null;
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    bytes[i * 2] = (val >> 8) & 0xff;
    bytes[i * 2 + 1] = val & 0xff;
  }
  return bytes;
}

/**
 * Check if an IPv6 address falls within a CIDR range.
 */
export function ipv6InCidr(ip: string, cidrAddr: string, prefixLen: number): boolean {
  if (prefixLen === 0) {
    return true;
  }
  const ipBytes = ipv6ToBytes(ip);
  const cidrBytes = ipv6ToBytes(cidrAddr);
  if (!ipBytes || !cidrBytes) {
    return false;
  }
  const fullBytes = Math.floor(prefixLen / 8);
  for (let i = 0; i < fullBytes; i++) {
    if (ipBytes[i] !== cidrBytes[i]) {
      return false;
    }
  }
  const remainingBits = prefixLen % 8;
  if (remainingBits > 0) {
    const mask = 0xff << (8 - remainingBits);
    if ((ipBytes[fullBytes] & mask) !== (cidrBytes[fullBytes] & mask)) {
      return false;
    }
  }
  return true;
}

/**
 * Return true when the CIDR allowlist is non-trivial.
 *
 * Accepts an optional trustedCidrs string (from frozen config); when omitted,
 * falls back to reading env directly (used only during startup / logConfig).
 */
export function isCidrStrict(trustedCidrs?: string): boolean {
  const cidrsRaw = trustedCidrs ?? env('TRUSTED_CIDRS');
  if (!cidrsRaw) {
    return false;
  }
  const cidrs = cidrsRaw.split(',').map((c) => c.trim()).filter(Boolean);
  if (cidrs.length === 0) {
    return false;
  }
  const catchAll = new Set(['0.0.0.0/0', '::/0']);
  if (cidrs.some((c) => catchAll.has(c))) {
    return false;
  }
  return true;
}

/**
 * Check if the request source IP is within the trusted CIDR ranges
 * and the hop count is within limits.
 *
 * When a frozen config is provided, uses those values instead of
 * reading process.env per-request.
 */
export function isSourceTrusted(
  req: Request,
  config?: Pick<FrozenConfig, 'trustedCidrs' | 'maxHops'>,
): boolean {
  const cidrsRaw = config?.trustedCidrs ?? env('TRUSTED_CIDRS', '0.0.0.0/0,::/0');
  const cidrs = cidrsRaw.split(',').map((c) => c.trim()).filter(Boolean);

  const maxHops = config?.maxHops ?? parseInt(env('MAX_HOPS', '1'), 10);

  if (isNaN(maxHops)) {
    logger.warn('[trustedHeaderAuth] maxHops is NaN -- rejecting request (fail-closed)');
    return false;
  }

  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const hops = (xForwardedFor as string).split(',').map((h) => h.trim()).filter(Boolean);
    if (hops.length > maxHops) {
      logger.warn(
        `[trustedHeaderAuth] Hop count ${hops.length} exceeds MAX_HOPS=${maxHops}`,
      );
      return false;
    }
  }

  let clientIp = req.ip;
  if (!clientIp) {
    logger.warn('[trustedHeaderAuth] Unable to determine client IP');
    return false;
  }

  // Normalize IPv4-mapped IPv6 (::ffff:10.0.0.1 -> 10.0.0.1)
  if (clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.slice(7);
  }

  const isIpv4 = net.isIPv4(clientIp);

  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr);
    if (!parsed) {
      logger.warn(`[trustedHeaderAuth] Invalid CIDR: ${cidr}`);
      continue;
    }

    if (isIpv4 && net.isIPv4(parsed.address)) {
      if (ipv4InCidr(clientIp, parsed.address, parsed.prefixLen)) {
        return true;
      }
    }

    if (!isIpv4 && net.isIPv6(parsed.address)) {
      if (ipv6InCidr(clientIp, parsed.address, parsed.prefixLen)) {
        return true;
      }
    }
  }

  logger.warn(
    `[trustedHeaderAuth] Source IP ${redactIp(clientIp)} not in trusted CIDRs`,
  );
  return false;
}
