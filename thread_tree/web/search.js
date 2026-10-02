'use strict';
// Matching of pasted identifiers (e.g. from Home Assistant's "Matter info") against nodes.
// Pure functions without DOM access, so they can be tested outside a browser.

const hexOnly = s => s.toLowerCase().replace(/[^0-9a-f]/g, '');

// IPv6 text in any notation (compressed, upper case, leading zeros) -> 32 lowercase hex digits, or null
function ipv6Hex(text) {
  const t = text.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (!/^[0-9a-f:]+$/.test(t) || !t.includes(':') || (t.match(/::/g) || []).length > 1) return null;
  const [head, tail] = t.includes('::') ? t.split('::') : [t, null];
  const part = s => (s ? s.split(':') : []);
  const groups = [...part(head)];
  if (tail !== null) {
    const rest = part(tail);
    const missing = 8 - groups.length - rest.length;
    if (missing < 1) return null;
    groups.push(...Array(missing).fill('0'), ...rest);
  }
  if (groups.length !== 8 || groups.some(g => g === '' || g.length > 4)) return null;
  return groups.map(g => g.padStart(4, '0')).join('');
}

// 48-bit MAC (Ethernet/Wi-Fi) -> its modified EUI-64 interface ID (16 hex digits), used by SLAAC addresses
function macToIid(hex12) {
  const first = (parseInt(hex12.slice(0, 2), 16) ^ 0x02).toString(16).padStart(2, '0');
  return first + hex12.slice(2, 6) + 'fffe' + hex12.slice(6);
}

// node: {ext, addresses:[{addr}]}; haystack: lower-case text the plain substring search runs on
function matchesQuery(node, query, haystack) {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  if (haystack.includes(q)) return true;
  if (/^[0-9a-f]{2}([:\-. ]?[0-9a-f]{2}){5,7}$/.test(q)) {  // a MAC address: 6 bytes (48 bit) or 8 bytes (EUI-64)
    const hex = hexOnly(q);
    if (hex.length === 16) return node.ext === hex;
    if (hex.length === 12) {
      const iid = macToIid(hex);
      return (node.ext !== null && node.ext !== undefined &&
              (node.ext === hex.slice(0, 6) + 'fffe' + hex.slice(6) || node.ext === iid)) ||
        node.addresses.some(a => (ipv6Hex(a.addr) || '').endsWith(iid));
    }
    return false;
  }
  const want = ipv6Hex(q);
  return want !== null && node.addresses.some(a => ipv6Hex(a.addr) === want);
}
