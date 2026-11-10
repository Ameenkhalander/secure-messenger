// Tiny DOM helpers. User-controlled text is ONLY ever inserted with textContent (XSS-safe).
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}

// Static, trusted SVG markup only (never interpolate user data here).
const ICONS = {
  lock: '<path d="M7 10V8a5 5 0 0 1 10 0v2M6 10h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1z"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  checks: '<path d="M2.5 12.5L7 17l9-10M11 15.5l1.5 1.5 9-10"/>',
  clock: '<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>',
  back: '<path d="M15 5l-7 7 7 7"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  users: '<circle cx="9" cy="9" r="3.5"/><path d="M2.5 19c.6-3.3 3.1-5 6.5-5s5.9 1.7 6.5 5M16 6a3.5 3.5 0 0 1 0 7M18 14.2c2 .5 3.2 2 3.5 4.8"/>',
  send: '<path d="M4 12l16-8-6 16-3-7-7-1z"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  shield: '<path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6l8-3z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
  more: '<circle cx="5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="19" cy="12" r="1.2"/>',
};
export function icon(name, size = 18) {
  const wrap = document.createElement('span');
  wrap.className = 'icon';
  wrap.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ''}</svg>`;
  return wrap;
}

export const initials = (name) => (name || '?').trim().split(/\s+/).slice(0, 2).map((p) => p[0]).join('').toUpperCase() || '?';

export function avatar(name, seed, online = null, size = 44) {
  let h = 0;
  for (const ch of String(seed ?? name)) h = (h * 31 + ch.charCodeAt(0)) % 360;
  const a = el('div', { class: 'avatar', 'aria-hidden': 'true' }, initials(name));
  a.style.width = a.style.height = `${size}px`;
  a.style.background = `hsl(${h} 38% 38%)`;
  a.style.fontSize = `${Math.round(size * 0.36)}px`;
  if (online) a.classList.add('is-online');
  return a;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const dayFmt = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
export const fmtTime = (iso) => timeFmt.format(new Date(iso));
export function fmtDay(iso) {
  const d = new Date(iso), now = new Date();
  const same = (a, b) => a.toDateString() === b.toDateString();
  if (same(d, now)) return 'Today';
  const y = new Date(now); y.setDate(now.getDate() - 1);
  return same(d, y) ? 'Yesterday' : dayFmt.format(d);
}
export function fmtAgo(iso) {
  if (!iso) return 'a while ago';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function toast(message, kind = 'info', ms = 5000) {
  const host = document.getElementById('toasts');
  if (!host) return;
  const t = el('div', { class: `toast-item ${kind}`, role: 'status' }, message);
  host.append(t);
  setTimeout(() => t.remove(), ms);
}

export const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
