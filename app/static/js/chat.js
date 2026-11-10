import { api } from './api.js';
import { el, icon, avatar, fmtTime, fmtDay, fmtAgo, toast, debounce } from './dom.js';
import { b64d, b64e, decryptMessage, encryptMessage, fingerprint, generateIdentity, prettyFingerprint, registrationProof } from './e2ee.js';
import * as keystore from './keystore.js';

const root = document.getElementById('app');
const me = { id: Number(root.dataset.userId), username: root.dataset.username, name: root.dataset.displayName };
const $ = (id) => document.getElementById(id);

const state = {
  identity: null,            // this device's active key record
  keys: new Map(),           // keyId -> local key record (active + retired, for reading history)
  convs: new Map(),          // id -> conversation (server shape + _preview)
  messages: new Map(),       // convId -> [message]
  current: null,             // open conversation id
  typing: new Map(),         // convId -> Map(userId -> expiresAt)
  socket: null,
  hasMore: false,
};

// ------------------------------------------------------------------ trust (TOFU + manual verification)
const readJSON = (k) => { try { return JSON.parse(localStorage.getItem(k) || '{}'); } catch { return {}; } };
const writeJSON = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } };
const PIN_KEY = `sealed.pins.${me.id}`, VERIFIED_KEY = `sealed.verified.${me.id}`;
const shortFp = (fp) => prettyFingerprint(fp.slice(0, 16));

function checkPin(userId, fp, name) {
  if (userId === me.id) return;
  const pins = readJSON(PIN_KEY), seen = pins[userId] || [];
  if (seen.includes(fp)) return;
  pins[userId] = [...seen, fp];
  writeJSON(PIN_KEY, pins);
  if (seen.length) toast(`${name || 'A contact'} is using a new encryption key (${shortFp(fp)}). Compare safety numbers if you did not expect this.`, 'warn', 10000);
}
const isVerified = (fp) => !!readJSON(VERIFIED_KEY)[fp];
function setVerified(fp, on) { const v = readJSON(VERIFIED_KEY); if (on) v[fp] = true; else delete v[fp]; writeJSON(VERIFIED_KEY, v); }

// ------------------------------------------------------------------ device bootstrap
async function ensureDevice() {
  const { devices } = await api('GET', '/api/devices');
  const local = (await keystore.getForUser(me.id)) || [];
  local.forEach((r) => state.keys.set(r.keyId, r));
  const usable = local.filter((r) => r.active)
    .sort((a, b) => b.createdAt - a.createdAt)
    .find((r) => devices.some((d) => !d.revoked && d.key && d.key.id === r.keyId));
  if (usable) { state.identity = usable; return; }
  // First visit on this browser (or its device was removed): create a fresh identity.
  await keystore.deactivateAll(me.id);
  const id = await generateIdentity();
  const { device } = await api('POST', '/api/devices', {
    name: deviceName(), enc_pub: b64e(id.encPub), sign_pub: b64e(id.signPub), pop_sig: await registrationProof(id),
  });
  const rec = {
    keyId: device.key.id, userId: me.id, deviceId: device.id, xPriv: id.xPriv, sPriv: id.sPriv,
    encPub: b64e(id.encPub), signPub: b64e(id.signPub), fingerprint: await fingerprint(id.encPub, id.signPub),
    active: true, createdAt: Date.now(),
  };
  await keystore.putIdentity(rec);
  state.keys.set(rec.keyId, rec);
  state.identity = rec;
}
function deviceName() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'device';
  return `${browser} on ${os}`;
}

// ------------------------------------------------------------------ decrypt
async function decrypt(msg) {
  if (msg.deleted) return { deleted: true };
  const env = msg.envelopes.find((e) => state.keys.has(Number(e.k)));
  if (!env) return { error: 'Sent before this device joined, so it cannot be read here.' };
  const sk = msg.sender_key;
  if (!sk || sk.user_id !== msg.sender_id) return { error: 'Unknown sender key.' };
  try {
    const encPub = b64d(sk.enc_pub, 32), signPub = b64d(sk.sign_pub, 32);
    const fp = await fingerprint(encPub, signPub);       // never trust the server-reported fingerprint
    if (fp !== sk.fingerprint) return { error: 'Sender key does not match its fingerprint.' };
    checkPin(msg.sender_id, fp, msg.sender_name);
    const rec = state.keys.get(Number(env.k));
    const payload = await decryptMessage(msg, { myKeyId: rec.keyId, xPriv: rec.xPriv, encPub: b64d(rec.encPub, 32), senderSignPub: signPub });
    return { payload, fp };
  } catch {
    return { error: 'This message failed verification and was not shown.' };
  }
}
async function hydrate(list) { for (const m of list) m._res = await decrypt(m); return list; }

// ------------------------------------------------------------------ conversations
const convName = (c) => c.name || 'Conversation';
const peerOf = (c) => (c.kind === 'direct' ? c.peer : null);

async function previewOf(c) {
  const m = c.last_message;
  if (!m) return 'No messages yet';
  const res = m._res || (m._res = await decrypt(m));
  if (res.deleted) return 'Message deleted';
  if (res.error) return 'Encrypted message';
  const who = m.sender_id === me.id ? 'You: ' : (c.kind === 'group' ? `${(m.sender_name || '').split(' ')[0]}: ` : '');
  return who + String(res.payload.body || '').replace(/\s+/g, ' ').slice(0, 70);
}

async function loadConversations() {
  const { conversations } = await api('GET', '/api/conversations');
  await Promise.all(conversations.map(async (c) => { c._preview = await previewOf(c); }));
  state.convs = new Map(conversations.map((c) => [c.id, c]));
  renderList();
  if (state.current && !state.convs.has(state.current)) closeThread();
}

function typingNames(convId) {
  const t = state.typing.get(convId); if (!t) return [];
  const now = Date.now(), c = state.convs.get(convId);
  return [...t.entries()].filter(([, exp]) => exp > now)
    .map(([uid]) => (c?.members.find((m) => m.id === uid)?.display_name || 'Someone').split(' ')[0]);
}

function renderList() {
  const host = $('conv-list');
  const q = $('search').value.trim().toLowerCase();
  host.replaceChildren();
  const items = [...state.convs.values()].filter((c) => !q || convName(c).toLowerCase().includes(q));
  if (!items.length) {
    host.append(el('div', { class: 'list-empty' },
      el('p', { text: q ? 'No conversations match.' : 'No conversations yet.' }),
      el('button', { class: 'btn btn-sm btn-accent', type: 'button', onclick: () => openNewChat(q) }, q ? 'Find people' : 'Start a conversation')));
    return;
  }
  for (const c of items) {
    const peer = peerOf(c), typers = typingNames(c.id);
    const row = el('div', { class: `conv${c.id === state.current ? ' active' : ''}`, role: 'listitem', tabindex: '0', onclick: () => openConv(c.id),
      onkeydown: (e) => { if (e.key === 'Enter') openConv(c.id); } },
      avatar(convName(c), peer ? peer.id : `g${c.id}`, peer && peer.online),
      el('div', { class: 'conv-body' },
        el('div', { class: 'conv-name', text: convName(c) }),
        el('div', { class: `conv-preview${typers.length ? ' is-typing' : ''}`, text: typers.length ? 'typing…' : c._preview || '' })),
      el('div', { class: 'conv-meta' },
        el('div', { class: 'conv-time', text: c.last_activity ? fmtTime(c.last_activity) : '' }),
        c.unread > 0 ? el('span', { class: 'badge-unread', text: c.unread > 99 ? '99+' : String(c.unread) }) : null));
    host.append(row);
  }
}

// ------------------------------------------------------------------ thread
function closeThread() {
  state.current = null;
  root.classList.remove('show-chat');
  $('thread').hidden = true; $('empty').hidden = false;
  renderList();
}

async function openConv(id) {
  state.current = id;
  root.classList.add('show-chat');
  $('empty').hidden = true; $('thread').hidden = false;
  const conv = state.convs.get(id);
  renderHeader(conv);
  $('messages').replaceChildren(el('div', { class: 'loading', text: 'Decrypting…' }));
  const { messages } = await api('GET', `/api/conversations/${id}/messages?limit=50`);
  state.hasMore = messages.length >= 50;
  state.messages.set(id, await hydrate(messages));
  if (state.current !== id) return;
  renderMessages(true);
  markRead(id);
  renderList();
  $('composer-input').focus();
}

function renderHeader(c) {
  const peer = peerOf(c), typers = typingNames(c.id);
  const head = $('thread-head');
  head.replaceChildren(
    el('button', { class: 'btn-icon back', type: 'button', 'aria-label': 'Back to conversations', onclick: closeThread }, icon('back', 22)),
    avatar(convName(c), peer ? peer.id : `g${c.id}`, peer && peer.online, 40),
    el('div', { class: 'thread-title' },
      el('div', { class: 'name', text: convName(c) }),
      el('div', { class: `sub${typers.length || (peer && peer.online) ? ' live' : ''}`,
        text: typers.length ? `${typers.join(', ')} typing…`
          : peer ? (peer.online ? 'Online' : `Last seen ${fmtAgo(peer.last_seen_at)}`) : `${c.members.length} members` })),
    el('span', { class: 'sealed-pill', title: 'End-to-end encrypted. Only the people in this chat can read it.' }, icon('lock', 14), 'Sealed'),
    el('button', { class: 'btn-icon', type: 'button', 'aria-label': 'Conversation details and safety numbers', onclick: () => openInfo(c.id) }, icon('info', 20)));
}

function statusIcon(m) {
  if (m.pending) return icon('clock', 14);
  const n = m.recipient_count;
  if (n > 0 && m.read_count >= n) { const i = icon('checks', 15); i.classList.add('read'); return i; }
  if (n > 0 && m.delivered_count >= n) return icon('checks', 15);
  return icon('check', 14);
}

function bubble(m, conv, fresh = false) {
  const mine = m.sender_id === me.id, res = m._res || {};
  const body = res.deleted ? el('div', { class: 'text deleted', text: 'This message was deleted.' })
    : res.error ? el('div', { class: 'text error', text: res.error })
    : el('div', { class: 'text', text: String(res.payload.body) });
  const meta = el('div', { class: 'meta' },
    !res.deleted && !res.error ? el('span', { class: 'seal', title: 'Signature verified. Encrypted end to end.' }, icon('lock', 11)) : null,
    el('span', { text: fmtTime(m.created_at || new Date(m.timestamp).toISOString()) }),
    mine && !res.deleted ? statusIcon(m) : null);
  const actions = mine && !m.pending && !res.deleted
    ? el('button', { class: 'bubble-action', type: 'button', 'aria-label': 'Delete for everyone', title: 'Delete for everyone', onclick: () => deleteMessage(m) }, icon('trash', 14)) : null;
  return el('div', { class: `bubble ${mine ? 'mine' : 'theirs'}${fresh ? ' enter' : ''}${res.error ? ' failed' : ''}`, dataset: { id: String(m.id || m.client_msg_id) } },
    !mine && conv.kind === 'group' ? el('div', { class: 'author', text: m.sender_name || m.sender_username }) : null,
    body, meta, actions);
}

function renderMessages(scrollBottom = false) {
  const host = $('messages'), conv = state.convs.get(state.current);
  if (!conv) return;
  const list = state.messages.get(state.current) || [];
  const nearBottom = host.scrollHeight - host.scrollTop - host.clientHeight < 120;
  host.replaceChildren();
  if (state.hasMore) host.append(el('button', { class: 'btn btn-sm btn-ghost load-more', type: 'button', onclick: loadEarlier }, 'Load earlier messages'));
  if (!list.length) host.append(el('div', { class: 'thread-empty' }, icon('shield', 28),
    el('p', { text: 'Messages here are sealed on your device before they are sent. Say hello.' })));
  let lastDay = '';
  for (const m of list) {
    const iso = m.created_at || new Date(m.timestamp).toISOString(), day = fmtDay(iso);
    if (day !== lastDay) { host.append(el('div', { class: 'day', text: day })); lastDay = day; }
    host.append(bubble(m, conv, m._fresh)); m._fresh = false;
  }
  if (scrollBottom || nearBottom) host.scrollTop = host.scrollHeight;
}

async function loadEarlier() {
  const list = state.messages.get(state.current) || [];
  const first = list.find((m) => m.id);
  if (!first) return;
  const { messages } = await api('GET', `/api/conversations/${state.current}/messages?limit=50&before_id=${first.id}`);
  state.hasMore = messages.length >= 50;
  state.messages.set(state.current, [...(await hydrate(messages)), ...list]);
  renderMessages();
}

async function markRead(convId) {
  const conv = state.convs.get(convId);
  const ids = (state.messages.get(convId) || []).filter((m) => m.id && m.sender_id !== me.id && !m.deleted && !m.read_by_me).map((m) => m.id);
  if (!ids.length) { if (conv && conv.unread) { conv.unread = 0; renderList(); } return; }
  try { await api('POST', '/api/receipts', { message_ids: ids, status: 'read' }); } catch { return; }
  (state.messages.get(convId) || []).forEach((m) => { if (ids.includes(m.id)) m.read_by_me = true; });
  if (conv) { conv.unread = 0; renderList(); }
}

// ------------------------------------------------------------------ sending
async function recipientsFor(convId) {
  const { keys } = await api('GET', `/api/conversations/${convId}/recipients`);
  const out = [], conv = state.convs.get(convId);
  for (const k of keys) {
    const encPub = b64d(k.enc_pub, 32), signPub = b64d(k.sign_pub, 32);
    const fp = await fingerprint(encPub, signPub);
    if (fp !== k.fingerprint) continue;                     // inconsistent key record: do not encrypt to it
    checkPin(k.user_id, fp, conv?.members.find((m) => m.id === k.user_id)?.display_name);
    out.push({ keyId: k.id, encPub });
  }
  const missing = (conv?.members || []).filter((m) => m.id !== me.id && !keys.some((k) => k.user_id === m.id));
  if (conv?.kind === 'direct' && missing.length) {
    throw new Error(`${missing[0].display_name} has not opened Sealed yet, so there is nothing to encrypt to. Ask them to sign in once, then try again.`);
  }
  if (missing.length) toast(`${missing.map((m) => m.display_name).join(', ')} can't read this message yet because they have not opened Sealed.`, 'warn', 8000);
  return out;
}

async function sendText(text) {
  const convId = state.current, conv = state.convs.get(convId);
  const clientMsgId = crypto.randomUUID();
  const pending = { client_msg_id: clientMsgId, conversation_id: convId, sender_id: me.id, sender_name: me.name, timestamp: Date.now(),
    pending: true, deleted: false, delivered_count: 0, read_count: 0, recipient_count: Math.max(conv.members.length - 1, 0),
    _res: { payload: { t: 'text', body: text } }, _fresh: true };
  const list = state.messages.get(convId) || []; list.push(pending); state.messages.set(convId, list);
  renderMessages(true);
  try {
    let saved;
    for (let attempt = 0; attempt < 2 && !saved; attempt++) {
      const msg = await encryptMessage({
        conversationId: convId, clientMsgId, timestamp: Date.now(), payload: { t: 'text', body: text },
        sender: { keyId: state.identity.keyId, sPriv: state.identity.sPriv }, recipients: await recipientsFor(convId),
      });
      try { saved = (await api('POST', `/api/conversations/${convId}/messages`, msg)).message; }
      catch (e) { if (!(e.code === 'stale_recipients' && attempt === 0)) throw e; }
    }
    absorb(saved, { payload: { t: 'text', body: text } });
  } catch (e) {
    state.messages.set(convId, (state.messages.get(convId) || []).filter((m) => m.client_msg_id !== clientMsgId));
    renderMessages();
    $('composer-input').value = text;
    toast(`Message not sent: ${e.message}`, 'error');
  }
}

// merge a server message into local state (replaces the optimistic copy)
function absorb(msg, knownResult) {
  const list = state.messages.get(msg.conversation_id) || [];
  const idx = list.findIndex((m) => m.client_msg_id === msg.client_msg_id);
  msg._res = knownResult || msg._res;
  msg._fresh = idx === -1;
  if (idx >= 0) list[idx] = msg; else if (!list.some((m) => m.id === msg.id)) list.push(msg);
  state.messages.set(msg.conversation_id, list);
  const conv = state.convs.get(msg.conversation_id);
  if (conv) { conv.last_message = msg; conv.last_activity = msg.created_at; }
  if (state.current === msg.conversation_id) renderMessages(true);
  return msg;
}

async function deleteMessage(m) {
  if (!window.confirm('Delete this message for everyone? The encrypted copy is erased from the server.')) return;
  try { await api('DELETE', `/api/messages/${m.id}`); } catch (e) { toast(e.message, 'error'); }
}

// ------------------------------------------------------------------ sockets
function connectSocket() {
  const socket = (state.socket = window.io({ withCredentials: true }));
  socket.on('connect_error', async () => { try { await api('GET', '/api/me'); } catch { /* redirected */ } });

  socket.on('message:new', async ({ message }) => {
    message._res = await decrypt(message);
    const known = state.convs.has(message.conversation_id);
    if (!known) await loadConversations();
    absorb(message, message._res);
    const conv = state.convs.get(message.conversation_id);
    if (!conv) return;
    conv._preview = await previewOf(conv);
    const incoming = message.sender_id !== me.id;
    if (incoming) {
      const open = state.current === conv.id && document.visibilityState === 'visible';
      if (open) markRead(conv.id);
      else { conv.unread = (conv.unread || 0) + 1; api('POST', '/api/receipts', { message_ids: [message.id], status: 'delivered' }).catch(() => {}); }
      if (!open && document.visibilityState === 'hidden') toast(`New encrypted message from ${message.sender_name}`, 'info', 3000);
    }
    renderList();
  });
  socket.on('message:deleted', ({ conversation_id, message_id }) => {
    const m = (state.messages.get(conversation_id) || []).find((x) => x.id === message_id);
    if (m) { m.deleted = true; m._res = { deleted: true }; }
    const conv = state.convs.get(conversation_id);
    if (conv && conv.last_message && conv.last_message.id === message_id) { conv.last_message.deleted = true; conv.last_message._res = { deleted: true }; previewOf(conv).then((p) => { conv._preview = p; renderList(); }); }
    if (state.current === conversation_id) renderMessages();
  });
  socket.on('receipt:update', ({ conversation_id }) => { if (state.current === conversation_id) refreshCounts(); });
  socket.on('presence:update', ({ user_id, online, last_seen_at }) => {
    state.convs.forEach((c) => c.members.forEach((m) => { if (m.id === user_id) { m.online = online; if (last_seen_at) m.last_seen_at = last_seen_at; } }));
    renderList();
    if (state.current) renderHeader(state.convs.get(state.current));
  });
  socket.on('typing', ({ conversation_id, user_id, typing }) => {
    if (!state.typing.has(conversation_id)) state.typing.set(conversation_id, new Map());
    const t = state.typing.get(conversation_id);
    if (typing) t.set(user_id, Date.now() + 4000); else t.delete(user_id);
    renderList();
    if (state.current === conversation_id) renderHeader(state.convs.get(conversation_id));
    setTimeout(() => { renderList(); if (state.current === conversation_id) renderHeader(state.convs.get(conversation_id)); }, 4100);
  });
  socket.on('conversation:updated', debounce(() => loadConversations().then(() => { if (state.current) renderHeader(state.convs.get(state.current)); }), 300));
  socket.on('security:alert', ({ detail, severity }) => toast(detail || 'Security alert', severity === 'info' ? 'info' : 'warn', 9000));
}

const refreshCounts = debounce(async () => {
  const id = state.current; if (!id) return;
  const { messages } = await api('GET', `/api/conversations/${id}/messages?limit=100`);
  const local = state.messages.get(id) || [];
  for (const fresh of messages) {
    const m = local.find((x) => x.id === fresh.id);
    if (m) { m.delivered_count = fresh.delivered_count; m.read_count = fresh.read_count; m.recipient_count = fresh.recipient_count; }
  }
  renderMessages();
}, 300);

// ------------------------------------------------------------------ composer
let lastTypingSent = 0, typingTimer = null;
function wireComposer() {
  const input = $('composer-input');
  const send = () => {
    const text = input.value.trim();
    if (!text || !state.current) return;
    input.value = ''; autosize(); stopTyping();
    sendText(text);
  };
  $('composer').addEventListener('submit', (e) => { e.preventDefault(); send(); });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
  input.addEventListener('input', () => {
    autosize();
    const now = Date.now();
    if (state.socket && state.current && now - lastTypingSent > 2500) { lastTypingSent = now; state.socket.emit('typing', { conversation_id: state.current, typing: true }); }
    clearTimeout(typingTimer); typingTimer = setTimeout(stopTyping, 3000);
  });
  function autosize() { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 160)}px`; }
  function stopTyping() { clearTimeout(typingTimer); if (state.socket && state.current && lastTypingSent) { state.socket.emit('typing', { conversation_id: state.current, typing: false }); lastTypingSent = 0; } }
}

// ------------------------------------------------------------------ modals
const modal = (id) => window.bootstrap.Modal.getOrCreateInstance($(id));

function userResults(host, query, onPick, exclude = []) {
  host.replaceChildren();
  if (query.length < 2) { host.append(el('p', { class: 'hint', text: 'Type at least 2 characters of a username or name.' })); return; }
  api('GET', `/api/users/search?q=${encodeURIComponent(query)}`).then(({ users }) => {
    host.replaceChildren();
    const rows = users.filter((u) => !exclude.includes(u.id));
    if (!rows.length) host.append(el('p', { class: 'hint', text: 'No one found.' }));
    rows.forEach((u) => host.append(el('button', { type: 'button', class: 'person', onclick: () => onPick(u) },
      avatar(u.display_name, u.id, u.online, 36),
      el('div', {}, el('div', { class: 'name', text: u.display_name }), el('div', { class: 'handle', text: `@${u.username}` })))));
  }).catch((e) => host.append(el('p', { class: 'hint error', text: e.message })));
}

function openNewChat(prefill = '') {
  const input = $('newchat-q'), host = $('newchat-results');
  input.value = prefill;
  userResults(host, prefill, startDirect);
  modal('newChatModal').show();
}
async function startDirect(user) {
  try {
    const { conversation } = await api('POST', '/api/conversations', { type: 'direct', user_id: user.id });
    modal('newChatModal').hide();
    await loadConversations();
    openConv(conversation.id);
  } catch (e) { toast(e.message, 'error'); }
}

const groupDraft = new Map();
function renderGroupChips() {
  const chips = $('group-chips'); chips.replaceChildren();
  groupDraft.forEach((u) => chips.append(el('button', { type: 'button', class: 'chip', onclick: () => { groupDraft.delete(u.id); renderGroupChips(); } }, `${u.display_name} ×`)));
}
function openNewGroup() {
  groupDraft.clear(); renderGroupChips();
  $('group-name').value = ''; $('group-q').value = ''; $('group-results').replaceChildren();
  modal('newGroupModal').show();
}
async function createGroup() {
  try {
    const { conversation } = await api('POST', '/api/conversations', { type: 'group', name: $('group-name').value, member_ids: [...groupDraft.keys()] });
    modal('newGroupModal').hide();
    await loadConversations();
    openConv(conversation.id);
  } catch (e) { toast(e.message, 'error'); }
}

async function openInfo(convId) {
  const conv = state.convs.get(convId); if (!conv) return;
  const body = $('info-body'), admin = conv.my_role === 'admin';
  body.replaceChildren(el('div', { class: 'loading', text: 'Loading safety numbers…' }));
  modal('infoModal').show();
  $('info-title').textContent = convName(conv);
  const { keys } = await api('GET', `/api/conversations/${convId}/recipients`);
  const draw = async () => {
    body.replaceChildren();
    body.append(el('h3', { class: 'h6', text: conv.kind === 'group' ? `Members (${conv.members.length})` : 'Safety numbers' }));
    for (const m of conv.members) {
      const mkeys = keys.filter((k) => k.user_id === m.id);
      const row = el('div', { class: 'member' },
        el('div', { class: 'member-head' }, avatar(m.display_name, m.id, m.online, 32),
          el('div', { class: 'grow' }, el('div', { class: 'name', text: m.display_name + (m.id === me.id ? ' (you)' : '') }), el('div', { class: 'handle', text: `@${m.username}${m.role === 'admin' ? ' · admin' : ''}` })),
          conv.kind === 'group' && admin && m.id !== me.id ? el('div', { class: 'member-actions' },
            el('button', { class: 'btn btn-sm btn-ghost', type: 'button', onclick: async () => { await api('POST', `/api/conversations/${convId}/members/${m.id}/role`, { role: m.role === 'admin' ? 'member' : 'admin' }).catch((e) => toast(e.message, 'error')); await loadConversations(); openInfo(convId); } }, m.role === 'admin' ? 'Remove admin' : 'Make admin'),
            el('button', { class: 'btn btn-sm btn-ghost danger', type: 'button', onclick: async () => { await api('DELETE', `/api/conversations/${convId}/members/${m.id}`).catch((e) => toast(e.message, 'error')); await loadConversations(); openInfo(convId); } }, 'Remove')) : null));
      for (const k of mkeys) {
        const fp = await fingerprint(b64d(k.enc_pub, 32), b64d(k.sign_pub, 32));
        const mine = m.id === me.id && k.id === state.identity.keyId;
        row.append(el('div', { class: 'fp' },
          el('code', { text: prettyFingerprint(fp) }),
          el('div', { class: 'fp-foot' }, el('span', { text: mine ? 'This device' : `Device key #${k.id}` }),
            m.id !== me.id ? el('label', { class: 'form-check form-switch m-0' },
              el('input', { class: 'form-check-input', type: 'checkbox', checked: isVerified(fp), onchange: (e) => { setVerified(fp, e.target.checked); } }),
              el('span', { class: 'form-check-label', text: 'Verified' })) : null)));
      }
      body.append(row);
    }
    if (conv.kind === 'group') {
      if (admin) {
        const q = el('input', { class: 'form-control', placeholder: 'Add someone by username', 'aria-label': 'Add member' }), res = el('div', { class: 'results' });
        q.addEventListener('input', debounce(() => userResults(res, q.value.trim(), async (u) => {
          await api('POST', `/api/conversations/${convId}/members`, { user_id: u.id }).catch((e) => toast(e.message, 'error'));
          await loadConversations(); openInfo(convId);
        }, conv.members.map((m) => m.id)), 250));
        body.append(el('h3', { class: 'h6 mt-3', text: 'Add member' }), q, res);
      }
      body.append(el('button', { class: 'btn btn-outline-danger btn-sm mt-3', type: 'button', onclick: async () => {
        if (!window.confirm('Leave this group?')) return;
        await api('DELETE', `/api/conversations/${convId}/members/${me.id}`).catch((e) => toast(e.message, 'error'));
        modal('infoModal').hide(); await loadConversations(); closeThread();
      } }, 'Leave group'));
    }
    body.append(el('p', { class: 'hint mt-3', text: 'Compare these numbers with the other person in person or over a call. If they match, no one is intercepting your messages.' }));
  };
  await draw();
}

// ------------------------------------------------------------------ boot
async function boot() {
  wireComposer();
  $('search').addEventListener('input', renderList);
  $('btn-new-chat').addEventListener('click', () => openNewChat());
  $('btn-new-group').addEventListener('click', openNewGroup);
  $('newchat-q').addEventListener('input', debounce(() => userResults($('newchat-results'), $('newchat-q').value.trim(), startDirect), 250));
  $('group-q').addEventListener('input', debounce(() => userResults($('group-results'), $('group-q').value.trim(), (u) => { groupDraft.set(u.id, u); renderGroupChips(); }, [me.id, ...groupDraft.keys()]), 250));
  $('group-create').addEventListener('click', createGroup);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && state.current) markRead(state.current); });
  try {
    await ensureDevice();
    $('key-fp').textContent = shortFp(state.identity.fingerprint);
    $('key-status').classList.add('ok');
    await loadConversations();
    connectSocket();
  } catch (e) {
    $('key-status').classList.add('bad');
    toast(`Could not set up encryption on this device: ${e.message}`, 'error', 12000);
  }
}
boot();