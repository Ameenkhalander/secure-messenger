// E2EE-v1 client protocol (WebCrypto). Mirrors app/security/e2ee_protocol.py byte for byte.
// Pure module: no DOM, no storage. Works in browsers and in Node 20+ (for tests).
const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();
const PAD_BLOCK = 128;

export class E2EEError extends Error {}

// ---------- encoding ----------
export function b64e(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64d(str, length) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(str)) throw new E2EEError('invalid base64');
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (length !== undefined && out.length !== length) throw new E2EEError('bad length');
  return out;
}
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export function encodeFields(fields) {
  const parts = [];
  for (const f of fields) {
    const raw = f instanceof Uint8Array ? f : te.encode(String(f));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, raw.length, false);
    parts.push(len, raw);
  }
  return concat(...parts);
}
const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const sha256 = async (data) => new Uint8Array(await subtle.digest('SHA-256', data));
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');

function pad(data) {
  const frame = new Uint8Array(4 + data.length);
  new DataView(frame.buffer).setUint32(0, data.length, false);
  frame.set(data, 4);
  const total = Math.ceil(frame.length / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(total);
  out.set(frame);
  return out;
}
function unpad(frame) {
  if (frame.length < 4 || frame.length % PAD_BLOCK) throw new E2EEError('bad frame');
  const n = new DataView(frame.buffer, frame.byteOffset, frame.length).getUint32(0, false);
  if (n > frame.length - 4) throw new E2EEError('bad frame length');
  return frame.subarray(4, 4 + n);
}

// ---------- keys ----------
// Private keys are generated NON-extractable: not even this page's JavaScript can export them.
export async function generateIdentity() {
  const x = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const s = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const encPub = new Uint8Array(await subtle.exportKey('raw', x.publicKey));
  const signPub = new Uint8Array(await subtle.exportKey('raw', s.publicKey));
  return { xPriv: x.privateKey, sPriv: s.privateKey, encPub, signPub };
}
export async function fingerprint(encPub, signPub) {
  return hex(await sha256(concat(te.encode('E2EE-FP-v1'), encPub, signPub)));
}
export const prettyFingerprint = (h) => (h.match(/.{1,4}/g) || []).join(' ');
export async function registrationProof(identity) {
  return b64e(new Uint8Array(await subtle.sign('Ed25519', identity.sPriv,
    encodeFields(['E2EE-KEY-REG-v1', identity.encPub, identity.signPub]))));
}
export async function rotationProof(oldSignPriv, newIdentity) {
  return b64e(new Uint8Array(await subtle.sign('Ed25519', oldSignPriv,
    encodeFields(['E2EE-KEY-ROTATE-v1', newIdentity.encPub, newIdentity.signPub]))));
}

// ---------- signing ----------
async function envelopesDigest(envelopes) {
  const parts = [];
  [...envelopes].sort((a, b) => Number(a.k) - Number(b.k)).forEach((e) => {
    parts.push(String(Number(e.k)), b64d(e.epk), b64d(e.n), b64d(e.w));
  });
  return sha256(encodeFields(parts));
}
async function signingBytes(m, nonce, ct) {
  return encodeFields(['E2EE-SIG-v1', m.conversation_id, m.client_msg_id, m.sender_key_id,
    m.timestamp, nonce, ct, await envelopesDigest(m.envelopes)]);
}
const contentAad = (m) => encodeFields(['E2EE-AAD-v1', m.conversation_id, m.client_msg_id, m.sender_key_id, m.timestamp]);

async function wrapKey(sharedBits, ephPub, recipPub, m, keyId) {
  const ikm = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: concat(ephPub, recipPub),
    info: encodeFields(['E2EE-WRAP-v1', m.conversation_id, m.client_msg_id, keyId]),
  }, ikm, 256);
  return subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
const wrapAad = (m, keyId) => encodeFields(['E2EE-WRAPAAD-v1', m.client_msg_id, keyId]);

// ---------- encrypt / decrypt ----------
// recipients: [{keyId, encPub: Uint8Array}], sender: {keyId, sPriv: CryptoKey}
export async function encryptMessage({ conversationId, clientMsgId, timestamp, payload, sender, recipients }) {
  const msg = { conversation_id: conversationId, client_msg_id: clientMsgId, timestamp, sender_key_id: sender.keyId };
  const cekRaw = rand(32);
  const nonce = rand(12);
  const cek = await subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['encrypt']);
  const frame = pad(te.encode(JSON.stringify(payload)));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: contentAad(msg) }, cek, frame));
  const envelopes = [];
  for (const r of recipients) {
    const eph = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
    const rPub = await subtle.importKey('raw', r.encPub, { name: 'X25519' }, true, []);
    const shared = await subtle.deriveBits({ name: 'X25519', public: rPub }, eph.privateKey, 256);
    const wk = await wrapKey(shared, ephPub, r.encPub, msg, r.keyId);
    const wn = rand(12);
    const wrapped = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: wn, additionalData: wrapAad(msg, r.keyId) }, wk, cekRaw));
    envelopes.push({ k: r.keyId, epk: b64e(ephPub), n: b64e(wn), w: b64e(wrapped) });
  }
  msg.nonce = b64e(nonce);
  msg.ciphertext = b64e(ct);
  msg.envelopes = envelopes;
  msg.signature = b64e(new Uint8Array(await subtle.sign('Ed25519', sender.sPriv, await signingBytes(msg, nonce, ct))));
  return msg;
}

export async function verifyMessage(msg, senderSignPub) {
  try {
    const key = await subtle.importKey('raw', senderSignPub, { name: 'Ed25519' }, true, ['verify']);
    return await subtle.verify('Ed25519', key, b64d(msg.signature, 64),
      await signingBytes(msg, b64d(msg.nonce, 12), b64d(msg.ciphertext)));
  } catch { return false; }
}

// Verify the signature FIRST; only then touch any ciphertext.
export async function decryptMessage(msg, { myKeyId, xPriv, encPub, senderSignPub }) {
  if (!(await verifyMessage(msg, senderSignPub))) throw new E2EEError('invalid signature');
  const env = msg.envelopes.find((e) => Number(e.k) === Number(myKeyId));
  if (!env) throw new E2EEError('no envelope for this device');
  try {
    const ephPub = b64d(env.epk, 32);
    const ephKey = await subtle.importKey('raw', ephPub, { name: 'X25519' }, true, []);
    const shared = await subtle.deriveBits({ name: 'X25519', public: ephKey }, xPriv, 256);
    const wk = await wrapKey(shared, ephPub, encPub, msg, myKeyId);
    const cekRaw = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(env.n, 12), additionalData: wrapAad(msg, myKeyId) }, wk, b64d(env.w, 48)));
    const cek = await subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['decrypt']);
    const frame = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: b64d(msg.nonce, 12), additionalData: contentAad(msg) }, cek, b64d(msg.ciphertext)));
    return JSON.parse(td.decode(unpad(frame)));
  } catch (err) {
    if (err instanceof E2EEError) throw err;
    throw new E2EEError('decryption failed');
  }
}
