import { api } from './api.js';
import { toast } from './dom.js';
import { b64d, b64e, fingerprint, generateIdentity, registrationProof, rotationProof } from './e2ee.js';
import * as keystore from './keystore.js';

const root = document.getElementById('security');
const userId = Number(root.dataset.userId);
const status = document.getElementById('local-status');

async function inspectThisBrowser() {
  let local = [];
  try { local = (await keystore.getForUser(userId)) || []; } catch { /* IndexedDB unavailable */ }
  const activeIds = new Set(local.filter((r) => r.active).map((r) => r.keyId));
  let found = false;
  for (const row of document.querySelectorAll('[data-key-id]')) {
    const keyId = Number(row.dataset.keyId);
    const tag = row.querySelector('.local-tag');
    try {
      const fp = await fingerprint(b64d(row.dataset.encPub, 32), b64d(row.dataset.signPub, 32));
      const ok = fp === row.dataset.fingerprint;
      row.querySelector('.fp-check').textContent = ok ? 'Fingerprint recomputed in your browser: matches' : 'Fingerprint MISMATCH. Do not trust this key.';
      row.querySelector('.fp-check').classList.add(ok ? 'good' : 'bad');
    } catch { /* leave blank */ }
    if (activeIds.has(keyId)) { found = true; tag.hidden = false; row.dataset.local = '1'; }
  }
  status.textContent = found
    ? 'This browser holds the private keys for a registered device. They never leave it.'
    : 'This browser has no registered device key yet. Open the chat page to create one.';
  status.classList.add(found ? 'good' : 'warn');
  return local;
}

async function rotate(row) {
  const local = (await keystore.getForUser(userId)) || [];
  const old = local.find((r) => r.active && r.keyId === Number(row.dataset.keyId));
  if (!old) { toast('Rotate keys from the browser that owns this device.', 'warn'); return; }
  if (!window.confirm('Rotate encryption keys for this device? New messages use the new keys; old messages stay readable here.')) return;
  const id = await generateIdentity();
  const { device } = await api('POST', `/api/devices/${row.dataset.deviceId}/rotate`, {
    enc_pub: b64e(id.encPub), sign_pub: b64e(id.signPub), pop_sig: await registrationProof(id), prev_sig: await rotationProof(old.sPriv, id),
  });
  await keystore.putIdentity({ ...old, active: false });
  await keystore.putIdentity({
    keyId: device.key.id, userId, deviceId: device.id, xPriv: id.xPriv, sPriv: id.sPriv, encPub: b64e(id.encPub), signPub: b64e(id.signPub),
    fingerprint: await fingerprint(id.encPub, id.signPub), active: true, createdAt: Date.now(),
  });
  toast('Keys rotated.', 'success');
  setTimeout(() => window.location.reload(), 600);
}

root.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-action]'); if (!btn) return;
  const row = btn.closest('[data-id], [data-key-id]');
  try {
    switch (btn.dataset.action) {
      case 'revoke-session': {
        const r = await api('DELETE', `/api/sessions/${btn.dataset.id}`);
        window.location.href = r.signed_out_self ? '/login' : '/security'; break;
      }
      case 'revoke-others': await api('POST', '/api/sessions/revoke-others'); window.location.reload(); break;
      case 'ack-alerts': await api('POST', '/api/security/acknowledge'); window.location.reload(); break;
      case 'rotate-keys': await rotate(row); break;
      case 'revoke-device': {
        const isLocal = row.dataset.local === '1';
        if (!window.confirm(isLocal ? 'Remove THIS browser as a device? Its private keys are deleted and old messages here become unreadable.' : 'Remove this device? It will stop receiving new messages.')) return;
        await api('DELETE', `/api/devices/${btn.dataset.id}`);
        if (isLocal) await keystore.deleteForUser(userId);
        window.location.reload(); break;
      }
      default: break;
    }
  } catch (e) { toast(e.message, 'error'); }
});

inspectThisBrowser();
