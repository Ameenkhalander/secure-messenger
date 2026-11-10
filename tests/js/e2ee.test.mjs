// Run with: node --test tests/js     (Node 20+)
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateIdentity, encryptMessage, decryptMessage, fingerprint, b64e } from '../../app/static/js/e2ee.js';

async function setup() {
  const alice = await generateIdentity(), bob = await generateIdentity(), eve = await generateIdentity();
  const msg = await encryptMessage({
    conversationId: 5, clientMsgId: 'msg-0001-abcdef', timestamp: Date.now(),
    payload: { t: 'text', body: 'héllo 🌍 secret' },
    sender: { keyId: 1, sPriv: alice.sPriv },
    recipients: [{ keyId: 1, encPub: alice.encPub }, { keyId: 2, encPub: bob.encPub }],
  });
  return { alice, bob, eve, msg };
}
const open = (msg, who, keyId, from) => decryptMessage(msg, { myKeyId: keyId, xPriv: who.xPriv, encPub: who.encPub, senderSignPub: from.signPub });

test('recipient and sender can decrypt', async () => {
  const { alice, bob, msg } = await setup();
  assert.equal((await open(msg, bob, 2, alice)).body, 'héllo 🌍 secret');
  assert.equal((await open(msg, alice, 1, alice)).body, 'héllo 🌍 secret');
});
test('ciphertext does not contain plaintext', async () => {
  const { msg } = await setup();
  assert.ok(!JSON.stringify(msg).includes('secret'));
});
test('modified ciphertext is rejected', async () => {
  const { alice, bob, msg } = await setup();
  const raw = Buffer.from(msg.ciphertext, 'base64'); raw[3] ^= 1;
  await assert.rejects(open({ ...msg, ciphertext: raw.toString('base64') }, bob, 2, alice), /invalid signature/);
});
test('modified envelope is rejected', async () => {
  const { alice, bob, msg } = await setup();
  const envs = structuredClone(msg.envelopes); const w = Buffer.from(envs[1].w, 'base64'); w[0] ^= 1; envs[1].w = w.toString('base64');
  await assert.rejects(open({ ...msg, envelopes: envs }, bob, 2, alice), /invalid signature/);
});
test('forged sender is rejected', async () => {
  const { eve, bob, msg } = await setup();
  await assert.rejects(open(msg, bob, 2, eve), /invalid signature/);
});
test('non-recipient cannot decrypt', async () => {
  const { alice, eve, msg } = await setup();
  await assert.rejects(open(msg, eve, 3, alice), /no envelope/);
  await assert.rejects(open(msg, eve, 2, alice), /decryption failed/);
});
test('context binding: changed conversation id fails', async () => {
  const { alice, bob, msg } = await setup();
  await assert.rejects(open({ ...msg, conversation_id: 6 }, bob, 2, alice), /invalid signature/);
});
test('fingerprint is stable 64 hex chars', async () => {
  const a = await generateIdentity();
  const f = await fingerprint(a.encPub, a.signPub);
  assert.match(f, /^[0-9a-f]{64}$/);
});
test('private keys are non-extractable', async () => {
  const a = await generateIdentity();
  assert.equal(a.xPriv.extractable, false); assert.equal(a.sPriv.extractable, false);
});
// Cross-language: prints a message for tests/test_crypto.py (reads JSON from stdin when interop mode is on)
if (process.env.E2EE_INTEROP_OUT) {
  test('emit interop vector', async () => {
    const { writeFileSync } = await import('node:fs');
    const alice = await generateIdentity(), bob = await generateIdentity();
    const msg = await encryptMessage({ conversationId: 9, clientMsgId: 'interop-12345678', timestamp: 1700000000000,
      payload: { t: 'text', body: 'from javascript' }, sender: { keyId: 10, sPriv: alice.sPriv },
      recipients: [{ keyId: 11, encPub: bob.encPub }] });
    writeFileSync(process.env.E2EE_INTEROP_OUT, JSON.stringify({ msg, signPub: b64e(alice.signPub) }));
  });
}
// Cross-language: decrypt a message produced by the Python reference implementation.
if (process.env.E2EE_PY_VECTOR) {
  test('JS decrypts a message encrypted by Python', async () => {
    const { readFileSync } = await import('node:fs');
    const { b64d } = await import('../../app/static/js/e2ee.js');
    const v = JSON.parse(readFileSync(process.env.E2EE_PY_VECTOR, 'utf8'));
    const xPriv = await crypto.subtle.importKey('pkcs8', b64d(v.enc_priv_pkcs8), { name: 'X25519' }, false, ['deriveBits']);
    const out = await decryptMessage(v.msg, { myKeyId: v.key_id, xPriv, encPub: b64d(v.enc_pub), senderSignPub: b64d(v.sign_pub) });
    assert.equal(out.body, 'from python ✓');
  });
}
