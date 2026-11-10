// Device key storage. Private keys are non-extractable CryptoKey objects persisted in
// IndexedDB via structured clone: this page's JavaScript can USE them but can never read the bytes.
const DB_NAME = 'sealed-keys';
const STORE = 'identities';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const s = req.result.createObjectStore(STORE, { keyPath: 'keyId' });
      s.createIndex('userId', 'userId');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function run(mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const req = fn(tx.objectStore(STORE));
    tx.oncomplete = () => { db.close(); resolve(req && req.result); };
    tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
  });
}

export const putIdentity = (rec) => run('readwrite', (s) => s.put(rec));
export const getForUser = (userId) => run('readonly', (s) => s.index('userId').getAll(userId));
export async function deactivateAll(userId) {
  for (const rec of (await getForUser(userId)) || []) if (rec.active) await putIdentity({ ...rec, active: false });
}
export async function deleteForUser(userId) {
  for (const rec of (await getForUser(userId)) || []) await run('readwrite', (s) => s.delete(rec.keyId));
}
