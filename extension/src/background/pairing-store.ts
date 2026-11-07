// The pairing with the desktop app: its id and the non-extractable pairing key
// (an HKDF CryptoKey), in IndexedDB, which can hold a CryptoKey without ever
// exposing its bytes (design 3.3). Nothing else is stored here, and this is the
// only IndexedDB use in the extension.

const DB = "ciphermoth";
const STORE = "pairing";
const KEY = "desktop";

export interface Pairing {
  id: string;
  key: CryptoKey;
}

const database = (): Promise<IDBDatabase> =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

const run = async <T>(
  mode: IDBTransactionMode,
  work: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> => {
  const db = await database();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = work(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally {
    db.close();
  }
};

export const loadPairing = async (): Promise<Pairing | null> => {
  const value = (await run("readonly", (store) => store.get(KEY))) as Partial<Pairing> | undefined;
  if (!value || typeof value.id !== "string" || !(value.key instanceof CryptoKey)) return null;
  return { id: value.id, key: value.key };
};

export const savePairing = (pairing: Pairing): Promise<IDBValidKey> =>
  run("readwrite", (store) => store.put({ id: pairing.id, key: pairing.key }, KEY));

export const deletePairing = (): Promise<undefined> =>
  run("readwrite", (store) => store.delete(KEY));
