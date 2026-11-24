import sodium from "libsodium-wrappers-sumo";

export type Entry = {
  id: string;
  service: string;
  login: string;
  password: string;
};

const variant = () => sodium.base64_variants.ORIGINAL;
const context = "password-vault:v1";
export const ready = () => sodium.ready;

export function makeSalt(): string {
  return sodium.to_base64(sodium.randombytes_buf(16), variant());
}

export function deriveKey(master: string, salt: string): Uint8Array {
  return sodium.crypto_pwhash(
    32, master, sodium.from_base64(salt, variant()),
    3, 64 * 1024 * 1024, sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

export function encrypt(entries: Entry[], key: Uint8Array): string {
  const nonce = sodium.randombytes_buf(24);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    JSON.stringify(entries), context, null, nonce, key,
  );
  const packed = new Uint8Array(nonce.length + ciphertext.length);
  packed.set(nonce);
  packed.set(ciphertext, nonce.length);
  return sodium.to_base64(packed, variant());
}

export function decrypt(payload: string, key: Uint8Array): Entry[] {
  try {
    const packed = sodium.from_base64(payload, variant());
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, packed.slice(24), context, packed.slice(0, 24), key,
    );
    try {
      return JSON.parse(sodium.to_string(plaintext)) as Entry[];
    } finally {
      sodium.memzero(plaintext);
    }
  } catch {
    throw new Error("Phrase maîtresse incorrecte ou coffre endommagé.");
  }
}

export function generatePassword(): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%*-_";
  return Array.from(
    { length: 24 },
    () => alphabet[sodium.randombytes_uniform(alphabet.length)],
  ).join("");
}

export function wipe(key: Uint8Array) {
  sodium.memzero(key);
}