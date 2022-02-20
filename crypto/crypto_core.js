/* 
    Selection and call semplification for usefull crypto primitives.
    For parameters details see:
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    https://stackoverflow.com/questions/17218089/salt-and-hash-using-pbkdf2
*/

// Imports
const crypto = require('crypto');

// KDF params
const PBKDF2_ITERATIONS = 310000;
const PBKDF2_SALT_LEN = 32; // bytes
const PBKDF2_KEY_LEN = 64; // bytes
const PBKDF2_DIGEST = 'sha256';

// AES params
const AES_256_GCM = 'aes-256-gcm';
const AES_IV_LEN = 16; // bytes
const AES_KEY_LEN = 32; // bytes
const AES_IN_ENCODING = 'utf8';
const AES_OUT_ENCODING = 'base64';

// Curve25519 DH params
const EC_DH_FUN = 'x25519';
const EC_DH_PUB_KEY_EXPORT_TYPE = 'spki';
const EC_DH_PUB_KEY_EXPORT_FORMAT = 'pem';


// Module exports
module.exports = {
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_LEN,
    PBKDF2_KEY_LEN,
    PBKDF2_DIGEST,
    AES_IV_LEN,
    AES_KEY_LEN,
    EC_DH_FUN,
    randomBytes,
    randomUUID,
    randomSalt,
    pbkdf2,
    pbkdf2Verify,
    aes256gcmEnc,
    aes256gcmEncWithIV,
    aes256gcmDec,
    x25519GenerateKeyPair,
    exportPubKey,
    importPubKey,
    x25519KeyAgree
};

function randomBytes(len) {
    return crypto.randomBytes(len);
}

function randomUUID() {
    return crypto.randomUUID();
}

/**
 * Generates a random string of length saltlen.
 * @param {int} saltlen length of salt
 * @returns a random string of length saltlen
 */
function randomSalt(saltlen = PBKDF2_SALT_LEN) {
    if (saltlen % 2 != 0) throw new Error("saltlen must be even (the returned string is in hex format)");
    let bytes = crypto.randomBytes(saltlen / 2); // every byte will be represented with 2 bytes for string conversion
    return bytes.toString('hex');
}

/**
 * Computes the derived key using pbkdf2 implementation contained in crypto package.
 * @param {string} plain the plaintext
 * @param {string} salt the salt
 * @param {int} iterations number of pbkdf2 iterations. If not specified is set to {@link PBKDF2_ITERATIONS}.
 * @param {int} keylen length of the derived key. If not specified is set to {@link PBKDF2_KEY_LEN}.
 * @param {string} digest ID of the digest algorithm (e.g. 'sha256'). If not specified is set to {@link PBKDF2_DIGEST}.
 * @returns {string} the derived pbkdf2 key as hex string
 */
function pbkdf2(plain, salt, iterations = PBKDF2_ITERATIONS, keylen = PBKDF2_KEY_LEN, digest = PBKDF2_DIGEST) {
    let key = crypto.pbkdf2Sync(plain, salt, iterations, keylen, digest);
    return key.toString('hex');
}

/**
 * Verifies a password matching it with the given derived key and salt.
 * @param {string} plain the plaintext to verify
 * @param {string} salt the salt
 * @param {string} hexhash the pbkdf2 derived key to match 
 * @param {int} iterations number of pbkdf2 iterations
 * @param {int} keylen length of the derived key
 * @param {string} digest ID of the digest algorithm (e.g. 'sha256'). If not specified is set to
 * @returns {bool} true if the verification has been successful
 */
function pbkdf2Verify(plain, salt, hexhash, iterations = PBKDF2_ITERATIONS, keylen = PBKDF2_KEY_LEN, digest = PBKDF2_DIGEST) {
    let key = crypto.pbkdf2Sync(plain, salt, iterations, keylen, digest);
    return key.toString('hex') == hexhash;
}

/**
 * Encrypts the given plaintext using AES-256-GCM algorithm.
 * @param {string} plaintext the plaintext to encrypt
 * @param {Buffer} key the AES-256 key. It must be 256-bit long
 * @param {Buffer} iv the instance vector
 * @returns an object with the following keys: "ciphertext" base64 string, "iv" Buffer, "authTag" Buffer.
 */
function aes256gcmEncWithIV(plaintext, key, iv) {
    let cipher = crypto.createCipheriv(AES_256_GCM, key, iv);
    let enc = cipher.update(plaintext, AES_IN_ENCODING, AES_OUT_ENCODING);
    enc += cipher.final(AES_OUT_ENCODING);
    return {
        ciphertext: enc,
        iv: iv,
        authTag: cipher.getAuthTag()
    };
}

/**
 * Encrypts the given plaintext using AES-256-GCM algorithm.
 * @param {string} plaintext the plaintext to encrypt
 * @param {Buffer} key the AES-256 key. It must be 256-bit long
 * @returns an object with the following keys: "ciphertext" base64 string, "iv" Buffer, "authTag" Buffer.
 */
function aes256gcmEnc(plaintext, key) {
    let iv = crypto.randomBytes(AES_IV_LEN);
    return aes256gcmEncWithIV(plaintext, key, iv);
}

/**
 * Decrypts the given ciphertext using AES-256-GCM algorithm.
 * @param {string} ciphertext ciphertext to decrypt expressed as base64 string
 * @param {Buffer} key the AES-256 key. It myst be 256-bit long
 * @param {Buffer} iv the instance vector
 * @param {Buffer} authTag the authentication tag
 * @returns the plaintext expressed as utf8 string
 */
function aes256gcmDec(ciphertext, key, iv, authTag) {
    let decipher = crypto.createDecipheriv(AES_256_GCM, key, iv);
    decipher.setAuthTag(authTag);
    let plain = decipher.update(ciphertext, AES_OUT_ENCODING, AES_IN_ENCODING);
    plain += decipher.final(AES_IN_ENCODING);
    return plain;
}

/**
 * @returns an x25519 key pair object
 */
function x25519GenerateKeyPair() {
    return crypto.generateKeyPairSync(EC_DH_FUN);
}

/**
 * @param {crypto.KeyObject} pubKey the public key to export
 * @returns a key export string of format {@link EC_DH_PUB_KEY_EXPORT_FORMAT} and type {@link EC_DH_PUB_KEY_EXPORT_TYPE}
 */
function exportPubKey(pubKey) {
    return pubKey.export({
        type: EC_DH_PUB_KEY_EXPORT_TYPE,
        format: EC_DH_PUB_KEY_EXPORT_FORMAT
    });
}

/**
 * @param {string} pubKeyExport a key export string to import
 * @returns the imported public key oject ( {@link crypto.KeyObject} )
 */
function importPubKey(pubKeyExport) {
    return crypto.createPublicKey(pubKeyExport);
}

/**
 * 
 * @param {crypto.KeyObject} privateKey the external private key
 * @param {crypto.KeyObject} publicKey the internal public key
 * @returns the Diffie-Hellman shared secret as {@link Buffer}
 */
function x25519KeyAgree(privateKey, publicKey) {
    return crypto.diffieHellman({
        publicKey: publicKey,
        privateKey: privateKey
    });
}