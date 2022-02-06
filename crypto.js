/* 
    Selection and call semplification for usefull crypto functions.
    For parameters details see:
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    https://stackoverflow.com/questions/17218089/salt-and-hash-using-pbkdf2
*/

// Imports
const crypto = require('crypto');
const util = require('util');

// KDF params
const PBKDF2_ITERATIONS = 310000;
const PBKDF2_SALT_LEN = 32; // bytes
const PBKDF2_KEY_LEN = 64; // bytes
const PBKDF2_DIGEST = 'sha256';

// Symmetric enc params
const AES_256_GCM = 'aes-256-gcm';
const AES_IV_LEN = 16; // bytes
const AES_KEY_LEN = 32; // bytes
const AES_IN_ENCODING = 'utf8';
const AES_OUT_ENCODING = 'base64';


// Module exports
module.exports = {
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_LEN,
    PBKDF2_KEY_LEN,
    PBKDF2_DIGEST,
    AES_IV_LEN,
    AES_KEY_LEN,
    randomBytesProm,
    randomSalt,
    pbkdf2,
    pbkdf2Verify,
    aes256gcmEnc,
    aes256gcmDec
};

/**
 * Generates an array of random bytes of length len.
 * @param {int} len number of bytes that must be returned
 * @returns a Promise returning an array of random bytes of given length
 */
async function randomBytesProm(len) {
    const randBytes = util.promisify(crypto.randomBytes);
    return await randBytes(len);
}


/**
 * Generates a random string of length saltlen.
 * @param {int} saltlen length of salt
 * @returns a Promise returning a random string of length saltlen
 */
async function randomSalt(saltlen = PBKDF2_SALT_LEN) {
    if (saltlen % 2 != 0) throw Error("saltlen must be even (the returned string is in hex format)");
    let bytes = await randomBytesProm(saltlen / 2); // every byte will be represented with 2 bytes for string conversion
    return bytes.toString('hex');
}

/**
 * Computes the derived key using pbkdf2 implementation contained in crypto package.
 * @param {string} plain the plaintext
 * @param {string} salt the salt
 * @param {int} iterations number of pbkdf2 iterations
 * @param {int} keylen length of the derived key
 * @param {string} digest ID of the digest algorithm (e.g. 'sha256'). If not specified is set to @PBKDF2_DIGEST
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

async function aes256gcmEnc(plaintext, key, iv = null) {
    if (iv === null) {
        iv = await randomBytesProm(AES_IV_LEN);
    }
    const cipher = crypto.createCipheriv(AES_256_GCM, key, iv);
    let enc = cipher.update(plaintext, AES_IN_ENCODING, AES_OUT_ENCODING);
    enc += cipher.final(AES_OUT_ENCODING);
    return {
        ciphertext: enc,
        iv: iv,
        authTag: cipher.getAuthTag()
    };
}

function aes256gcmDec(ciphertext, key, iv, authTag) {
    const decipher = crypto.createDecipheriv(AES_256_GCM, key, iv);
    decipher.setAuthTag(authTag);
    let plain = decipher.update(ciphertext, AES_OUT_ENCODING, AES_IN_ENCODING);
    plain += decipher.final(AES_IN_ENCODING);
    return plain;
}