/* 
    Selection and call semplification for usefull crypto functions.
    For parameters details see:
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    https://stackoverflow.com/questions/17218089/salt-and-hash-using-pbkdf2
*/

// Imports
const {
    randomBytes,
    pbkdf2Sync
} = require('crypto');
const util = require('util');

// Crypto params
const PBKDF2_ITERATIONS = 310000;
const PBKDF2_SALT_LEN = 32; // bytes
const PBKDF2_KEY_LEN = 64; // bytes
const PBKDF2_DIGEST = 'sha256';

// Module exports
module.exports = {
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    PBKDF2_SALT_LEN : PBKDF2_SALT_LEN,
    PBKDF2_KEY_LEN: PBKDF2_KEY_LEN,
    PBKDF2_DIGEST: PBKDF2_DIGEST,
    randomSalt: randomSalt,
    pbkdf2: pbkdf2,
    pbkdf2Verify
};


/**
 * Generates a random string of length saltlen.
 * @param {*} saltlen 
 * @returns a Promise returning a random string of length saltlen
 */
async function randomSalt(saltlen = PBKDF2_SALT_LEN) {
    if (saltlen % 2 != 0) throw Error("saltlen must be even (the returned string is in hex format)");
    const randBytes = util.promisify(randomBytes);
    var bytes = await randBytes(saltlen / 2); // every byte will be represented with 2 bytes for string conversion
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
    var key = pbkdf2Sync(plain, salt, iterations, keylen, digest);
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
    var key = pbkdf2Sync(plain, salt, iterations, keylen, digest);
    return key.toString('hex') == hexhash;
}
