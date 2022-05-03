/* 
    Selection and call semplification for usefull crypto primitives.
    For parameters details see:
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    https://stackoverflow.com/questions/17218089/salt-and-hash-using-pbkdf2
*/

// Imports
import crypto from "crypto";

export abstract class CryptoCore {

    // KDF params
    static PBKDF2_ITERATIONS = 310000;
    static PBKDF2_SALT_LEN = 32; // bytes
    static PBKDF2_KEY_LEN = 64; // bytes
    static PBKDF2_DIGEST = 'sha256';

    // AES params
    static AES_256_GCM: crypto.CipherGCMTypes = 'aes-256-gcm';
    static AES_IV_LEN = 16; // bytes
    static AES_KEY_LEN = 32; // bytes
    static AES_IN_ENCODING: crypto.Encoding = 'utf8';
    static AES_OUT_ENCODING: crypto.Encoding = 'base64';

    // Curve25519 DH params
    static EC_DH_FUN: 'x25519' = 'x25519';
    static EC_DH_PUB_KEY_EXPORT_TYPE: 'spki' = 'spki';
    static EC_DH_PUB_KEY_EXPORT_FORMAT: 'pem' = 'pem';

    public static randomBytes(len: number): Buffer {
        return crypto.randomBytes(len);
    }
    
    public static randomUUID(): string {
        return crypto.randomUUID();
    }
    
    /**
     * Generates a random string of length saltlen.
     * @param {number} saltlen length of salt
     * @returns a random string of length saltlen
     */
    public static randomSalt(saltlen: number = this.PBKDF2_SALT_LEN): string {
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
    public static pbkdf2(plain: string, salt: string, iterations = this.PBKDF2_ITERATIONS, keylen = this.PBKDF2_KEY_LEN, digest = this.PBKDF2_DIGEST): string {
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
    public static pbkdf2Verify(plain: string, salt: string, hexhash: string, iterations = this.PBKDF2_ITERATIONS, keylen = this.PBKDF2_KEY_LEN, digest = this.PBKDF2_DIGEST): boolean {
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
    public static aes256gcmEncWithIV(plaintext: string, key: Buffer, iv: Buffer) {
        let cipher = crypto.createCipheriv(this.AES_256_GCM, key, iv);
        let enc = cipher.update(plaintext, this.AES_IN_ENCODING, this.AES_OUT_ENCODING);
        enc += cipher.final(this.AES_OUT_ENCODING);
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
    public static aes256gcmEnc(plaintext: string, key: Buffer) {
        let iv = crypto.randomBytes(this.AES_IV_LEN);
        return this.aes256gcmEncWithIV(plaintext, key, iv);
    }
    
    /**
     * Decrypts the given ciphertext using AES-256-GCM algorithm.
     * @param {string} ciphertext ciphertext to decrypt expressed as base64 string
     * @param {Buffer} key the AES-256 key. It myst be 256-bit long
     * @param {Buffer} iv the instance vector
     * @param {Buffer} authTag the authentication tag
     * @returns the plaintext expressed as utf8 string
     */
    public static aes256gcmDec(ciphertext: string, key: Buffer, iv: Buffer, authTag: Buffer): string {
        let decipher = crypto.createDecipheriv(this.AES_256_GCM, key, iv);
        decipher.setAuthTag(authTag);
        let plain = decipher.update(ciphertext, this.AES_OUT_ENCODING, this.AES_IN_ENCODING);
        plain += decipher.final(this.AES_IN_ENCODING);
        return plain;
    }
    
    /**
     * @returns an x25519 key pair object
     */
    public static x25519GenerateKeyPair() {
        return crypto.generateKeyPairSync(this.EC_DH_FUN);
    }
    
    /**
     * @param {crypto.KeyObject} pubKey the public key to export
     * @returns a key export string of format {@link EC_DH_PUB_KEY_EXPORT_FORMAT} and type {@link EC_DH_PUB_KEY_EXPORT_TYPE}
     */
    public static exportPubKey(pubKey: crypto.KeyObject): string {
        return pubKey.export({
            type: this.EC_DH_PUB_KEY_EXPORT_TYPE,
            format: this.EC_DH_PUB_KEY_EXPORT_FORMAT
        }).toString();
    }
    
    /**
     * @param {string} pubKeyExport a key export string to import
     * @returns the imported public key oject ( {@link crypto.KeyObject} )
     */
    public static importPubKey(pubKeyExport: string) {
        return crypto.createPublicKey(pubKeyExport);
    }
    
    /**
     * 
     * @param {crypto.KeyObject} privateKey the external private key
     * @param {crypto.KeyObject} publicKey the internal public key
     * @returns the Diffie-Hellman shared secret as {@link Buffer}
     */
    public static x25519KeyAgree(privateKey: crypto.KeyObject, publicKey: crypto.KeyObject) {
        return crypto.diffieHellman({
            publicKey: publicKey,
            privateKey: privateKey
        });
    }

}