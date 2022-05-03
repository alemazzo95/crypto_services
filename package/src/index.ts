/* 
    Interface that provides crypto services using crypto primitives contained in crypto_core.js
*/

// Imports
import crypto from "crypto";
import { CryptoCore } from "./crypto_core.js";

/*
    Used to be backwards compatible in case of parameters upgrade.
 */
export class DerivationKeyParam {

    public static DERIVATION_KEY_VER = "v1";
    private _version: string;
    private _pbkdf2Iterations: number;
    private _pbkdf2SaltLen: number;
    private _pbkdf2KeyLen: number;
    private _pbkdf2Digest: string;

    public constructor(version: string = DerivationKeyParam.DERIVATION_KEY_VER) {
        this._version = version;
        switch(version) {
            case "v1":
                this._pbkdf2Iterations = 310000;
                this._pbkdf2SaltLen = 32;
                this._pbkdf2KeyLen = 64;
                this._pbkdf2Digest = 'sha256';
                break;
            default:
                throw new Error("Invalid derived key");
        }
    }

    public get version() { return this._version }

    public get pbkdf2Iterations() { return this._pbkdf2Iterations; }

    public get pbkdf2SaltLen() { return this._pbkdf2SaltLen; }

    public get pbkdf2KeyLen() { return this._pbkdf2KeyLen; }

    public get pbkdf2Digest() { return this._pbkdf2Digest; }

}

export abstract class CryptoServices {

    /**
     * Returns the DH shared secret. If the aliceKeyPair is not passed, a randomly one is generated and returned.
     * @param {string} bobPubKeyExport the exported bob public key
     * @param {crypto.KeyPairKeyObjectResult} aliceKeyPair the alice key pair. If null it will be randomly generated.
     * @returns an object with the following fields: "sharedSecret" a {@link Buffer} representing the DH shared secret, "keyPair" the alice key pair ({@link crypto.KeyPairKeyObjectResult}), "pubKeyExport" a string representing the exported alice public key
     */
    public static asymKeyAgree(bobPubKeyExport: string, aliceKeyPair?: crypto.KeyPairKeyObjectResult) {
        if (aliceKeyPair == null) {
            aliceKeyPair = CryptoCore.x25519GenerateKeyPair();
        }
        let bobPubKey = CryptoCore.importPubKey(bobPubKeyExport);
        let keyAgree = CryptoCore.x25519KeyAgree(aliceKeyPair.privateKey, bobPubKey);
        return {
            sharedSecret: keyAgree,
            keyPair: aliceKeyPair,
            pubKeyExport: CryptoCore.exportPubKey(aliceKeyPair.publicKey)
        };
    }

    /**
     * @returns a random generated string Buffer that can be used as symmetric key.
     */
    public static randomSymKey() {
        return CryptoCore.randomBytes(CryptoCore.AES_KEY_LEN);
    }

    /**
     * @param {Buffer} key the symmetric key
     * @param {string} plaintext the plaintext to encrypt
     * @returns a payload formatted as the following string: "<iv>:<auth_tag>:<ciphertext>", where iv and auth_tag are formatted in hex strings.
     */
    public static symEncrypt(key: Buffer, plaintext: string) {
        let cipherObj = CryptoCore.aes256gcmEnc(plaintext, key);
        let ivHex = cipherObj.iv.toString('hex');
        let authTagHex = cipherObj.authTag.toString('hex');
        return `${ivHex}:${authTagHex}:${cipherObj.ciphertext}`;
    }

    /**
     * 
     * @param {Buffer} key the symmetric key
     * @param {string} payload the payload that must be formatted as returned by function {@link symEncrypt}.
     * @returns the plaintext
     */
    public static symDecrypt(key: Buffer, payload: string) {
        let splittedPayload = payload.split(':');
        if (splittedPayload.length != 3) {
            throw new Error("Invalid payload");
        }
        let iv = Buffer.from(splittedPayload[0], 'hex');
        let authTag = Buffer.from(splittedPayload[1], 'hex');
        let ciphertext = splittedPayload[2];
        return CryptoCore.aes256gcmDec(ciphertext, key, iv, authTag);
    }

    /**
     * @returns a random generated UUID.
     */
    public static randomUUID() {
        return CryptoCore.randomUUID();
    }

    /**
     * Generates a random string. Please see {@link DerivationKeyParam} for details on the salt length.
     * @returns a random string to be used as salt in key derivation functions.
     */
    public static randomSalt() {
        let derivationKeyParams = new DerivationKeyParam();
        return CryptoCore.randomSalt(derivationKeyParams.pbkdf2SaltLen);
    }

    /**
     * Derive the given key using pbkdf2. The derived key is versioned so to be backwards compatible.
     * @param {string} key a string representing a key to derive
     * @param {string} salt an optional string representing a random salt. If not given, a random salt will be generated using {@link CryptoServices.randomSalt}.
     * @returns a string formatted as follows: <version>:<salt>:<derived_key>
     */
    public static deriveKey(key: string, salt: string = "") {
        let derivationKeyParams = new DerivationKeyParam();
        if (salt === undefined || salt === "") {
            salt = CryptoServices.randomSalt();
        }
        let derivedKey = CryptoCore.pbkdf2(
            key,
            salt,
            derivationKeyParams.pbkdf2Iterations,
            derivationKeyParams.pbkdf2KeyLen,
            derivationKeyParams.pbkdf2Digest
        );
        return `${derivationKeyParams.version}:${salt}:${derivedKey}`;
    }

    /**
     * Verify that the given key matches the derived one.
     * @param {string} key the key that must be verified
     * @param {string} derivedKey the derived key on which verify the key. It must be formatted as indicated in function {@link deriveKey}.
     * @returns true if the key matches the derived one.
     */
    public static verifyKey(key: string, derivedKey: string) {
        let splittedDerivedKey = derivedKey.split(':');
        if (splittedDerivedKey.length != 3) {
            throw new Error("Invalid derived key");
        }
        try {
            let version = splittedDerivedKey[0];
            let derivationKeyParams = new DerivationKeyParam(version);
            let salt = splittedDerivedKey[1];
            let dKey = splittedDerivedKey[2];
            return CryptoCore.pbkdf2Verify(
                key,
                salt,
                dKey,
                derivationKeyParams.pbkdf2Iterations,
                derivationKeyParams.pbkdf2KeyLen,
                derivationKeyParams.pbkdf2Digest
            );
        } catch(err) {
            throw new Error("Invalid derived key");
        }
    }

}
