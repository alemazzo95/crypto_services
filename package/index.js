/* 
    Interface that provides crypto services using crypto primitives contained in crypto_core.js
*/

// Imports
const crypto = require("crypto");
const cc = require("./crypto_core.js");

/*
    Used to be backwards compatible in case of parameters upgrade.
 */
const DERIVATION_KEY_VER = "v1";
const DERIVATION_KEY_PARAMS = {
    "v1": {
        "PBKDF2_ITERATIONS": 310000,
        "PBKDF2_SALT_LEN": 32,
        "PBKDF2_KEY_LEN": 64,
        "PBKDF2_DIGEST": 'sha256'
    }
};

// Module exports
module.exports = {
    DERIVATION_KEY_VER,
    DERIVATION_KEY_PARAMS,
    asymKeyAgree,
    randomSymKey,
    symEncrypt,
    symDecrypt,
    randomUUID,
    deriveKey,
    verifyKey
};

/**
 * Returns the DH shared secret. If the aliceKeyPair is not passed, a randomly one is generated and returned.
 * @param {string} bobPubKeyExport the exported bob public key
 * @param {crypto.KeyPairKeyObjectResult} aliceKeyPair the alice key pair. If null it will be randomly generated.
 * @returns an object with the following fields: "sharedSecret" a {@link Buffer} representing the DH shared secret, "keyPair" the alice key pair ({@link crypto.KeyPairKeyObjectResult}), "pubKeyExport" a string representing the exported alice public key
 */
function asymKeyAgree(bobPubKeyExport, aliceKeyPair = null) {
    if (aliceKeyPair == null) {
        aliceKeyPair = cc.x25519GenerateKeyPair();
    }
    let bobPubKey = cc.importPubKey(bobPubKeyExport);
    let keyAgree = cc.x25519KeyAgree(aliceKeyPair.privateKey, bobPubKey);
    return {
        sharedSecret: keyAgree,
        keyPair: aliceKeyPair,
        pubKeyExport: cc.exportPubKey(aliceKeyPair.publicKey)
    };
}

/**
 * @returns a random generated string Buffer that can be used as symmetric key.
 */
function randomSymKey() {
    return cc.randomBytes(cc.AES_KEY_LEN);
}

/**
 * @param {Buffer} key the symmetric key
 * @param {string} plaintext the plaintext to encrypt
 * @returns a payload formatted as the following string: "<iv>:<auth_tag>:<ciphertext>", where iv and auth_tag are formatted in hex strings.
 */
function symEncrypt(key, plaintext) {
    let cipherObj = cc.aes256gcmEnc(plaintext, key);
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
function symDecrypt(key, payload) {
    let splittedPayload = payload.split(':');
    if (splittedPayload.length != 3) {
        throw new Error("Invalid payload");
    }
    let iv = Buffer.from(splittedPayload[0], 'hex');
    let authTag = Buffer.from(splittedPayload[1], 'hex');
    let ciphertext = splittedPayload[2];
    return cc.aes256gcmDec(ciphertext, key, iv, authTag);
}

/**
 * @returns a random generated UUID.
 */
function randomUUID() {
    return cc.randomUUID();
}

/**
 * Derive the given key using pbkdf2. The derived key is versioned so to be backwards compatible.
 * @param {string} key a string representing a key to derive
 * @returns a string formatted as follows: <version>:<salt>:<derived_key>
 */
function deriveKey(key) {
    let derivationKeyParams = DERIVATION_KEY_PARAMS[DERIVATION_KEY_VER];
    let salt = cc.randomSalt(derivationKeyParams["PBKDF2_SALT_LEN"]);
    let derivedKey = cc.pbkdf2(
        key,
        salt,
        derivationKeyParams["PBKDF2_ITERATIONS"],
        derivationKeyParams["PBKDF2_KEY_LEN"],
        derivationKeyParams["PBKDF2_DIGEST"]
    );
    return `${DERIVATION_KEY_VER}:${salt}:${derivedKey}`;
}

/**
 * Verify that the given key matches the derived one.
 * @param {string} key the key that must be verified
 * @param {string} derivedKey the derived key on which verify the key. It must be formatted as indicated in function {@link deriveKey}.
 * @returns true if the key matches the derived one.
 */
function verifyKey(key, derivedKey) {
    let splittedDerivedKey = derivedKey.split(':');
    if (splittedDerivedKey.length != 3) {
        throw new Error("Invalid derived key");
    }
    try {
        let version = splittedDerivedKey[0];
        let derivationKeyParams = DERIVATION_KEY_PARAMS[version];
        let salt = splittedDerivedKey[1];
        let dKey = splittedDerivedKey[2];
        return cc.pbkdf2Verify(
            key,
            salt,
            dKey,
            derivationKeyParams["PBKDF2_ITERATIONS"],
            derivationKeyParams["PBKDF2_KEY_LEN"],
            derivationKeyParams["PBKDF2_DIGEST"]
        );
    } catch(err) {
        throw new Error("Invalid derived key");
    }
}