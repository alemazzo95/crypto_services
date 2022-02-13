/* 
    Interface that provides crypto services using crypto primitives contained in crypto_core.js
*/

// Imports
const crypto = require("crypto");
const cc = require("./crypto_core.js");

// Module exports
module.exports = {
    asymKeyAgree,
    randomSymKey,
    symEncrypt,
    symDecrypt
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

function randomSymKey() {
    return cc.randomBytes(cc.AES_KEY_LEN);
}

function symEncrypt(key, plaintext) {
    let cipherObj = cc.aes256gcmEnc(plaintext, key);
    let ivHex = cipherObj.iv.toString('hex');
    let authTagHex = cipherObj.authTag.toString('hex');
    return `${ivHex}:${authTagHex}:${cipherObj.ciphertext}`;
}

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