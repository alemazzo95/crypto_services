/* 
    Interface that provides crypto services using crypto primitives contained in crypto_core.js
*/

// Imports
const crypto = require("crypto");
const cc = require("./crypto_core.js");

// Module exports
module.exports = {
    asymKeyAgree
};

/**
 * Returns the DH shared secret. If the aliceKeyPair is not passed, a randomly one is generated and returned.
 * @param {string} bobPubKeyExport the exported bob public key
 * @param {crypto.KeyPairKeyObjectResult} aliceKeyPair the alice key pair. If null it will be randomly generated.
 * @returns an object with the following fields: "keyAgree" a {@link Buffer} representing the DH shared secret, "aliceKeyPair" a {@link crypto.KeyPairKeyObjectResult}, "alicePubKeyExport" a string representing the exported alice public key
 */
function asymKeyAgree(bobPubKeyExport, aliceKeyPair = null) {
    if (aliceKeyPair == null) {
        aliceKeyPair = cc.x25519GenerateKeyPair();
    }
    let bobPubKey = cc.importPubKey(bobPubKeyExport);
    let keyAgree = cc.x25519KeyAgree(aliceKeyPair.privateKey, bobPubKey);
    return {
        keyAgree: keyAgree,
        aliceKeyPair: aliceKeyPair,
        alicePubKeyExport: cc.exportPubKey(aliceKeyPair.publicKey)
    };
}
