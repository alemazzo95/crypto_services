/**
 * File containing all unit tests
 */

const assert = require('assert');
const cc = require('../crypto/crypto_core.js');
const cd = require('../crypto/crypto_driver.js');


function cropString(stringToCrop, charToPrint = 5) {
    return `${stringToCrop.slice(0, charToPrint)}...${stringToCrop.slice(charToPrint * -1)}`;
}

function testRandomUUID() {
    describe('#randomUUID()', () => {
        const UUID_LEN = 36;
        const UUID_PARTS = 5;
        const UUID_PARTS_LEN = [8, 4, 4, 4, 12];
        it('should return a string like "9f48b2a8-cb45-458c-b3d1-dd693b4f1d20"', () => {
            let uuid = cc.randomUUID();
            assert.equal(uuid.length, UUID_LEN);
            let splittedUUID = uuid.split("-");
            assert.equal(splittedUUID.length, UUID_PARTS);
            for(let i=0; i<splittedUUID.length; i++) {
                assert.equal(splittedUUID[i].length, UUID_PARTS_LEN[i]);
            }
        });
    });
}

function testRandomSalt() {
    describe('#randomSalt(...)', () => {
        it(`randomSalt() should return a random string of len crypto.PBKDF2_SALT_LEN = ${cc.PBKDF2_SALT_LEN}`, () => {
            let salt = cc.randomSalt();
            assert.equal(salt.length, cc.PBKDF2_SALT_LEN);
        });
        const saltlen1 = 15;
        it(`randomSalt(${saltlen1}) should throw an error because "saltlen" must be even`, (done) => {
            try {
                cc.randomSalt(saltlen1);
                done("It didn't throw the expected error");
            } catch(err) {
                done();
            }
        });
        const saltlen2 = 24;
        it(`randomSalt(${saltlen2}) should return a random string of len ${saltlen2}`, () => {
            let salt = cc.randomSalt(saltlen2);
            assert.equal(salt.length, saltlen2);
        });
    });
}

function testPbkdf2Generation() {
    describe(`#pbkdf2(...)`, () => {
        const psw1 = "password", salt1 = "salt", salt2 = "different";
        const expectedDerivedKey1 = "66fb3eadeac9a027142642b593359613d587ca1be360b8b53d84eda5c784574e6177bdd7ef27bf123aadadf0fd1230002dda086c4c7d22aeb0011a6dafd18842";
        it(`pbkdf2("${psw1}", "${salt1}") should return "${cropString(expectedDerivedKey1)}"`, () => {
            const derivedKey = cc.pbkdf2(psw1, salt1);
            assert.equal(derivedKey, expectedDerivedKey1);
        });
        it(`The keys derived from same password and different salts should be different from each other ( pbkdf2("${psw1}", "${salt1}") != #pbkdf2("${psw1}", "${salt2}") )`, () => {
            const derivedKey1 = cc.pbkdf2(psw1, salt1);
            const derivedKey2 = cc.pbkdf2(psw1, salt2);
            assert.notEqual(derivedKey1, derivedKey2);
        });
    });
}

function testPbkdf2Verify() {
    describe(`#pbkdf2Verify(...)`, () => {
        const psw1 = "password", psw2 = "pass1234", salt1 = "salt", salt2 = "differentSalt";
        // pbkdf2(psw1, salt1)
        const expectedDerivedKey1 = "66fb3eadeac9a027142642b593359613d587ca1be360b8b53d84eda5c784574e6177bdd7ef27bf123aadadf0fd1230002dda086c4c7d22aeb0011a6dafd18842";
        const expectedDerivedKey2 = "75722f0c7b87ef268edcc61079cfd0f5749f505bc5f34be4433b9d0faa2abad1f84bedb0c015b5e6666525de95e274ff71a674037d64e26c77417a9208bd676e";
        it(`pbkdf2Verify("${psw1}", "${salt1}", "${cropString(expectedDerivedKey1)})") should return true`, () => {
            const success = cc.pbkdf2Verify(psw1, salt1, expectedDerivedKey1);
            assert.deepEqual(success, true);
        });
        it(`pbkdf2Verify("${psw1}", "${salt1}", "${cropString(expectedDerivedKey2)})") should return false`, () => {
            const success = cc.pbkdf2Verify(psw1, salt1, expectedDerivedKey2);
            assert.deepEqual(success, false);
        });
        it(`pbkdf2Verify("${psw1}", "${salt2}", "${cropString(expectedDerivedKey1)})") should return false`, () => {
            const success = cc.pbkdf2Verify(psw1, salt2, expectedDerivedKey1);
            assert.deepEqual(success, false);
        });
        it(`pbkdf2Verify("${psw2}", "${salt1}", "${cropString(expectedDerivedKey1)})") should return false`, () => {
            const success = cc.pbkdf2Verify(psw2, salt1, expectedDerivedKey1);
            assert.deepEqual(success, false);
        });
    });
}

function testAes256Gcm() {
    describe(`#aes256gcm methods`, () => {
        const key1 = Buffer.from("924432b5d2daf360f379db847681fdc1026b598d60be4c08191930d33ce06131", "hex");
        const iv1 = Buffer.from("70667b2d3f90167e8aca9a315cea85c9", "hex");
        const plaintext = "ciao bella";
        const expCiphertext = "mby4GWahpin7Aw==";
        const expAuthTag = Buffer.from("2abc309063bea33f3a834daffa8fa03a", "hex");
        it(`aes256gcmEncWithIV("${plaintext}", "${key1}", "${iv1}") should return "${expCiphertext}"`, () => {
            let enc = cc.aes256gcmEncWithIV(plaintext, key1, iv1);
            assert.equal(enc.ciphertext, expCiphertext);
            assert.equal(enc.iv.toString("hex"), iv1.toString("hex"));
            assert.equal(enc.authTag.toString("hex"), expAuthTag.toString("hex"));
        });
        it(`aes256gcmEnc("${plaintext}", "${key1}") should return same result of aes256gcmEncWithIV("${plaintext}", "${key1}", <rndIV>)`, () => {
            let enc = cc.aes256gcmEnc(plaintext, key1);
            let enc1 = cc.aes256gcmEncWithIV(plaintext, key1, enc.iv);
            assert.equal(enc.ciphertext, enc1.ciphertext);
            assert.equal(enc.iv.toString("hex"), enc1.iv.toString("hex"));
            assert.equal(enc.authTag.toString("hex"), enc1.authTag.toString("hex"));
        });
        it(`aes256gcmDec("${expCiphertext}", "${key1}", "${iv1}", "${expAuthTag}") should return "${plaintext}"`, () => {
            const plain = cc.aes256gcmDec(expCiphertext, key1, iv1, expAuthTag);
            assert.equal(plain, plaintext);
        });
    });
}

function testX25519() {
    describe(`#x25519 methods`, () => {
        let aliceKeyPair = cc.x25519GenerateKeyPair();
        it(`x25519GenerateKeyPair() should return a key pair`, () => {
            assert.notEqual(aliceKeyPair, null);
            assert.notEqual(aliceKeyPair.privateKey, null);
            assert.notEqual(aliceKeyPair.publicKey, null);
            assert.equal(aliceKeyPair.privateKey.asymmetricKeyType, cc.EC_DH_FUN);
            assert.equal(aliceKeyPair.publicKey.asymmetricKeyType, cc.EC_DH_FUN);
        });
        it(`exportPubKey(..), importPubKey(..)`, () => {
            let pubKeyExport = cc.exportPubKey(aliceKeyPair.publicKey);
            let publicKey = cc.importPubKey(pubKeyExport);
            let pubKeyExport1 = cc.exportPubKey(publicKey);
            assert.equal(pubKeyExport, pubKeyExport1);
        });
        let bobKeyPair = cc.x25519GenerateKeyPair();
        it(`x25519KeyAgree(<alicePriKey>, <bobPubKey>) = x25519KeyAgree(<bobPriKey>, <alicePubKey>)`, () => {
            let aliceKeyAgree = cc.x25519KeyAgree(aliceKeyPair.privateKey, bobKeyPair.publicKey);
            let bobKeyAgree = cc.x25519KeyAgree(bobKeyPair.privateKey, aliceKeyPair.publicKey);
            assert.equal(aliceKeyAgree.toString('hex'), bobKeyAgree.toString('hex'));
        });
    });
}

function testAsymKeyAgree() {
    describe(`#asymKeyAgree(...)`, () => {
        let bobKeyPair = cc.x25519GenerateKeyPair();
        let bobPubKeyExport = cc.exportPubKey(bobKeyPair.publicKey);
        it(`asymKeyAgree(bobPubKey, aliceKeyPair).keyAgree = asymKeyAgree(alicePubKey, bobKeyPair).keyAgree`, () => {
            let aliceKeyAgree = cd.asymKeyAgree(bobPubKeyExport);
            assert.equal(aliceKeyAgree.pubKeyExport, cc.exportPubKey(aliceKeyAgree.keyPair.publicKey));
            let bobKeyAgree = cd.asymKeyAgree(aliceKeyAgree.pubKeyExport, bobKeyPair);
            assert.equal(aliceKeyAgree.sharedSecret.toString('hex'), bobKeyAgree.sharedSecret.toString('hex'));
        });
    });
}

function testSymMethods() {
    describe(`#symmetric methods`, () => {
        let key = cd.randomSymKey();
        it(`randomSymKey() should return a random key of lenght ${cc.AES_KEY_LEN}`, () => {
            assert.equal(key.length, cc.AES_KEY_LEN);
        });
        let plaintext = "Hello World, how are you?";
        it(`symDecrypt(<key>, symEncrypt(<key>, <plaintext>)) = <plaintext>`, () => {
            let payload = cd.symEncrypt(key, plaintext);
            let decrypted = cd.symDecrypt(key, payload);
            assert.equal(decrypted, plaintext);
        });
    });
}

function testKeyDerivation() {
    describe(`#key derivation methods`, () => {
        let password = "pass1234";
        let dKey = cd.deriveKey(password);
        it(`deriveKey(${password}) should return a derived key formatted as following "v1:<salt>:<derived_key>"`, () => {
            console.log(dKey);
            let splittedDerivedKey = dKey.split(":");
            assert.equal(splittedDerivedKey.length, 3);
            assert.equal(splittedDerivedKey[0], cd.DERIVATION_KEY_VER);
            let expectedParams = cd.DERIVATION_KEY_PARAMS[cd.DERIVATION_KEY_VER];
            assert.equal(splittedDerivedKey[1].length, expectedParams["PBKDF2_SALT_LEN"]);
            assert.equal(splittedDerivedKey[2].length, expectedParams["PBKDF2_KEY_LEN"]*2); // expressed in hex, so double it
        });
        it(`verifyKey(${password}, deriveKey(${password})) should return true`, () => {
            assert.equal(cd.verifyKey(password, dKey), true);
        });
    });
}

function testCryptoFlow() {

    // client sends its public key to the server
    let clientKeyPair = cc.x25519GenerateKeyPair();
    let clientPubKeyExport = cc.exportPubKey(clientKeyPair.publicKey);

    // server receives client public key, generates the server key pair
    // computes the DH shared secret and sends server public key to the client
    let serverKeyAgree = cd.asymKeyAgree(clientPubKeyExport);
    let serverPubKeyExport = serverKeyAgree.pubKeyExport;
    let serverSharedSecret = serverKeyAgree.sharedSecret;
    
    // client computes DH shared secret
    let clientKeyAgree = cd.asymKeyAgree(serverPubKeyExport, clientKeyPair);
    let clientSharedSecret = clientKeyAgree.sharedSecret;

    it(`clientSharedSecret = serverSharedSecret`, () => {
        assert.equal(clientSharedSecret.toString('hex'), serverSharedSecret.toString('hex'));
    });

    // client encrypts a message and sends it to the server
    const clientMsg = "a beautiful client message";
    let encryptedClientMsg = cd.symEncrypt(clientSharedSecret, clientMsg);

    // server decrypts the encrypted client message
    let decryptedClientMsg = cd.symDecrypt(serverSharedSecret, encryptedClientMsg);
    
    it(`decryptedClientMsg = clientMsg`, () => {
        assert.equal(decryptedClientMsg, clientMsg);
    });

    // server generates a response, encrypts and sends it to the client
    const serverResponse = "a pretty server response";
    let encryptedServerRes = cd.symEncrypt(serverSharedSecret, serverResponse);
    
    // client decypts the encrypted server response
    let decryptedServerRes = cd.symDecrypt(clientSharedSecret, encryptedServerRes);

    it(`decryptedServerRes = serverResponse`, () => {
        assert.equal(decryptedServerRes, serverResponse);
    });
}

describe('crypto_core', () => {
    testRandomUUID();
    testRandomSalt();
    testPbkdf2Generation();
    testPbkdf2Verify();
    testAes256Gcm();
    testX25519();
});

describe('crypto_driver', () => {
    testAsymKeyAgree();
    testSymMethods();
    testKeyDerivation();
});

describe('crypto flow', () => {
    testCryptoFlow();
});