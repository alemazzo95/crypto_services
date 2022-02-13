/**
 * File containing all unit tests
 */

const assert = require('assert');
const cc = require('../crypto/crypto_core.js');
const cd = require('../crypto/crypto_driver.js');


function cropString(stringToCrop, charToPrint = 5) {
    return `${stringToCrop.slice(0, charToPrint)}...${stringToCrop.slice(charToPrint * -1)}`;
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
            assert.equal(aliceKeyAgree.alicePubKeyExport, cc.exportPubKey(aliceKeyAgree.aliceKeyPair.publicKey));
            let bobKeyAgree = cd.asymKeyAgree(aliceKeyAgree.alicePubKeyExport, bobKeyPair);
            assert.equal(aliceKeyAgree.keyAgree.toString('hex'), bobKeyAgree.keyAgree.toString('hex'));
        });
    });
}

describe('crypto_core', () => {
    testRandomSalt();
    testPbkdf2Generation();
    testPbkdf2Verify();
    testAes256Gcm();
    testX25519();
});

describe('crypto_driver', () => {
    testAsymKeyAgree();
});