/**
 * File containing all unit tests
 */

const assert = require('assert');
const cryptoCore = require('../crypto/crypto_core.js');


function cropString(stringToCrop, charToPrint = 5) {
    return `${stringToCrop.slice(0, charToPrint)}...${stringToCrop.slice(charToPrint * -1)}`;
}


function testRandomSalt() {
    describe('#randomSalt(...)', () => {
        it(`randomSalt() should return a random string of len crypto.PBKDF2_SALT_LEN = ${cryptoCore.PBKDF2_SALT_LEN}`, () => {
            let salt = cryptoCore.randomSalt();
            assert.equal(salt.length, cryptoCore.PBKDF2_SALT_LEN);
        });
        const saltlen1 = 15;
        it(`randomSalt(${saltlen1}) should throw an error because "saltlen" must be even`, (done) => {
            try {
                cryptoCore.randomSalt(saltlen1);
                done("It didn't throw the expected error");
            } catch(err) {
                done();
            }
        });
        const saltlen2 = 24;
        it(`randomSalt(${saltlen2}) should return a random string of len ${saltlen2}`, () => {
            let salt = cryptoCore.randomSalt(saltlen2);
            assert.equal(salt.length, saltlen2);
        });
    });
}

function testPbkdf2Generation() {
    describe(`#pbkdf2(...)`, () => {
        const psw1 = "password", salt1 = "salt", salt2 = "different";
        const expectedDerivedKey1 = "66fb3eadeac9a027142642b593359613d587ca1be360b8b53d84eda5c784574e6177bdd7ef27bf123aadadf0fd1230002dda086c4c7d22aeb0011a6dafd18842";
        it(`pbkdf2("${psw1}", "${salt1}") should return "${cropString(expectedDerivedKey1)}"`, () => {
            const derivedKey = cryptoCore.pbkdf2(psw1, salt1);
            assert.equal(derivedKey, expectedDerivedKey1);
        });
        it(`The keys derived from same password and different salts should be different from each other ( pbkdf2("${psw1}", "${salt1}") != #pbkdf2("${psw1}", "${salt2}") )`, () => {
            const derivedKey1 = cryptoCore.pbkdf2(psw1, salt1);
            const derivedKey2 = cryptoCore.pbkdf2(psw1, salt2);
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
            const success = cryptoCore.pbkdf2Verify(psw1, salt1, expectedDerivedKey1);
            assert.deepEqual(success, true);
        });
        it(`pbkdf2Verify("${psw1}", "${salt1}", "${cropString(expectedDerivedKey2)})") should return false`, () => {
            const success = cryptoCore.pbkdf2Verify(psw1, salt1, expectedDerivedKey2);
            assert.deepEqual(success, false);
        });
        it(`pbkdf2Verify("${psw1}", "${salt2}", "${cropString(expectedDerivedKey1)})") should return false`, () => {
            const success = cryptoCore.pbkdf2Verify(psw1, salt2, expectedDerivedKey1);
            assert.deepEqual(success, false);
        });
        it(`pbkdf2Verify("${psw2}", "${salt1}", "${cropString(expectedDerivedKey1)})") should return false`, () => {
            const success = cryptoCore.pbkdf2Verify(psw2, salt1, expectedDerivedKey1);
            assert.deepEqual(success, false);
        });
    });
}

function testAes256Gcm() {
    describe(`#aes256gcmEncWithIV(...)`, () => {
        const key1 = Buffer.from("924432b5d2daf360f379db847681fdc1026b598d60be4c08191930d33ce06131", "hex");
        const iv1 = Buffer.from("70667b2d3f90167e8aca9a315cea85c9", "hex");
        const plaintext = "ciao bella";
        const expCiphertext = "mby4GWahpin7Aw==";
        const expAuthTag = Buffer.from("2abc309063bea33f3a834daffa8fa03a", "hex");
        it(`aes256gcmEncWithIV("${plaintext}", "${key1}", "${iv1}") should return "${expCiphertext}"`, () => {
            let enc = cryptoCore.aes256gcmEncWithIV(plaintext, key1, iv1);
            assert.equal(enc.ciphertext, expCiphertext);
            assert.equal(enc.iv.toString("hex"), iv1.toString("hex"));
            assert.equal(enc.authTag.toString("hex"), expAuthTag.toString("hex"));
        });
        it(`aes256gcmEnc("${plaintext}", "${key1}") should return same result of aes256gcmEncWithIV("${plaintext}", "${key1}", <rndIV>)`, () => {
            let enc = cryptoCore.aes256gcmEnc(plaintext, key1);
            let enc1 = cryptoCore.aes256gcmEncWithIV(plaintext, key1, enc.iv);
            assert.equal(enc.ciphertext, enc1.ciphertext);
            assert.equal(enc.iv.toString("hex"), enc1.iv.toString("hex"));
            assert.equal(enc.authTag.toString("hex"), enc1.authTag.toString("hex"));
        });
        it(`aes256gcmDec("${expCiphertext}", "${key1}", "${iv1}", "${expAuthTag}") should return "${plaintext}"`, () => {
            const plain = cryptoCore.aes256gcmDec(expCiphertext, key1, iv1, expAuthTag);
            assert.equal(plain, plaintext);
        });
    });
}

describe('crypto_core', () => {
    testRandomSalt();
    testPbkdf2Generation();
    testPbkdf2Verify();
    testAes256Gcm();
});