/**
 * File containing all unit tests
 */

const assert = require('assert');
const crypto = require('../crypto.js');


function cropString(stringToCrop, charToPrint = 5) {
    return `${stringToCrop.slice(0, charToPrint)}...${stringToCrop.slice(charToPrint * -1)}`;
}


function testRandomSalt() {
    describe('#randomSalt(...)', function() {
        it(`randomSalt() should return a random string of len crypto.PBKDF2_SALT_LEN = ${crypto.PBKDF2_SALT_LEN}`, function(done) {
            crypto.randomSalt().then(salt => {
                assert.equal(salt.length, crypto.PBKDF2_SALT_LEN);
                done();
            }).catch(err => {
                done(err);
            });
        });
        const saltlen1 = 15;
        it(`randomSalt(${saltlen1}) should throw an error because "saltlen" must be even`, function(done) {
            crypto.randomSalt(saltlen1).then(salt => {
                done(`no error thrown, instead ${salt} has been returned`);
            }).catch(err => {
                done()
            });
        });
        const saltlen2 = 24;
        it(`randomSalt(${saltlen2}) should return a random string of len ${saltlen2}`, function(done) {
            crypto.randomSalt(saltlen2).then(salt => {
                assert.equal(salt.length, saltlen2);
                done();
            }).catch(err => {
                done(err)
            });
        });
    });
}

function testPbkdf2Generation() {
    describe(`#pbkdf2(...)`, function() {
        const psw1 = "password", salt1 = "salt", salt2 = "different";
        const expectedDerivedKey1 = "66fb3eadeac9a027142642b593359613d587ca1be360b8b53d84eda5c784574e6177bdd7ef27bf123aadadf0fd1230002dda086c4c7d22aeb0011a6dafd18842";
        it(`pbkdf2("${psw1}", "${salt1}") should return "${cropString(expectedDerivedKey1)}"`, function() {
            const derivedKey = crypto.pbkdf2(psw1, salt1);
            assert.equal(derivedKey, expectedDerivedKey1);
        });
        it(`The keys derived from same password and different salts should be different from each other ( pbkdf2("${psw1}", "${salt1}") != #pbkdf2("${psw1}", "${salt2}") )`, function() {
            const derivedKey1 = crypto.pbkdf2(psw1, salt1);
            const derivedKey2 = crypto.pbkdf2(psw1, salt2);
            assert.notEqual(derivedKey1, derivedKey2);
        });
    });
}

function testPbkdf2Verify() {
    describe(`#pbkdf2Verify(...)`, function() {
        const psw1 = "password", psw2 = "pass1234", salt1 = "salt", salt2 = "differentSalt";
        // pbkdf2(psw1, salt1)
        const expectedDerivedKey1 = "66fb3eadeac9a027142642b593359613d587ca1be360b8b53d84eda5c784574e6177bdd7ef27bf123aadadf0fd1230002dda086c4c7d22aeb0011a6dafd18842";
        const expectedDerivedKey2 = "75722f0c7b87ef268edcc61079cfd0f5749f505bc5f34be4433b9d0faa2abad1f84bedb0c015b5e6666525de95e274ff71a674037d64e26c77417a9208bd676e";
        it(`pbkdf2Verify("${psw1}", "${salt1}", "${cropString(expectedDerivedKey1)})") should return true`, function() {
            const success = crypto.pbkdf2Verify(psw1, salt1, expectedDerivedKey1);
            assert.deepEqual(success, true);
        });
        it(`pbkdf2Verify("${psw1}", "${salt1}", "${cropString(expectedDerivedKey2)})") should return false`, function() {
            const success = crypto.pbkdf2Verify(psw1, salt1, expectedDerivedKey2);
            assert.deepEqual(success, false);
        });
        it(`pbkdf2Verify("${psw1}", "${salt2}", "${cropString(expectedDerivedKey1)})") should return false`, function() {
            const success = crypto.pbkdf2Verify(psw1, salt2, expectedDerivedKey1);
            assert.deepEqual(success, false);
        });
        it(`pbkdf2Verify("${psw2}", "${salt1}", "${cropString(expectedDerivedKey1)})") should return false`, function() {
            const success = crypto.pbkdf2Verify(psw2, salt1, expectedDerivedKey1);
            assert.deepEqual(success, false);
        });
    });
}

function testAes256Gcm() {
    describe(`#aes256gcmEnc(...)`, function() {
        const key1 = Buffer.from("924432b5d2daf360f379db847681fdc1026b598d60be4c08191930d33ce06131", "hex");
        const iv1 = Buffer.from("70667b2d3f90167e8aca9a315cea85c9", "hex");
        const plaintext = "ciao bella";
        const expCiphertext = "mby4GWahpin7Aw==";
        const expAuthTag = Buffer.from("2abc309063bea33f3a834daffa8fa03a", "hex");
        it(`aes256gcmEnc("${plaintext}", "${key1}", "${iv1}") should return "${expCiphertext}"`, function(done) {
            crypto.aes256gcmEnc(plaintext, key1, iv1).then(enc => {
                assert.equal(enc.ciphertext, expCiphertext);
                assert.equal(enc.iv.toString("hex"), iv1.toString("hex"));
                assert.equal(enc.authTag.toString("hex"), expAuthTag.toString("hex"));
                done();
            }).catch(err => {
                done(err);
            });
        });
        it(`aes256gcmDec("${expCiphertext}", "${key1}", "${iv1}", "${expAuthTag}") should return "${plaintext}"`, function() {
            const plain = crypto.aes256gcmDec(expCiphertext, key1, iv1, expAuthTag);
            assert.equal(plain, plaintext);
        });
    });
}

describe('Crypto', function() {
    testRandomSalt();
    testPbkdf2Generation();
    testPbkdf2Verify();
    testAes256Gcm();
});