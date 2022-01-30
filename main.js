var crypto = require('./crypto.js');

try {
    const psw = "password";
    crypto.randomSalt().then(salt => {
        var derivedKey = crypto.pbkdf2(psw, salt);
        console.log(derivedKey);
        var verified = crypto.pbkdf2Verify(psw, salt, derivedKey);
        console.log(verified ? "verified" : "ERROR");
    });
} catch (err) {
  console.log(err);
}