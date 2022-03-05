let cd = require('./crypto/crypto_driver.js');

try {
    const psw = "password";
    console.log(cd.deriveKey(psw).length);
} catch (err) {
  console.log(err);
}