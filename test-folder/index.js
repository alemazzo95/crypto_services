let cd = require('crypto-services');

try {
    const psw = "password";
    console.log(cd.deriveKey(psw).length);
} catch (err) {
  console.log(err);
}