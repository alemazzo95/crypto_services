import { CryptoServices } from 'crypto-services';

try {
    const psw = "password";
    console.log(CryptoServices.deriveKey(psw).length);
} catch (err) {
  console.log(err);
}