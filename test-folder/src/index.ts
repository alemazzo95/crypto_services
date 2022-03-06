declare module 'crypto-services';
import cd from 'crypto-services';

try {
    const psw = "password";
    console.log(cd.deriveKey(psw).length);
} catch (err) {
  console.log(err);
}