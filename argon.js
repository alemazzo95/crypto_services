const argon2 = require('argon2');

// please see best practise at https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
const argon2conf = {
    type: argon2.argon2id,
    version: 0x13,      // latest version in this moment
    timeCost: 3,        // minimum advised #iterations is 2, 3 is default
    memoryCost: 16384,  // 16 Mib per thread
    parallelism: 2,     // # of used thread
    saltLength: 16      // 128bit
};

function kdfCompute(plaintext) {
    return argon2.hash(plaintext, argon2conf);
}

function kdfVerity(plaintext, hash) {
    return argon2.verify(hash, plaintext);
}

// this should be done on clients, the results is then transmitted in the login / registration APIs
function computeFirstKdfClientIteration(password) {
    return kdfCompute(password);
}

try {
    const psw = "password";
    const clientPsw = await computeFirstKdfClientIteration(psw); // not plaintext, 1° iteration done on the client
    kdfCompute(clientPsw).then(hash => {
        console.log(hash);
        kdfVerity(psw, hash).then(success => {
            console.log(success ? "verified" : "not verified");
        });
    });
} catch (err) {
  console.err(err);
}