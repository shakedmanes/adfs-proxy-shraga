const crypto = require("crypto");
const pathJoin = require("path").join;
const fs = require("fs");

function generateKeys() {

    const folderName = "../keys";

    // First, create folder for storing the keys if not exists
    if (!fs.existsSync(pathJoin(__dirname, folderName))) {
        fs.mkdirSync(pathJoin(__dirname, folderName));
    }

    // Generate key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
    });

    // Storing the keys in the folder
    fs.writeFileSync(pathJoin(__dirname, pathJoin, "privatekey.pem"), privateKey);
    fs.writeFileSync(pathJoin(__dirname, pathJoin, "publickey.pem"), publicKey);
}

generateKeys();