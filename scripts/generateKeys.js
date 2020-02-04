const generateKeyPairSync = require("crypto").generateKeyPairSync;
const pathJoin = require("path").join;
const fs = require("fs");

function generateKeys() {

    // Extract folder name from script arguments
    const folderName = process.argv.slice(2)[0];

    // Did not receive folder name for storing the keys
    if (!folderName) {
      console.error('ERROR: Missing folder name for the keys directory');
      return;
    }

    // Keys folder full path 
    const keysFolderPath = pathJoin(__dirname, '../' , folderName);

    // First, create folder for storing the keys if not exists
    if (!fs.existsSync(keysFolderPath)) {
        fs.mkdirSync(keysFolderPath);
    }

    // Generate key pair
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
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
    fs.writeFileSync(pathJoin(keysFolderPath, "privatekey.pem"), privateKey);
    fs.writeFileSync(pathJoin(keysFolderPath, "publickey.pem"), publicKey);
}

generateKeys();