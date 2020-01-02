const nJwtCreate = require("njwt").create;
const createHash = require("crypto").createHash;
const readFileSync = require("fs").readFileSync;
const pathResolve = require("path").resolve;


const jwtUtils = {};
const cryptKeysUtils = {};

/**
 *  JWT Utils
 * 
 *  Used basically for nicley wrapper around jwt operations
 */

// Enum type for type of signing key on JWT
jwtUtils.signKeyType = {
    PRIVATE_KEY: 0,
    SECRET: 1,
}

/**
 * Creates and sign a JWT, using secret/private key
 */
jwtUtils.createAndSignJWT = (payload, signKey, type) => {

    let token = null;
    
    // Taking care of `sub` claim, by hashing the `sub` claim with SHA256
    // This is used for helping the client to verify if the token actually created by
    // him, by validating the hash of the 'sub' claim.
    // If we set the value to plain text, anyone can use the 'sub' claim value to
    // disguise to any other client, compromising the trust of the client.
    if (payload.sub) {
        payload.sub = createHash('sha256').update(payload.sub).digest('base64');
    }

    // Sign the JWT with the specific type
    switch (type) {
        
        case this.signKeyType.PRIVATE_KEY:
            token = nJwtCreate(payload, signKey, "RSA256");
            break;
        case this.signKeyType.SECRET:
        default:
            token = nJwtCreate(payload, signKey);
            break;
    }

    return token.compact();

};

/**
 * Crypt Keys Utils
 * 
 * Used basically for operations with private/public keys
 */

cryptKeysUtils._privateKey = null;
cryptKeysUtils._publicKey = null;
cryptKeysUtils._KEYS_DIR = pathResolve(__dirname, "keys");
cryptKeysUtils._PRIVATE_KEY_PATH = pathResolve(cryptKeysUtils._KEYS_DIR, "privatekey.pem");
cryptKeysUtils._PUBLIC_KEY_PATH = pathResolve(cryptKeysUtils._KEYS_DIR, "publickey.pem");

/**
 * Gets the private key
 */
cryptKeysUtils.getPrivateKey = () => {
    if (cryptKeysUtils._privateKey) {
        return cryptKeysUtils._privateKey;
    }

    cryptKeysUtils._privateKey = readFileSync(cryptKeysUtils._PRIVATE_KEY_PATH);

    return cryptKeysUtils._privateKey;
};

/**
 * Gets the public key
 */
cryptKeysUtils.getPublicKey = () => {
    if (cryptKeysUtils._publicKey) {
        return cryptKeysUtils._publicKey;
    }

    cryptKeysUtils._publicKey = readFileSync(cryptKeysUtils._PUBLIC_KEY_PATH);

    return cryptKeysUtils._publicKey;
}

module.exports = {
    jwtUtils,
    cryptKeysUtils
};