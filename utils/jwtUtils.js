const nJwt = require("njwt");
const crypto = require("crypto");


const jwtUtils = {};

// Enum type for type of signing key on JWT
jwtUtils.signKeyType = {
    PRIVATE_KEY: 0,
    SECRET: 1,
}

jwtUtils.createAndSignJWT = (payload, signKey, type) => {

    // Taking care of `sub` claim, by hashing the `sub` claim with SHA256
    let token = null;

    if (payload.sub) {
        payload.sub = crypto.createHash('sha256').update(payload.sub).digest('base64');
    }

    switch (type) {
        
        case this.signKeyType.PRIVATE_KEY:
            token = nJwt.create(payload, signKey, "RSA256");
            break;
        case this.signKeyType.SECRET:
        default:
            token = nJwt.create(payload, signKey);
            break;
    }

    return token.compact();

};

module.exports = jwtUtils;