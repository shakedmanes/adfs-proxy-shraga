const Router = require("express").Router;
const passport = require("passport");
const nJwt = require("njwt");
const xmldom = require('xmldom');

const { jwtUtils, cryptKeysUtils }= require('../utils/authUtils');
const authConfig = require("../authConfig");


const { enrichment, attributeTagName, samlResponseModifier } = authConfig();
//by default enrich is the identity function if undefined
const enrich = enrichment.enrich ? enrichment.enrich : x => x;
const router = Router();

// Route for public key gathering
router.get("/publickey.pem", (req, res, next) => res.send(cryptKeysUtils.getPublicKey()));

router.get("/saml", passport.authenticate("saml"), (req, res) => {
    res.redirect("/");
});


const dealWithCallback = async (req, res, next) => {
    if (req.cookies["useADFS"]) {
        return next();
    }

    const { user } = req;

    const enrichedUser = await enrich(user, req.cookies.useEnrichId);

    const RelayState = req.cookies["RelayState"];
    if (RelayState) {
        enrichedUser.RelayState = RelayState;
    }

    // First, append the `sub` claim if found appName option
    let payload = { ...enrichedUser, ...( req.cookies['appName'] ? { sub: req.cookies["appName"] } : null )};
    
    let jwt = null;

    // If used private key signing option, sign with private key
    if (req.cookies["usePrivateKeySigning"]) {
        jwt = jwtUtils.createAndSignJWT(payload, cryptKeysUtils.getPrivateKey(), jwtUtils.signKeyType.PRIVATE_KEY);
    }    
    // else, using SignInSecret signing    
    else {
        jwt = jwtUtils.createAndSignJWT(
            payload,
            Buffer.from(req.cookies["SignInSecret"], 'base64'),
            jwtUtils.signKeyType.SECRET
        );
        // jwt = nJwt.create(enrichedUser, Buffer.from(req.cookies["SignInSecret"], 'base64'));
    }

    res.cookie('jwtUserCreds', jwt);

    res.redirect(307, `${req.cookies["callbackURL"]}/?jwt=${jwt}`);
};

const dealWithSAMLuseADFSCallback = async (req, res, next) => {
    const { SAMLResponse } = req.body;
    const xml = Buffer.from(SAMLResponse, 'base64').toString('utf8');
    const dom = new xmldom.DOMParser().parseFromString(xml);

    const getToNodeValueAndAssignNewValue = async (initialNode, newValueFunc) => {
        while (!initialNode.nodeValue) {
            initialNode = initialNode.childNodes[0];
        }

        const { parentNode } = initialNode;
        parentNode.removeChild(initialNode);
        const newValue = await newValueFunc(initialNode.nodeValue);
        const newElm = dom.createTextNode(newValue);
        parentNode.appendChild(newElm);
        return true;
    }

    const attributes = dom.getElementsByTagName(attributeTagName);
    for (let attributeIndex = 0; attributeIndex < attributes.length; attributeIndex++) {
        for (let attribute in samlResponseModifier) {
            if (attributes[attributeIndex].getAttribute("Name") === attribute) {
                await getToNodeValueAndAssignNewValue(attributes[attributeIndex], samlResponseModifier[attribute]);
            }
        }
    }

    const newSerializedXml = new xmldom.XMLSerializer().serializeToString(dom);
    const newXml = Buffer.from(newSerializedXml, 'utf8').toString('base64');

    const RelayState = req.cookies["RelayState"];
    const htlmResponse = createHTMLResponse(newXml, req.cookies["callbackURL"], RelayState);

    res.status(200).send(htlmResponse);
};

const createHTMLResponse = (SAMLResponse, callbackURL, RelayState) => {
    const response =
        `<html>
            <body>
                <form method="POST" name="hiddenform" action="${callbackURL}">
                    <input type="hidden" name="SAMLResponse" value="${SAMLResponse}" />
                    ${ RelayState ? `<input type="hidden" name="RelayState" value="${RelayState}" />` : ''}
                </form>
                <script language="javascript">
                    window.setTimeout('document.forms[0].submit()',0);
                </script>
            </body>
        </html>`

    return response;
}


router.post("/saml", passport.authenticate("saml"), dealWithCallback);

router.post("/saml", passport.authenticate("saml"), dealWithSAMLuseADFSCallback);

// to adhere to ADFS standards - not allways relavent.
router.post("/saml/callback", passport.authenticate("saml"), dealWithCallback);

router.post("/saml/callback", passport.authenticate("saml"), dealWithSAMLuseADFSCallback);

module.exports = router;
