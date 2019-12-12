var express = require('express');
var router = express.Router();
const axios = require("axios");

router.get('/setCallback/:callbackURL', function (req, res, next) {
  const {
    callbackURL
  } = req.params;
  const {
    SignInSecret,
    useEnrichId,
    useADFS,
    RelayState,
    usePrivateKeySigning,
    appName,
  } = req.query;

  res.cookie("callbackURL", callbackURL);

  res.cookie("SignInSecret", SignInSecret);

  if (SignInSecret) {
    res.cookie("SignInSecret", SignInSecret);
  } else {
    res.clearCookie("SignInSecret");
  }

  if (useEnrichId) {
    res.cookie("useEnrichId", useEnrichId);
  } else {
    res.clearCookie("useEnrichId");
  }

  if (useADFS) {
    res.cookie("useADFS", useADFS);
  } else {
    res.clearCookie("useADFS");
  }

  if (RelayState) {
    res.cookie("RelayState", RelayState);
  } else {
    res.clearCookie("RelayState");
  }

  // If mentioned and value is true, setting the cookie for indicating the JWT need to be signed by private key
  if (usePrivateKeySigning) {
    res.cookie("usePrivateKeySigning", usePrivateKeySigning);
  } else {
    res.clearCookie("usePrivateKeySigning");
  }

  // If mentioned and given a value, setting the `sub` claim in the JWT to hash of the given value
  if (appName) {
    res.cookie("appName", appName);
  } else {
    res.clearCookie("appName");
  }

  res.status(200).redirect('/auth/saml');
});

module.exports = router;
