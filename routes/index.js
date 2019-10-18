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
    useADFS
  } = req.query;

  res.cookie("callbackURL", callbackURL);
  res.cookie("SignInSecret", SignInSecret);

  if(useEnrichId) {
    res.cookie("useEnrichId", useEnrichId);
  }

  if(useADFS) {
    res.cookie("useADFS", useADFS);
  }

  res.status(200).redirect('/auth/saml');
});

module.exports = router;
