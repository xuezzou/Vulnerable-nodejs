var express = require('express');
var router = express.Router();

/* GET order page. */
router.get('/order', function (req, res) {
  var name = req.query.name; // $_GET["id"]
  res.render('order', { title: '(｡ ･･｡) want something?', name: name });
});

module.exports = router;
