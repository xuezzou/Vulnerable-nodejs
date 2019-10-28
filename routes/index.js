var express = require('express');
var router = express.Router();

/* GET login page. */
router.get('/login', function(req, res) {
  res.render('login', { title: 'Express' });
});

module.exports = router;
