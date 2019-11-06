var express = require('express');
var router = express.Router();

/* GET secret page. */
router.get('/pikachu', function(req, res) {
  res.render('pikachu', { title: 'Hey' });
});

module.exports = router;
