var express = require('express');
var router = express.Router();

// -------------------------------admin support-------------------------------

/* GET userlist. */
router.get('/userlist', function(req, res) {
  var db = req.db;
  var collection = db.get('userlist');
  collection.find({},{},function(e,docs){
    res.json(docs);
  });
});

/* POST to adduser. */
router.post('/adduser', async function(req, res) {
  var db = req.db;
  var collection = db.get('userlist');

  // no duplicate username is allowed
  var user = await collection.findOne({"username" : req.body.username});
  if(user){
    res.send({ msg: "duplicate username" });
  } else {
    collection.insert(req.body, function(err, result){
      res.send(
        (err === null) ? { msg: '' } : { msg: err }
      );
    });
  }
});

/* DELETE to deleteuser. */
router.delete('/deleteuser/:id', function(req, res) {
  var db = req.db;
  var collection = db.get('userlist');
  var userToDelete = req.params.id;
  collection.remove({ '_id' : userToDelete }, function(err) {
    res.send((err === null) ? { msg: '' } : { msg:'error: ' + err });
  });
});

// -------------------------------user support-------------------------------

/* authenticate and login user */
router.post('/authenticate', async function(req, res) {
  var db = req.db;
  var collection = db.get('userlist');
  var user = await collection.findOne({"username" : req.body.username});
  if(!user) {
    res.send({ msg: "username not exist" });
  } else {
    if(user.password !== req.body.password) {
      res.send({ msg: "password is incorrect" });
    } else {
      // sucessfully login
      req.session.regenerate(() => {
        req.session.user = user;
        console.log(
          `Session.login success: ${req.session.user.username}`
        );
        // If a match, return 200:{ username }
        res.status(200).send({
          username: user.username,
        });
      });
    }
  }
});

/* end the login user's session */
router.delete('/logout', (req, res) => {
  if (req.session.user) {
    req.session.destroy(() => {
      res.status(204).end();
    });
  } else {
    res.status(200).end();
  }
});

/* modify the login user's data */
router.put('/modify', async function(req, res) {
  // check is login
  if(!req.session.user) {
    res.send({ msg: "login first" });
    return;
  } 
  var db = req.db;
  var collection = db.get('userlist');
  var user = await collection.findOne({"username" : req.body.username});
  if(!user) {
    res.send({ msg: "username not exist" });
  } else {
    if(user.password !== req.body.password) {
      res.send({ msg: "password is incorrect" });
    } else {
      // sucessfully login
      req.session.regenerate(() => {
        req.session.user = user;
        console.log(
          `Session.login success: ${req.session.user.username}`
        );
        // If a match, return 200:{ username }
        res.status(200).send({
          username: user.username,
        });
      });
    }
  }
});

module.exports = router;
