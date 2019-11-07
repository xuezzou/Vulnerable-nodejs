var express = require('express');
var router = express.Router();

// -------------------------------admin support-------------------------------

/* GET userlist. */
router.get('/userlist', function (req, res) {
  var db = req.db;
  var collection = db.get('userlist');
  collection.find({}, {}, function (e, docs) {
    res.json(docs);
  });
});

/* POST to adduser. */
router.post('/adduser', async function (req, res) {
  var db = req.db;
  var collection = db.get('userlist');

  // no duplicate username is allowed
  var user = await collection.findOne({ "username": req.body.username });
  if (user) {
    res.send({ msg: "duplicate username" });
  } else {
    collection.insert(req.body, function (err, result) {
      res.send(
        (err === null) ? { msg: '' } : { msg: err }
      );
    });
  }
});

/* DELETE to deleteuser. */
router.delete('/deleteuser/:id', function (req, res) {
  var db = req.db;
  var collection = db.get('userlist');
  var userToDelete = req.params.id;
  collection.remove({ '_id': userToDelete }, function (err) {
    res.send((err === null) ? { msg: '' } : { msg: 'error: ' + err });
  });
});

// -------------------------------user support-------------------------------

/* authenticate and login user */
router.post('/session', async function (req, res) {
  // session exists and send it back
  if (req.session.user) {
    res.send({ user: req.session.user });
  } else {
    // check the field should not be blank
    if (req.body.username === '' || req.body.password === '') {
      res.send({ msg: "Please fill in all fields" }).end();
    }
    // query for the username
    var db = req.db;
    var collection = db.get('userlist');
    var user = await collection.findOne({ username: req.body.username, password: req.body.password });
    if (!user) {
      res.send({ msg: "unauthorized" });
    } else {
      // sucessfully login
      try {
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
      } catch (err) {
        console.log(err);
      }

    }
  }
});

/* delete a user's session */
router.delete('/session', (req, res) => {
  if (req.session.user) {
    console.log(
      `Session.login destroy: ${req.session.user.username}`
    );
    req.session.destroy(() => {
      res.status(204).end();
    });
  }
});

/* get info of the current user in session */
router.get('/', (req, res) => {
  if (req.session.user) {
    res.status(200).send({ user: req.session.user }).end();
  } else {
    res.send({ msg: "Something bad happens" });
  }
});

/* modify the login user's data */
router.put('/modify', async function (req, res) {
  // check is login
  if (!req.session.user) {
    res.send({ msg: "login first" }).end();
  } else {
    var db = req.db;
    var collection = db.get('userlist');
    var query = req.body;
    // update the corresponding fields
    collection.findOneAndUpdate({ 'username': req.session.user.username }, { $set: query }, function (err, result) {
      // update session too
      if (result) {
        req.session.user = result;
      }
      res.send(
        (err === null) ? { msg: '' } : { msg: err }
      );
    });
  }
});

module.exports = router;
