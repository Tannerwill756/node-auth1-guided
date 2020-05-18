const bcryptjs = require("bcryptjs");

const router = require("express").Router();

const Users = require("../users/users-model");
const { isValid } = require("../users/users-service");

router.post("/register", (req, res) => {
  const credentials = req.body;

  if (isValid(credentials)) {
    const rounds = process.env.BCRYPT_ROUNDS || 8;

    // hash the password
    const hash = bcryptjs.hashSync(credentials.password, rounds);

    credentials.password = hash;

    Users.add(credentials)
      .then((user) => {
        res.status(201).json({ data: user });
      })
      .catch((err) => {
        res.status(500).json({ error: err.message });
      });
  } else {
    res.status(400).json({
      message: "Please provide username and password that is a string",
    });
  }
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (isValid(req.body)) {
    Users.findBy({ username: username })
      .then(([user]) => {
        // compare the password to the hash stored in the database
        if (user && bcryptjs.compareSync(password, user.password)) {
          //create a session and send a cookie back ( the cookie will store the session id)
          // we can save information about the client inside the session (req.sesion)
          req.session.loggedIn = true;
          req.session.user = user;

          res.status(200).json({ message: "Welcome to our API" });
        } else {
          res.status(401).json({ message: "Invalid Credentials" });
        }
      })
      .catch((err) => {
        res.status(500).json({ error: err.message });
      });
  } else {
    res.status(400).json({
      message: "Please provide username and password that is a string",
    });
  }
});

router.get("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        res
          .status(500)
          .json({ message: "we could not log you out, try later" });
      } else {
        res.status(204).end();
      }
    });
  } else {
    res.status(204).end();
  }
});
module.exports = router;
