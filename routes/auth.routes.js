const { Router } = require("express");
const router = new Router();
const bcryptjs = require("bcryptjs");
const saltRounds = 10;
const User = require("../models/User.model");

router.get("/signup", (req, res) => res.render("auth/signup"));

router.post("/signup", (req, res, next) => {
  const { username, email, password } = req.body;
  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        username,
        email,
        passwordHash: hashedPassword,
      });
    })
    .then((userFromDB) => {
      res.redirect("/");
    })
    .catch((error) => next(error));
});

router.get("/userLogin", (req, res) => res.render("users/login"));

router.post("/userLogin", (req, res, next) => {
  User.findOne({ username: req.body.username })
    .then((foundUser) => {
      if (!foundUser) {
        return res.send("Username not found");
      }
      const valid = bcryptjs.compareSync(
        req.body.password,
        foundUser.passwordHash
      );
      if (!valid) {
        return res.send("Incorrect password");
      }
      res.render("users/user-profile", {foundUser});
    })
    .catch((err) => {
      console.log("Something went wrong", err);
    });
});

module.exports = router;
