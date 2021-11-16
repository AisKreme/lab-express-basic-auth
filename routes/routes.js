const router = require("express").Router();
const UserModel = require("../models/User.model");
const bcrypt = require("bcryptjs");

//
// SIGN UP
//

router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;

  if (username == "" || password == "") {
    res.render("auth/signup.hbs", { error: "Please enter all fields" });
    return;
  }

  let passRegEx = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{4,}$/;
  if (!passRegEx.test(password)) {
    res.render("auth/signup.hbs", {
      error: "pick better password",
    });
    return;
  }

  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);

  UserModel.create({ username, password: hash })
    .then(() => {
      res.redirect("/");
    })
    .catch((err) => {
      next(err);
    });
});

//
//  SIGN IN
//

router.get("/signin", (req, res, next) => {
  res.render("auth/signin.hbs");
});

router.post("/signin", (req, res, next) => {
  const { username, password } = req.body;

  UserModel.find({ username })
    .then((name) => {
      if (name.length) {
        let userObj = name[0];

        let isMatching = bcrypt.compareSync(password, userObj.password);

        if (isMatching) {
          req.session.property = userObj;

          res.redirect("/main");
        } else {
          res.render("auth/signin.hbs", { error: "wrong password" });
          return;
        }
      } else {
        res.render("auth/signin.hbs", { error: "wrong username" });
        return;
      }
    })
    .catch((err) => {
      next(err);
    });
});

//
// MAIN
//

const checkLogin = (req, res, next) => {
  if (req.session.property) {
    next();
  } else {
    res.redirect("/signin");
  }
};

router.get("/main", checkLogin, (req, res, next) => {
  let userInfo = req.session.property;
  if (userInfo) {
    res.render("auth/main.hbs", { name: userInfo.username });
  } else {
    res.redirect("/signin");
  }
});

//
// PRIVATE
//

router.get("/private", checkLogin, (req, res, next) => {
  let userInfo = req.session.property;
  if (userInfo) {
    res.render("auth/private.hbs", { name: userInfo.username });
  } else {
    res.redirect("/signin");
  }
});
module.exports = router;
