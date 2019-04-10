const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const flash = require('connect-flash');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const async = require('async');
const nodemailer = require('nodemailer')
const mongoose = require('mongoose');;
const passportLocalMongoose = require('passport-local-mongoose');
const {ensureAuthenticated} = require('../config/auth');
const {checkUser} = require('../config/auth');
require('dotenv').config()
//usermodel
const User = require('../models/User');

var app = express();
app.use(flash());
// Login Page
router.get('/login', (req, res) => res.render('Login'));
//Main Page
router.get('/main', (req, res) => res.render('main', {layout:'layot'})
  );

// about Page
router.get('/contact', (req, res) => res.render('contact'));

//master page
router.get('/master', checkUser, ensureAuthenticated, (req, res) => {
   var noMatch = null;
    if(req.query.search) {
        const regex = new RegExp(escapeRegex(req.query.search), 'gi');
        // Get all campgrounds from DB
        User.find({name: regex}, function(err, user){
           if(err){
               console.log(err);
           } else {
              if(user.length < 1) {
                  noMatch = "No campgrounds match that query, please try again.";
              }
              res.render('master',{user:user, noMatch: noMatch});
           }
        });
    } else {
        mongoose.model("User"). find(function(err, user) {
    if (err) {
      res.send ("Error Occurred");
    }
    res.render('master', {
      user: user
    });
  })
    }
 
});

// Register Page
router.get('/register', (req, res) => res.render('Register'));

router.post('/register', (req, res) => {
	const { name, email, username, password, password2, profession, phone, info } = req.body;
  let errors = [];

  //check required fields
  if (!name || !email || !password || !password2 || !profession || !phone || !info) {
    errors.push({ msg: 'Please enter all fields' });
  }

  //check passwords match
  if (password !== password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  //check password length 

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
  	res.render('register', {
      errors,
      name,
      email,
      password,
      password2,
      phone,
      profession,
      info 		
  	});
  } else {
  	// Validation
  	User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email is already registered' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2,
          phone,
          profession,
          info
        });
      } else {
    // Validation
    User.findOne({ name: name }).then(user => {
      if (user) {
        errors.push({ msg: 'name is already registered' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2,
          phone,
          profession,
          info
        });
      } else {
        const newUser = new User({
          name,
          email,
          password,
          phone,
          profession,
          info
        });

        //Hash Password
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                res.redirect('/login');
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  	  }
  	});
  }
});

// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
  })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/login');
});

var user = new User();

//forgot Password
router.get('/forgot', (req, res) =>{
  res.render('forgot');
});

router.post('/forgot', (req, res) => {
    async.waterfall([
    (done) => {
      crypto.randomBytes(20, (err, buf) => {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    (token, done) => {
      User.findOne({ email: req.body.email }, (err, user) => {
        if (!user) {
          req.flash('error', 'If the email matches an account, a link will be sent.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    (token, user, done) => {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: 'process.env.DB_USER',
          pass: 'process.env.DB_PASS'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'flystunna1@gmail.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, (err) => {
        console.log('mail sent');
        req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], (err) => {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});
router.get('/reset/:token', (req, res) => {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {token: req.params.token});
  });
});

router.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {token: req.params.token});
  });
});

router.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error_msg', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        if(req.body.password === req.body.confirm) {

          user.hash_password = bcrypt.hashSync(req.body.password, 10);
           user.password = req.body.password; 
            user.save();
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;
             bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) throw err;
            user.password = hash;
            next();
          });
          });
            user.save(function(err) {
              req.logIn(user, function(err) {
                done(err, user);
              });
            });
        } else {
            req.flash('error_msg', 'Passwords do not match.');
            return res.redirect('back');
        }
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: 'process.env.DB_USER',
          pass: 'process.env.DB_PASS'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'flystunna1@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/dashboard');
  });
});

router.get('/display/:id', function(req, res){
  console.log(req.params.id);
  User.findById(req.params.id, function(err, user) {
    if (err) {
      console.log(err);
    } else {
      res.render('display',  {user:user});
    }
  });
});
function escapeRegex(text) {
    return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
};
module.exports = router;
/*Hash Password
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) throw err;
            user.password = hash;
            next();
          });
        });
        */