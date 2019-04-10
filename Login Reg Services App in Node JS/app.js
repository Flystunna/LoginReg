const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const app = express();
const path = require('path');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');
const mongo = require('mongodb');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const passportLocalMongoose = require('passport-local-mongoose');
const LocalStrategy = require('passport-local').Strategy;
const async= require('async');
require('dotenv').config()

mongoose.connect('mongodb://localhost:27017/admin', { useNewUrlParser: true }, (err) => {
    if (!err) { console.log('MongoDB Connection Succeeded.') }
    else { console.log('Error in DB connection : ' + err) }
});

var db = mongoose.connection;


//passport

require('./config/passport')(passport);

//EJS
app.use(expressLayouts);
app.set('view engine', 'ejs');

//bodyparser
app.use(bodyparser.urlencoded({ extended: false}));

//Express Session
app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true,
}));

//Connect Flash
app.use(flash());


app.use(passport.initialize());
app.use(passport.session());

//Global
app.use((req, res, next) => {
	res.locals.success_msg = req.flash('success_msg');
	res.locals.error_msg = req.flash('error_msg');
	res.locals.error = req.flash('error');
	res.locals.msg = req.flash('msg');
	next();
});
//routes
app.use('/', require('./routes/index'));
app.use('/', require('./routes/users'));

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.render('contact');
});

app.post('/send', (req, res) => { 
  const output = `
    <p>You have a new contact request</p>
    <h3>Contact Details</h3>
    <ul>  
      <li>Name: ${req.body.name}</li>
      <li>Company: ${req.body.company}</li>
      <li>Email: ${req.body.email}</li>
      <li>Phone: ${req.body.phone}</li>
    </ul>
    <h3>Message</h3>
    <p>${req.body.message}</p>
  `;

 

  // create reusable transporter object using the default SMTP transport
  let transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: 'zoila.quitzon11@ethereal.email', // generated ethereal user
        pass: 'uF19DGUJ1f5xWHmfqh'  // generated ethereal password
   },
    tls:{
      rejectUnauthorized:false
    }
  });


  // setup email data with unicode symbols
  let mailOptions = {
      from: '"Nodemailer Contact" <your@email.com>', // sender address
      to: 'John.dhara@gmail.com', // list of receivers
      subject: 'Node Contact Request', // Subject line
      text: 'Hello world?', // plain text body
      html: output // html body
  };

  // send mail with defined transport object
  transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
          return console.log(error);
      }
      console.log('Message sent: %s', info.messageId);   
      console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
      req.flash('msg', 'Email has been sent');
      res.render('contact', {msg:'Email has been sent'});
  });
  });


app.listen(5000, () => {

	console.log('Express server started at port : 5000');
});