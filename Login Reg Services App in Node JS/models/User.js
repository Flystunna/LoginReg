const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  profession: {
    type: String, 
    required: true
  },
  isAdmin: {
    type: Boolean, 
    default: false
  },
  phone: {
    type: Number, 
    required: true
  },
  info: {
    type: String,
    required: true
  },
  resetPasswordToken: String,  
  resetPasswordExpires: Date,
});

const User = mongoose.model('User', UserSchema);

UserSchema.plugin(passportLocalMongoose);

module.exports = User;