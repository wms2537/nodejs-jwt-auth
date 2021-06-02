const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  firstName: {
    type: String,
    required: true
  },
  lastName: {
    type: String,
    required: true,
  },
  phoneNumber: {
    type: String,
    required: true
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  phoneNumberVerified: {
    type: Boolean,
    default: false
  },
  activeStatus: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String
  }
}, {
  timestamps: true
});

userSchema.index({ email: 'unique' });


module.exports = mongoose.model('User', userSchema);