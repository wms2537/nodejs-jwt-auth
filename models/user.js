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
  activeStatus: {
    type: Boolean,
    default: false
  },
}, {
  timestamps: true
});

userSchema.index({email: 'unique'});


module.exports = mongoose.model('User', userSchema);