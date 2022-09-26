const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const tokenSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  accessToken: {
    type: String,
    required: true
  },
  refreshToken: {
    type: String,
    required: true
  },
  device: {
    type: String
  }
}, {
  timestamps: true
});

tokenSchema.index({createdAt: 1}, {expireAfterSeconds: 7*24*60*60});

module.exports = mongoose.model('Token', tokenSchema);
