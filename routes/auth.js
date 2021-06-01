const express = require('express');
const {
  body
} = require('express-validator');

const User = require('../models/user');
const authController = require('../controllers/auth');

const router = express.Router();

router.post(
  '/signup', [
    body('email')
    .isEmail()
    .withMessage('Please enter a valid email.')
    .custom((value, {
      req
    }) => {
      return User.findOne({
        email: value
      }).then(userDoc => {
        if (userDoc) {
          return Promise.reject('E-Mail address already registered!');
        }
      });
    })
    .normalizeEmail(),
    body('password')
    .trim()
    .isLength({
      min: 5
    }),
    body('firstName')
    .trim()
    .notEmpty(),
    body('lastName')
    .trim()
    .notEmpty(),
    body('phoneNumber')
    .trim()
    .notEmpty()
    .custom((value, {
      req
    }) => {
      return User.findOne({
        phoneNumber: value
      }).then(userDoc => {
        if (userDoc) {
          return Promise.reject('Phone number already registered!');
        }
      });
    }),
    body('token')
    .trim()
    .notEmpty()
  ],
  authController.signup
);

router.post('/login', [
  body('email')
  .notEmpty()
  .trim(),
  body('password')
  .trim()
  .isLength({
    min: 5
  }),
  body('token')
  .trim()
  .notEmpty()
], authController.login);

router.get('/publicKey/:kid', authController.getPublicKey);

router.post('/refreshToken', [
  body('accessToken')
  .notEmpty()
  .trim(),
  body('refreshToken')
  .notEmpty()
  .trim()
], authController.refreshToken);


module.exports = router;