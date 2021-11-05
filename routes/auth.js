const path = require('path');

const express = require('express');
const {
  body
} = require('express-validator');

const User = require('../models/user');
const authController = require('../controllers/auth');
const { isAuth } = require('../middlewares/is-auth');

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

router.post('/sign_in_with_email_password', [
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
], authController.signInWithEmailPassword, authController.handleSignIn);

router.post("/sign_in_with_apple", [
  body('token')
    .trim()
    .notEmpty()
], authController.signInWithApple, authController.handleSignIn);

router.post("/sign_up_with_apple", [
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
], authController.signUpWithApple);

router.post("/sign_in_with_google", [
  body('token')
    .trim()
    .notEmpty()
], authController.signInWithGoogle, authController.handleSignIn);

router.post("/sign_up_with_google", [
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
], authController.signUpWithGoogle);

router.post('/enable2FA', isAuth, authController.enable2FA);

router.post('/disable2FA', isAuth, authController.disable2FA);

router.post('/setupOtp', isAuth, authController.setupOtp);

router.post('/disableOtp', isAuth, authController.disableOtp);

router.post("/validateOtp", [
  body('email')
    .notEmpty()
    .trim(),
  body('token')
    .trim()
    .notEmpty()
], authController.validateOtp, authController.handleSignIn);

router.get('/sendVerificationEmail', isAuth, authController.sendVerificationEmail);

router.get('/verifyEmail/:token', authController.verifyEmail);

router.post('/sendPasswordResetEmail/:email', [body('token')
  .trim()
  .notEmpty()
], authController.sendPasswordResetEmail);

router.get('/resetPassword/:token', authController.resetPassword);

router.get('/resetPassword', (req, res, next) => res.sendFile(path.join(__dirname, '..', 'templates', 'reset_password.html')));

router.get('/emailAvailability/:email', authController.getEmailAvailability);

router.get('/phoneNumberAvailability/:phoneNumber', authController.getPhoneNumberAvailability);

router.get('/publicKey', authController.getPublicKey);

router.post('/refreshToken', [
  body('accessToken')
    .notEmpty()
    .trim(),
  body('refreshToken')
    .notEmpty()
    .trim()
], authController.refreshToken);


module.exports = router;