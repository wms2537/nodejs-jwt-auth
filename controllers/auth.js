const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const {
  validationResult
} = require('express-validator');
const bcrypt = require('bcrypt');
const { importJWK } = require('jose/key/import');
const { SignJWT } = require('jose/jwt/sign');
const { createRemoteJWKSet } = require('jose/jwks/remote');
const { jwtVerify } = require('jose/jwt/verify');
const { OAuth2Client } = require('google-auth-library');

// const JWT_SECRET = fs.readFileSync('./.private/rsaPrivateKey.key');
const ACCESS_TOKEN_EXPIRY = 24*3600*1000;
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000;
const User = require('../models/user');
const Token = require('../models/token');
const { validateToken } = require('../utils/hcaptcha');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/nodemailer');
const { getSuccessTemplate, getFailedTemplate } = require('../templates/templates');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.signup = async(req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }
    const token = req.body.token;
    const tokenValidationResult = await validateToken(token);
    if (!tokenValidationResult) {
      const error = new Error('Captcha Validation failed.');
      error.statusCode = 422;
      throw error;
    }
    const email = req.body.email;
    const password = req.body.password;
    const firstName = req.body.firstName;
    const lastName = req.body.lastName;
    const phoneNumber = req.body.phoneNumber;
    const hashedPw = await bcrypt.hash(password, 12);
    const rndString = crypto.randomBytes(64).toString('hex') + ':' + (new Date()).toISOString();
    const user = new User({
      email,
      password: hashedPw,
      firstName,
      lastName,
      phoneNumber,
      emailVerificationToken: rndString
    });
    const result = await user.save();
    const verificationToken = result._id + ':' + rndString;
    await sendVerificationEmail(firstName, email, verificationToken);

    res.status(201).json({
      message: 'User created!',
      userId: result._id
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.login = async(req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }

    const token = req.body.token;
    const tokenValidationResult = await validateToken(token);
    if (!tokenValidationResult) {
      const error = new Error('Captcha Validation failed.');
      error.statusCode = 422;
      throw error;
    }
    const email = req.body.email;
    const password = req.body.password;

    const user = await User.findOne({
      email: email
    });
    if (!user) {
      const error = new Error('A user with this email could not be found.');
      error.statusCode = 401;
      throw error;
    }
    const isEqual = await bcrypt.compare(password, user.password);

    if (!isEqual) {
      const error = new Error('Wrong password!');
      error.statusCode = 401;
      throw error;
    }

    if (!user.emailVerified) {
      const error = new Error('Email not verified, please verify on your email!');
      error.statusCode = 401;
      throw error;
    }
    const jwks = JSON.parse((await fs.readFile(path.join(__dirname, '..', '.private', 'keys.json'))).toString());
    const jwk = jwks[Math.floor(Math.random() * jwks.length)];
    const privateKey = await importJWK(jwk, 'EdDSA');
    const accessTokenExpiry = new Date(Date.now() + ACCESS_TOKEN_EXPIRY);
    const accessToken = await new SignJWT({
      email: user.email,
      userId: user._id.toString(),
     })
      .setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
      .setIssuedAt()
      .setIssuer('wmtech')
      .setAudience('auth.wmtech.cc')
      .setExpirationTime(accessTokenExpiry.getTime())
      .sign(privateKey);
    const refreshToken = crypto.randomBytes(128).toString('base64');
    const mytoken = Token({
      accessToken,
      refreshToken,
      userId: user._id
    });
    await mytoken.save();
    res.status(200).json({
      accessToken,
      refreshToken,
      userId: user._id.toString(),
      accessTokenExpiry: accessTokenExpiry.toISOString(),
      refreshTokenExpiry: (new Date(Date.now() + REFRESH_TOKEN_EXPIRY)).toISOString(),
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
      activeStatus: user.activeStatus,
      googleAuthEnabled: user.googleAuthId !== undefined,
      appleAuthEnabled: user.appleAuthId !== undefined,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.signInWithApple = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }
    const JWKS = createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'));
    const { payload } = await jwtVerify(req.body.token, JWKS);
    if(!payload['email_verified']) {
      const error = new Error('Email not verified (Apple)!');
      error.statusCode = 401;
      throw error;
    }
    const user = await User.findOne({
      email: payload['email']
    });
    if (!user) {
      return res.status(200).json({message: 'Sign Up'});
    }
    const jwks = JSON.parse((await fs.readFile(path.join(__dirname, '..', '.private', 'keys.json'))).toString());
    const jwk = jwks[Math.floor(Math.random() * jwks.length)];
    const privateKey = await importJWK(jwk, 'EdDSA');
    const accessTokenExpiry = new Date(Date.now() + ACCESS_TOKEN_EXPIRY);
    const accessToken = await new SignJWT({
      email: user.email,
      userId: user._id.toString(),
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
      .setIssuedAt()
      .setIssuer('wmtech')
      .setAudience('auth.wmtech.cc')
      .setExpirationTime(accessTokenExpiry.getTime())
      .sign(privateKey);
    const refreshToken = crypto.randomBytes(128).toString('base64');
    const mytoken = Token({
      accessToken,
      refreshToken,
      userId: user._id
    });
    await mytoken.save();
    res.status(200).json({
      accessToken,
      refreshToken,
      userId: user._id.toString(),
      accessTokenExpiry: accessTokenExpiry.toISOString(),
      refreshTokenExpiry: (new Date(Date.now() + REFRESH_TOKEN_EXPIRY)).toISOString(),
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
      activeStatus: user.activeStatus,
      googleAuthEnabled: user.googleAuthId !== undefined,
      appleAuthEnabled: user.appleAuthId !== undefined,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.signUpWithApple = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }
    const token = req.body.token;
    const JWKS = createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'));
    const { payload } = await jwtVerify(token, JWKS);
    if (!payload['email_verified']) {
      const error = new Error('Email not verified (Apple)!');
      error.statusCode = 401;
      throw error;
    }
    const email = payload['email'];
    const password = req.body.password;
    const firstName = req.body.firstName;
    const lastName = req.body.lastName;
    const phoneNumber = req.body.phoneNumber;
    const hashedPw = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      password: hashedPw,
      firstName,
      lastName,
      phoneNumber,
      emailVerified: true,
      appleAuthId: payload['sub']
    });
    const result = await user.save();
    res.status(201).json({
      message: 'User created!',
      userId: result._id
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.signInWithGoogle = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }
    const token = req.body.token;
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload['email_verified']) {
      const error = new Error('Email not verified (Google)!');
      error.statusCode = 401;
      throw error;
    }
    // If request specified a G Suite domain:
    // const domain = payload['hd'];
    const email = payload['email'];
    const user = await User.findOne({
      email: email
    });
    if (!user) {
      return res.status(200).json({ 
        message: 'Sign Up',
        firstName: payload['given_name'],
        lastName: payload['family_name'],
      });
    }
    const jwks = JSON.parse((await fs.readFile(path.join(__dirname, '..', '.private', 'keys.json'))).toString());
    const jwk = jwks[Math.floor(Math.random() * jwks.length)];
    const privateKey = await importJWK(jwk, 'EdDSA');
    const accessTokenExpiry = new Date(Date.now() + ACCESS_TOKEN_EXPIRY);
    const accessToken = await new SignJWT({
      email: user.email,
      userId: user._id.toString(),
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
      .setIssuedAt()
      .setIssuer('wmtech')
      .setAudience('auth.wmtech.cc')
      .setExpirationTime(accessTokenExpiry.getTime())
      .sign(privateKey);
    const refreshToken = crypto.randomBytes(128).toString('base64');
    const mytoken = Token({
      accessToken,
      refreshToken,
      userId: user._id
    });
    await mytoken.save();
    res.status(200).json({
      accessToken,
      refreshToken,
      userId: user._id.toString(),
      accessTokenExpiry: accessTokenExpiry.toISOString(),
      refreshTokenExpiry: (new Date(Date.now() + REFRESH_TOKEN_EXPIRY)).toISOString(),
      firstName: user.firstName,
      lastName: user.lastName,
      phoneNumber: user.phoneNumber,
      activeStatus: user.activeStatus,
      googleAuthEnabled: user.googleAuthId !== undefined,
      appleAuthEnabled: user.appleAuthId !== undefined,
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.signUpWithGoogle = async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }
    const token = req.body.token;
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload['email_verified']) {
      const error = new Error('Email not verified (Google)!');
      error.statusCode = 401;
      throw error;
    }
    const email = payload['email'];
    const password = req.body.password;
    const firstName = req.body.firstName;
    const lastName = req.body.lastName;
    const phoneNumber = req.body.phoneNumber;
    const hashedPw = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      password: hashedPw,
      firstName,
      lastName,
      phoneNumber,
      emailVerified: true,
      googleAuthId: payload['sub']
    });
    const result = await user.save();
    res.status(201).json({
      message: 'User created!',
      userId: result._id
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.getPublicKey = async(req, res, next) => {
  try {
    const keyPath = path.join(__dirname, '..', '.public', 'keys.json')
    const publicKeys = JSON.parse((await fs.readFile(keyPath)).toString());
    res.status(200).json({keys: publicKeys});
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
}

exports.sendVerificationEmail = async(req, res, next) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    if (!user.emailVerified) {
      const rndString = crypto.randomBytes(64).toString('hex') + ':' + (new Date()).toISOString();
      user.emailVerificationToken = rndString;
      await user.save();
      const token = userId + ':' + rndString;
      await sendVerificationEmail(user.firstName, user.email, token);
    }
    res.status(200).json({
      message: 'Success'
    });
  } catch (error) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
}

exports.verifyEmail = async(req, res, next) => {
  try {
    const token = req.params.token.split(':');
    const userId = token.shift();
    const verificationCode = token.join(':');
    const user = await User.findById(userId);
    res.set('Content-Type', 'text/html');
    if (user.emailVerified) {
      user.emailVerificationToken = undefined;
      await user.save();
      res.send(Buffer.from(getSuccessTemplate('Email Verification Success', 'Thanks for registering!')));
    }
    if (user.emailVerificationToken !== verificationCode) {
      res.send(Buffer.from(getFailedTemplate('Email Verification Failed', 'Verification Code Error!')));
    }
    const createdDate = new Date(verificationCode.split(':').pop());
    const dateNow = new Date();
    if (Math.abs(dateNow.getTime() - createdDate.getTime) > 1000 * 60 * 15) {
      res.send(Buffer.from(getFailedTemplate('Email Verification Failed', 'Token Expired!')));
    }
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();
    res.send(Buffer.from(getSuccessTemplate('Email Verification Success', 'Thanks for registering!')));
  } catch (error) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

exports.sendPasswordResetEmail = async(req, res, next) => {
  try {
    const token = req.body.token;
    const tokenValidationResult = await validateToken(token);
    if (!tokenValidationResult) {
      const error = new Error('Captcha Validation failed.');
      error.statusCode = 422;
      throw error;
    }
    const email = req.params.email;
    const user = await User.findOne({ email });
    if (!user) {
      const error = new Error(`User with email ${email} not found!`);
      error.statusCode = 404;
      throw error;
    }
    const rndString = crypto.randomBytes(64).toString('hex') + ':' + (new Date()).toISOString();
    user.passwordChangeToken = rndString;
    await user.save();
    const mytoken = user._id + ':' + rndString;
    await sendPasswordResetEmail(user.firstName, user.email, mytoken);
    res.status(200).json({
      message: 'Success'
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
}

exports.resetPassword = async(req, res, next) => {
  try {
    const token = req.params.token.split(':');
    const userId = token.shift();
    const verificationCode = token.join(':');
    const user = await User.findById(userId);
    res.set('Content-Type', 'text/html');
    if (user.passwordChangeToken !== verificationCode) {
      res.send(Buffer.from(getFailedTemplate('Email Verification Failed', 'Verification Code Error!')));
    }
    const createdDate = new Date(verificationCode.split(':').pop());
    const dateNow = new Date();
    if (Math.abs(dateNow.getTime() - createdDate.getTime) > 1000 * 60 * 15) {
      res.send(Buffer.from(getFailedTemplate('Email Verification Failed', 'Token Expired!')));
    }
    const password = req.query.psw;
    const hashedPw = await bcrypt.hash(password, 12);
    user.password = hashedPw;
    user.passwordChangeToken = undefined;
    await user.save();
    res.send(Buffer.from(getSuccessTemplate('Password Update Success', 'You can login with your new password now!')));
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
}

exports.getEmailAvailability = async(req, res, next) => {
  try {
    const email = req.params.email;
    const user = await User.findOne({
      email
    });
    if (user) {
      res.status(200).json({
        result: true
      });
    }
    res.status(200).json({
      result: false
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
}

exports.getPhoneNumberAvailability = async(req, res, next) => {
  try {
    const phoneNumber = req.params.phoneNumber;
    const user = await User.findOne({
      phoneNumber
    });
    if (user) {
      res.status(200).json({
        result: true
      });
    }
    res.status(200).json({
      result: false
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
}

exports.refreshToken = async(req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array().map(e => `Error in ${e.param}: ${e.msg}`).join('\n');
      throw error;
    }
    const accessToken = req.body.accessToken;
    const refreshToken = req.body.refreshToken;
    const token = await Token.findOne({
      refreshToken,
      accessToken
    }).populate('user');
    if (!token) {
      const error = new Error('Refresh Token Error!');
      error.statusCode = 401;
      throw error;
    }
    const jwks = JSON.parse((await fs.readFile(path.join(__dirname, '..', '.private', 'keys.json'))).toString());
    const jwk = jwks[Math.floor(Math.random() * jwks.length)];
    const privateKey = await importJWK(jwk, 'EdDSA');
    const newAccessToken = await new SignJWT({
      username: token.userId.username,
      userId: token.userId._id.toString()
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
      .setIssuedAt()
      .setIssuer('wmtech')
      .setAudience('auth.wmtech.cc')
      .setExpirationTime(ACCESS_TOKEN_EXPIRY)
      .sign(privateKey);
    token.accessToken = newAccessToken;
    await token.save();
    res.status(200).json({
      token: newAccessToken,
      userId: token.userId._id.toString(),
      accessTokenExpiry: (new Date(Date.now() + ACCESS_TOKEN_EXPIRY)).toISOString()
    });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};