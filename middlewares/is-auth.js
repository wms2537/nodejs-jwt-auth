const axios = require('axios');
const { createRemoteJWKSet } = require('jose/jwks/remote');
const { jwtVerify } = require('jose/jwt/verify');
const BACKEND_URL = 'http://localhost:80';
const JWKS = createRemoteJWKSet(new URL(`${BACKEND_URL}/auth/publicKey`));

exports.isAuth = async (req, res, next) => {
  try {
    const authHeader = req.get('Authorization');
    if (!authHeader) {
      const error = new Error('Not authenticated.');
      error.statusCode = 401;
      throw error;
    }
    const token = authHeader.split(' ')[1];
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: 'wmtech',
      audience: 'auth.wmtech.cc'
    });

    if (!payload) {
      const error = new Error('Not authenticated.');
      error.statusCode = 401;
      throw error;
    }
    req.userId = payload['userId'];
    console.log(req.userId);
    next();
  } catch (err) {
    if(!err.statusCode){
      err.statusCode = 500;
    }
    next(err);
  }
};
