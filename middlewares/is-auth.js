const jwt = require('jsonwebtoken');
const axios = require('axios');

const BACKEND_URL = 'http://localhost:5000';

exports.isAuth = async (req, res, next) => {
  try {
    const authHeader = req.get('Authorization');
    if (!authHeader) {
      const error = new Error('Not authenticated.');
      error.statusCode = 401;
      throw error;
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.decode(token, {
      complete: true,
      algorithm: 'ES256',
    });
    const kid = decoded.header.kid;
    const key = await axios.get(`${BACKEND_URL}/auth/getPublicKey/${kid}`);
    const decodedToken = jwt.verify(token, key.data.publicKey, {
      algorithms: ['ES256']
    }, );
    if (!decodedToken) {
      const error = new Error('Not authenticated.');
      error.statusCode = 401;
      throw error;
    }
    req.userId = decodedToken.userId;
    next();
  } catch (err) {
    if(!err.statusCode){
      err.statusCode = 500;
    }
    next(err);
  }
};
