const jwt = require('jsonwebtoken');

const jwksClient = require('jwks-rsa');

const client = jwksClient({
  strictSsl: false, // Default value
  rateLimit: true,
  jwksUri: `http://localhost:${process.env.PORT || 8080}/.well-known/jwks.json`,
  timeout: 30000, // Defaults to 30s
});

// const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
// client.getSigningKey(kid, (err, key) => {
//   const signingKey = key.getPublicKey();

//   // Now I can use this to configure my Express or Hapi middleware
// });

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
      algorithm: 'RS256',
    });
    const kid = decoded.header.kid;
    const key = await client.getSigningKeyAsync(kid);
    const decodedToken = jwt.verify(token, key.rsaPublicKey, {
      algorithms: ['RS256']
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

exports.isAuthWS = async (token) => {
  try {
    const decoded = jwt.decode(token, {
      complete: true,
      algorithm: 'RS256',
    });
    const kid = decoded.header.kid;
    const key = await client.getSigningKeyAsync(kid);
    const decodedToken = jwt.verify(token, key.rsaPublicKey, {
      algorithms: ['RS256']
    }, );
    if (!decodedToken) {
      return false;
    }
    return decodedToken.userId;
  } catch (err) {
    return false;
  }
};