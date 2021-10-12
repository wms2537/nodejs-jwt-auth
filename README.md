# Nodejs REST API JWT Authentication Backend [![Build Status](https://jenkins.wmtech.cc/job/nodejs-jwt-auth/job/main/badge/icon)](https://jenkins.wmtech.cc/job/nodejs-jwt-auth/job/main/)
A REST API jwt authentication backend using nodejs and express. This code uses mongoDB as a database. Docker is supported.

We use two collections, one for users and another for tokens. Token refreshing is supported, expired token will be discarded using TTL index of mongoDB.
Access token expiry and refresh token expiry can be tuned in the files controllers/auth.js and models/token.js.

Note that you have to recreate the index of the collection if you updated it.

Key rotation is also implemented, signing keys are changed everyday, this cron task can be modified in index.js.

A sample middleware can be found in middlewares/is-auth.js, where 3rd party apps request the public JWKS to verify the tokens.

New users are required to verify their email through a verification link.

Password reset through email is also implemented.

### Features
* Email and Passsword Sign In
* Google Sign In
* Apple Sign In
* Hcaptcha Validation
* Email verification
* Email password reset

## **Usage**
### Keypair
Keypair generation is done in [utils/keypair.js](utils/keypair.js). If you intend to change the algorithm used, please make sure you update them at signing and verifying respectively.

### JWT Audience and issuer
Please change the audience and issuer claim on signing and verifying tokens:
```js
// Signing
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

// Verifying
const { payload } = await jwtVerify(token, JWKS, {
  issuer: 'wmtech',
  audience: 'auth.wmtech.cc'
});
```

### Hcaptcha
This repo uses hcaptcha validation. Please configure hcaptcha in your frontend respectively. A sample hcaptcha server can be found [here](https://github.com/wms2537/hcaptcha).

### Nodemailer
Modify the `defaultMailOptions` in [utils/nodemailer.js](utils/nodemailer.js).
```js
const defaultMailOptions = {
  from: `WMTech <noreply.wmtech.cc>`,
  replyTo: `info@wmtech.cc`,
  subject: 'WMTech',
};
```

### Environment Variables
* SMTP_USER
  * http port to serve the backend
* SMTP_PASS
  * http port to serve the backend
* VIRTUAL_HOST
  * url to host this auth service
* HCAPTCHA_HOST
  * url to hcaptcha backend
* GOOGLE_CLIENT_ID
  * Google OAuth2 Client ID (For sign in with google)
* PORT
  * http port to serve the backend
  * default: 80
* DATABASE_URL
  * mongodb connection url
* NUM_KEYS
  * number of signing keys to generate
  * default: 5
Instead of hardcoding these values into your docker-compose.yaml, you can create a `.env` file like below:
```sh
DATABASE_URL=<your mongodb connection string>
SMTP_USER=noreply@example.com
SMTP_PASS=<password>
VIRTUAL_HOST=https://auth.example.com
HCAPTCHA_HOST=https://hcaptcha.example.com
GOOGLE_CLIENT_ID=<your google client id>
```
### Docker
Dockerfile.dev spawns up a dev server with nodemon for development.

Dockerfile is for deployment.


## **API Reference**
Here are some main api usage, more details can be found in [routes](routes/auth.js).
### POST /signup
#### Request Body
```json
{
    "email": "test@test.com",
    "password": "Te$+12#$",
    "firstName": "Test",
    "lastName": "Test",
    "phoneNumber": "0123456789",
    "token": "HCAPTCHA_TOKEN"
}
```
#### Respond
```json
{
    "message": "User created!",
    "userId": "5fd21f48601a41001dbd5aef"
}
```
### POST /login
#### Request Body
```json
{
    "email": "test@test.com",
    "password": "Te$+12#$",
    "token": "HCAPTCHA_TOKEN"
}
```
#### Respond
```json
{
    "accessToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjA5ZWE4ZmEzNjg0OWVjMjQ1M2Q0YTEyMDg3MDBjMDg2NDlmYzc2MDk1OTRjMTdjMzRmYzE0MTRmYzkxZDgyMjcifQ.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJ1c2VySWQiOiI1ZmQyMWY0ODYwMWE0MTAwMWRiZDVhZWYiLCJpYXQiOjE2MDc2MDgwMzMsImV4cCI6MTYwNzY5NDQzM30.AAAAAANnSrz4foRuIGGhj46YRajaKO0dHLoKqHJLKLoAAAAAfbmYrk9WMFWmsG9yUPZdQCxug6kGMJEIgHUIfA",
    "refreshToken": "rdhXgbg3qMOvyK1gKwlLu/BA9uHExQ8PlpbSpMGLeJFEXfV8bGCj3n5/R+aXZOEzWovXTu+tirUuJPIycuXc45cQRPYh6LGG+WerPqfHnYaUlpTL6cic5q2vV5Vu491CSRt8X8ku3bIbJ0W2rJe3lvPKYkGEYbPoADdf4O6zac8=",
    "userId": "5fd21f48601a41001dbd5aef",
    "accessTokenExpiry": "2020-12-11T13:47:13.476Z",
    "refreshTokenExpiry": "2020-12-17T13:47:13.476Z",
    "firstName": "Test",
    "lastName": "Test",
    "phoneNumber": "0123456789",
    "activeStatus": false
}
```
### GET /publicKey
#### Respond
```json
{
  "keys": [
    {
      "crv": "Ed25519",
      "x": "26aHwydSBgeHHwVZbXMNcodveH8ykSn9MkUAHz54ytU",
      "kty": "OKP",
      "kid": "_GZeiv4vxFZ2OQZa8h7EL748wdwM-FUKT1K4UNnI7dU"
    },
    {
      "crv": "Ed25519",
      "x": "DGyZGOJ7jtSlZmghTnuzRxbKT6bL_2ElbIMitxqfQ-s",
      "kty": "OKP",
      "kid": "EPH8CmjuBBTEfLu8pUdE1p9zxtdBSk2YBsT4Yb9xSxc"
    },
    {
      "crv": "Ed25519",
      "x": "Vm2Oxs3Lklh80VYPKoT0oEQJePcUP-MMcrZDAtA_lUI",
      "kty": "OKP",
      "kid": "FvUPAADB8_zbDM1q8YPsRM1YwfAYxdvj-nuC-MIBg7I"
    },
    {
      "crv": "Ed25519",
      "x": "ymFWqJ6PUhxAcZkdd1WyTpDOuJvXTEe7grQgh_TVoGM",
      "kty": "OKP",
      "kid": "ioHpY3gFXb-HQYBp1GErKLLmPxcUR46sjFn9nphpoCE"
    },
    {
      "crv": "Ed25519",
      "x": "IR3eArUllksgC_1s1nHKZCbLz2_wdcz-5va8mEKKZy0",
      "kty": "OKP",
      "kid": "_I0VXkaAbQ4HFWk261OZG1wbuRBDLCRAJ6IiW4xBx18"
    }
  ]
}
```
### POST /refreshToken
#### Request Body
```json
{
    "accessToken": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjA5ZWE4ZmEzNjg0OWVjMjQ1M2Q0YTEyMDg3MDBjMDg2NDlmYzc2MDk1OTRjMTdjMzRmYzE0MTRmYzkxZDgyMjcifQ.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJ1c2VySWQiOiI1ZmQyMWY0ODYwMWE0MTAwMWRiZDVhZWYiLCJpYXQiOjE2MDc2MDgwMzMsImV4cCI6MTYwNzY5NDQzM30.AAAAAANnSrz4foRuIGGhj46YRajaKO0dHLoKqHJLKLoAAAAAfbmYrk9WMFWmsG9yUPZdQCxug6kGMJEIgHUIfA",
    "refreshToken": "rdhXgbg3qMOvyK1gKwlLu/BA9uHExQ8PlpbSpMGLeJFEXfV8bGCj3n5/R+aXZOEzWovXTu+tirUuJPIycuXc45cQRPYh6LGG+WerPqfHnYaUlpTL6cic5q2vV5Vu491CSRt8X8ku3bIbJ0W2rJe3lvPKYkGEYbPoADdf4O6zac8="
}
```
#### Respond
```json
{
    "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjA5ZWE4ZmEzNjg0OWVjMjQ1M2Q0YTEyMDg3MDBjMDg2NDlmYzc2MDk1OTRjMTdjMzRmYzE0MTRmYzkxZDgyMjcifQ.eyJ1c2VySWQiOiI1ZmQyMWY0ODYwMWE0MTAwMWRiZDVhZWYiLCJpYXQiOjE2MDc2MDg3MDUsImV4cCI6MTYwNzY5NTEwNX0.AAAAAISgA-S1UllqAni924esohWowfEqOei38FEHeegAAAAAdFM0e-sKpoRhYFnHtvYZCGEmE8M2s0_Q2IbG-w",
    "userId": "5fd21f48601a41001dbd5aef",
    "accessTokenExpiry": "2020-12-11T13:58:25.687Z"
}
```