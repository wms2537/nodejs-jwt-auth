# Nodejs REST API JWT Authentication Backend [![Build Status](https://jenkins.wmtech.cc/job/nodejs-jwt-auth/job/main/badge/icon)](https://jenkins.wmtech.cc/job/nodejs-jwt-auth/job/main/)
A REST API jwt authentication backend using nodejs and express. This code uses mongoDB as a database. Docker is supported.

We use two collections, one for users and another for tokens. Token refreshing is supported, expired token will be discarded using TTL index of mongoDB.
Access token expiry and refresh token expory can be tuned in the files controllers/auth.js and models/token.js.

Note that you have to recreate the index of the collection if you updated it.

Key rotation is also implemented, signing keys are changed everyday, this can be modified in index.js.

A sample middleware can be found in middlewares/is-auth.js
## **API Reference**
### POST /signup
#### Request Body
```json
{
    "email": "test@test.com",
    "password": "Te$+12#$",
    "firstName": "Test",
    "lastName": "Test",
    "phoneNumber": "0123456789"
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
### GET /publicKey/:kid
#### Respond
```json
{
    "publicKey": "-----BEGIN PUBLIC KEY-----\nMIH4MIGwBgcqhkjOOAQBMIGkAkEAj4aTuWBoIXeqR4KnU+1n23d5yi/7dLR6YKow\n4eAU3V/H3slcaLJmckYZZH/zhFM8IzFdpnWqoA+hzYjMl3DarwIdAIsq1rlf4jgg\nrqv6CXRWIRtZOv5vQOWFJ+rpKlMCQBFL896oT0lPsxhs7P8zMsBrR18M1OE+BhN1\nWuDwUXnQaNeLZCrWS7TDLOt6Q5t8gIklQi5I1Za2bqMOmy74HF0DQwACQG/j5qi0\nzNuV4Xep++BKjOwLv4y9mKvS92BiK2sAnTufLqGI/ZEZqr0MineNpmVXbxBoSgWw\nWnPKL7a42Lamo/Q=\n-----END PUBLIC KEY-----\n"
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

## **Usage**
### Keypair
Put your private key (.key) in the .private folder and public key (.pub) in the .public folder. You can also generate them with following code
```javascript
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
  modulusLength: 256,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  }
});
const kid = crypto.createHash("sha256")
  .update(publicKey)
  .digest("hex");
fs.writeFileSync(path.join(__dirname, '.public', `${kid}.pub`), publicKey);
fs.writeFileSync(path.join(__dirname, '.private', `${kid}.key`), privateKey);
```
### Environment Variables
* PORT
  * http port to serve the backend
  * default: 8080
* DATABASE_URL
  * mongodb connection url
* NUM_KEYS
  * number of signing keys to generate
  * default: 5
### Docker
Dockerfile.dev spawns up a dev server with nodemon for development.

Dockerfile is for deployment.

Add your mongoDB connection url in docker-compose.yaml.
