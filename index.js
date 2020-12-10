const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
// const multer = require('multer');

const authRoutes = require('./routes/auth');
const { fstat } = require('fs');
const app = express();

// TODO: implement key rotation logic
// const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
//   modulusLength: 256,
//   publicKeyEncoding: {
//     type: 'spki',
//     format: 'pem'
//   },
//   privateKeyEncoding: {
//     type: 'pkcs8',
//     format: 'pem',
//   }
// });
// const kid = crypto.createHash("sha256")
//   .update(publicKey)
//   .digest("hex");
// fs.writeFileSync(path.join(__dirname, '.public', `${kid}.pub`), publicKey);
// fs.writeFileSync(path.join(__dirname, '.private', `${kid}.key`), privateKey);

// const fileStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'images');
//   },
//   filename: (req, file, cb) => {
//     cb(null, new Date().toISOString() + '-' + file.originalname);
//   }
// });

// const fileFilter = (req, file, cb) => {
//   if (
//     file.mimetype === 'image/jpg' ||
//     file.mimetype === 'image/jpeg'
//   ) {
//     cb(null, true);
//   } else {
//     cb(null, false);
//   }
// };

// app.use(bodyParser.urlencoded()); // x-www-form-urlencoded <form>
app.use(bodyParser.json()); // application/json
// app.use(
//   multer({
//     fileFilter: fileFilter
//   })
//   .fields([{
//     name: 'image',
//   }]),
// );

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'OPTIONS, GET, POST, PUT, PATCH, DELETE'
  );
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

app.use('/auth', authRoutes);

app.use((error, req, res, next) => {
  console.log(error);
  const status = error.statusCode || 500;
  const message = error.message;
  const data = error.data;
  res.status(status).json({ message: message, data: data });
});

const server = http.createServer(app);

mongoose
  .connect(
    process.env.DATABASE_URL
  )
  .then(result => {
    console.log('Connected to Database!')
    server.listen(process.env.PORT || 8080);
  })
  .catch(err => console.log(err));
