const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cron = require('node-cron');

const { resetKeypair } = require('./utils/keypair');

resetKeypair();
// reset keypair after some time
// ┌───────────── second (0 - 59)
// | ┌───────────── minute(0 - 59)
// | │ ┌───────────── hour(0 - 23)
// | │ │ ┌───────────── day of the month(1 - 31)
// | │ │ │ ┌───────────── month(1 - 12)
// | │ │ │ │ ┌───────────── day of the week(0 - 6)(Sunday to Saturday;
// | │ │ │ │ │                                   7 is also Sunday on some systems)
// | │ │ │ │ │
// | │ │ │ │ │
// * * * * * *
const cronJob = cron.schedule("0 0 0 * * *", function() {
  resetKeypair();
  console.info('key-pair update job completed');
});
cronJob.start();
// const multer = require('multer');

const authRoutes = require('./routes/auth');
const app = express();

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

app.use(express.json()); // application/json
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
    server.listen(80);
  })
  .catch(err => console.log(err));