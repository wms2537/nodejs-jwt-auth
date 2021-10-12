const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: "smtp.wmtech.cc",
  port: 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const defaultMailOptions = {
  from: `WMTech <noreply.wmtech.cc>`,
  replyTo: `info@wmtech.cc`,
  subject: 'WMTech',
};

exports.sendVerificationEmail = async(firstName, email, token) => {
  try {
    const mailOptions = {...defaultMailOptions };
    mailOptions.to = email;
    mailOptions.subject = 'Thank You for registering';
    mailOptions.html = `<h1>Email Confirmation</h1>
        <h2>Hello ${firstName}</h2>
        <p>Thank you for registering. Please confirm your email by clicking on the following link within 15 minutes.</p>
        <a href=${process.env.VIRTUAL_HOST}/auth/verifyEmail/${token}> Click here</a>
        <p>This email is auto generated, please do not reply to this email.</p>
        `;
    await transporter.sendMail(mailOptions);
  } catch (error) {

  }
}

exports.sendPasswordResetEmail = async(firstName, email, token) => {
  try {
    const mailOptions = {...defaultMailOptions };
    mailOptions.to = email;
    mailOptions.subject = 'Password Reset';
    mailOptions.html = `<h1>Password Reset</h1>
        <h2>Hello ${firstName}</h2>
        <p>Reset your password by clicking on the following link within 15 minutes.</p>
        <a href=${process.env.VIRTUAL_HOST}/auth/resetPassword?token=${token}> Click here</a>
        <p>This email is auto generated, please do not reply to this email.</p>
        `;
    await transporter.sendMail(mailOptions);
  } catch (error) {

  }
}