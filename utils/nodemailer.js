const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    type: 'OAuth2',
    user: process.env.MAIL_USERNAME,
    pass: process.env.MAIL_PASSWORD,
    clientId: process.env.OAUTH_CLIENTID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    refreshToken: process.env.OAUTH_REFRESH_TOKEN
  }
});

const defaultMailOptions = {
  from: `WMTech <noreply.${process.env.MAIL_USERNAME}>`,
  replyTo: `noreply.${process.env.MAIL_USERNAME}`,
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
        <a href=http://auth.wmtech.cc/auth/verifyEmail/${token}> Click here</a>
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
        <a href=http://auth.wmtech.cc/auth/resetPassword?token=${token}> Click here</a>
        <p>This email is auto generated, please do not reply to this email.</p>
        `;
    await transporter.sendMail(mailOptions);
  } catch (error) {

  }
}