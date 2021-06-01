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
  from: 'WMTech <noreply.swmengappdev@gmail.com>',
  to: 'noreply.swmengappdev@gmail.com',
  subject: 'WMTech',
};

exports.sendVerificationEmail = async(firstName, email, token) => {
  try {
    const mailOptions = {...defaultMailOptions };
    mailOptions.to = email;
    mailOptions.subject = 'Thank You for registering';
    mailOptions.html = `<h1>Email Confirmation</h1>
        <h2>Hello ${firstName}</h2>
        <p>Thank you for registering. Please confirm your email by clicking on the following link</p>
        <a href=http://auth.wmtech.cc/verifyEmail/${token}> Click here</a>
        </div>`;
  } catch (error) {

  }
}

transporter.sendMail(mailOptions);