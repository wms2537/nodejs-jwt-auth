const axios = require('axios');

exports.validateToken = async(token) => {
  if (!token) {
    return false;
  }
  const result = await axios.get(`${process.env.HCAPTCHA_HOST}/api/siteverify/${token}`);
  if (result.status !== 200) {
    return false;
  }
  return true;
}