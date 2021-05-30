const axios = require('axios');

const BACKEND_URL = process.env.HCAPTCHA_VALIDATION_SERVER_URL;

exports.validateToken = async(token) => {
  if (!token) {
    return false;
  }
  const result = await axios.get(`${BACKEND_URL}/api/siteverify/${token}`);
  if (result.status !== 200) {
    return false;
  }
  return true;
}