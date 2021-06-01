const axios = require('axios');

const BACKEND_URL = "https://hcaptcha.wmtech.cc";

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