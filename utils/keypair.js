const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

exports.resetKeypair = () => {
  const numKeys = process.env.NUM_KEYS || 5;
  for (let i = 0; i < numKeys; i++) {
    fs.rmdirSync(path.join(__dirname, '..', '.public'), { recursive: true });
    fs.rmdirSync(path.join(__dirname, '..', '.private'), { recursive: true });
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
    fs.writeFileSync(path.join(__dirname, '..', '.public', `${kid}.pub`), publicKey);
    fs.writeFileSync(path.join(__dirname, '..', '.private', `${kid}.key`), privateKey);
  }
};