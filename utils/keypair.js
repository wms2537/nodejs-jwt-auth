const fs = require('fs');
const path = require('path');
const { generateKeyPair } = require('jose/util/generate_key_pair');
const { calculateThumbprint } = require('jose/jwk/thumbprint');
const { exportJWK } = require('jose/key/export');

exports.resetKeypair = async () => {
  const numKeys = process.env.NUM_KEYS || 5;
  if (fs.existsSync(path.join(__dirname, '..', '.public')))
    fs.rmSync(path.join(__dirname, '..', '.public'), { recursive: true });
  if (fs.existsSync(path.join(__dirname, '..', '.private')))
    fs.rmSync(path.join(__dirname, '..', '.private'), { recursive: true });
  fs.mkdirSync(path.join(__dirname, '..', '.public'));
  fs.mkdirSync(path.join(__dirname, '..', '.private'));
  const publicJwks = [];
  const privateJwks = [];
  for (let i = 0; i < numKeys; i++) {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA')
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);
    privateJwk.kid = await calculateThumbprint(privateJwk);
    publicJwk.kid = await calculateThumbprint(publicJwk);
    publicJwks.push(publicJwk);
    privateJwks.push(privateJwk);
  }
  fs.writeFileSync(path.join(__dirname, '..', '.private', 'keys.json'), JSON.stringify(privateJwks));
  fs.writeFileSync(path.join(__dirname, '..', '.public', 'keys.json'), JSON.stringify(publicJwks));
};