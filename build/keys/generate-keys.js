const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Save keys to files
const keysDir = path.join(__dirname);
fs.writeFileSync(path.join(keysDir, 'server-private.pem'), privateKey);
fs.writeFileSync(path.join(keysDir, 'server-public.pem'), publicKey);

// Generate JWK format for the public key
const jwk = crypto.createPublicKey(publicKey).export({
  format: 'jwk'
});

// Add key ID for JWT header
jwk.kid = 'rotate-2025-07';
jwk.alg = 'RS256';
jwk.use = 'sig';

fs.writeFileSync(path.join(keysDir, 'server-public.jwk'), JSON.stringify(jwk, null, 2));

console.log('RSA key pair generated successfully!');
console.log('Files created:');
console.log('- server-private.pem (server private key)');
console.log('- server-public.pem (server public key)');
console.log('- server-public.jwk (public key in JWK format)');
