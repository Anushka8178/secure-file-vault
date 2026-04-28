const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const env = require('../../config/env');
const logger = require('../../shared/logger');

// JWKS key store (in-memory; in production backed by Vault/KMS)
const keyStore = {
  current: { kid: uuidv4(), secret: env.JWT_SECRET },
  previous: null,
};

/**
 * Sign a JWT access token (HS256 or RS256)
 */
const signAccessToken = (payload) => {
  const { kid, secret } = keyStore.current;
  const options = {
    algorithm: env.JWT_ALGORITHM,
    expiresIn: env.JWT_ACCESS_TTL,
    issuer: 'secure-vault',
    audience: 'secure-vault-client',
    jwtid: uuidv4(),
    header: { kid },
  };

  let signingKey = secret;
  if (env.JWT_ALGORITHM === 'RS256' && env.JWT_PRIVATE_KEY) {
    signingKey = Buffer.from(env.JWT_PRIVATE_KEY, 'base64').toString('utf8');
  }

  return jwt.sign(payload, signingKey, options);
};

/**
 * Verify a JWT, trying current key then rotating to previous if kid mismatches
 */
const verifyAccessToken = (token) => {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) throw new Error('Invalid token structure');

  const { kid } = decoded.header || {};

  const keysToTry = [];
  if (kid === keyStore.current.kid) keysToTry.push(keyStore.current);
  else if (keyStore.previous && kid === keyStore.previous.kid) keysToTry.push(keyStore.previous);
  else keysToTry.push(keyStore.current);

  let lastErr;
  for (const key of keysToTry) {
    try {
      let verifyKey = key.secret;
      if (env.JWT_ALGORITHM === 'RS256' && env.JWT_PUBLIC_KEY) {
        verifyKey = Buffer.from(env.JWT_PUBLIC_KEY, 'base64').toString('utf8');
      }
      return jwt.verify(token, verifyKey, {
        algorithms: [env.JWT_ALGORITHM],
        issuer: 'secure-vault',
        audience: 'secure-vault-client',
      });
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
};

/**
 * JWKS endpoint — public keys for RS256
 */
const getJwks = () => {
  if (env.JWT_ALGORITHM !== 'RS256') {
    return { keys: [] };
  }
  // In production return actual JWK from node-jose
  return {
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        kid: keyStore.current.kid,
        // n, e would be populated from real key
      },
    ],
  };
};

/**
 * Rotate signing key (call on schedule or at startup)
 */
const rotateKey = () => {
  keyStore.previous = { ...keyStore.current };
  keyStore.current = { kid: uuidv4(), secret: require('crypto').randomBytes(64).toString('hex') };
  logger.info('JWT signing key rotated', { newKid: keyStore.current.kid });
};

module.exports = { signAccessToken, verifyAccessToken, getJwks, rotateKey };
