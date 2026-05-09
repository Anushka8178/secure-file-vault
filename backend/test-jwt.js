require('./config/env');
const { signAccessToken, verifyAccessToken } = require('./auth/services/jwt.service');

try {
  const token = signAccessToken({ sub: '123', email: 'test@example.com', role: 'User' });
  console.log("Token signed:", token);
  
  const decoded = verifyAccessToken(token);
  console.log("Token verified successfully:", decoded);
} catch (err) {
  console.error("JWT ERROR:", err);
}
