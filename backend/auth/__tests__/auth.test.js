const { hashPassword, verifyPassword, generateResetToken, verifyResetToken } = require('../services/password.service');
const { signAccessToken, verifyAccessToken } = require('../services/jwt.service');

describe('Password Service', () => {
  test('bcrypt: hash and verify password', async () => {
    const { hash, algo } = await hashPassword('MyP@ssword1!', 'bcrypt');
    expect(algo).toBe('bcrypt');
    expect(hash).not.toBe('MyP@ssword1!');
    const valid = await verifyPassword('MyP@ssword1!', hash, 'bcrypt');
    expect(valid).toBe(true);
  });

  test('bcrypt: wrong password returns false', async () => {
    const { hash } = await hashPassword('Correct1!', 'bcrypt');
    const valid = await verifyPassword('Wrong1!', hash, 'bcrypt');
    expect(valid).toBe(false);
  });

  test('argon2id: hash and verify password', async () => {
    const { hash, algo } = await hashPassword('MyP@ssword1!', 'argon2id');
    expect(algo).toBe('argon2id');
    const valid = await verifyPassword('MyP@ssword1!', hash, 'argon2id');
    expect(valid).toBe(true);
  });

  test('generateResetToken returns HMAC and expiry', () => {
    const { rawToken, hmacToken, expires } = generateResetToken();
    expect(rawToken).toBeDefined();
    expect(hmacToken).toBeDefined();
    expect(expires > new Date()).toBe(true);
  });

  test('verifyResetToken: correct token passes', () => {
    const { rawToken, hmacToken } = generateResetToken();
    expect(verifyResetToken(rawToken, hmacToken)).toBe(true);
  });

  test('verifyResetToken: tampered token fails', () => {
    const { hmacToken } = generateResetToken();
    expect(verifyResetToken('tampered', hmacToken)).toBe(false);
  });
});

describe('JWT Service', () => {
  const payload = { sub: 'user123', email: 'test@example.com', role: 'User', jti: 'abc' };

  test('signs and verifies access token', () => {
    const token = signAccessToken(payload);
    expect(token).toBeDefined();
    const decoded = verifyAccessToken(token);
    expect(decoded.sub).toBe('user123');
    expect(decoded.role).toBe('User');
  });

  test('rejects tampered token', () => {
    const token = signAccessToken(payload);
    const tampered = token.slice(0, -5) + 'XXXXX';
    expect(() => verifyAccessToken(tampered)).toThrow();
  });
});
