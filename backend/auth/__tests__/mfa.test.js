const { generateMfaSecret, verifyTotp } = require('../services/mfa.service');

describe('MFA Service', () => {
  test('generates a valid TOTP secret and QR code', async () => {
    const { secret, qrDataUrl, otpAuthUrl } = await generateMfaSecret('test@example.com');
    expect(secret).toBeDefined();
    expect(secret.length).toBeGreaterThan(10);
    expect(qrDataUrl).toMatch(/^data:image\/png/);
    expect(otpAuthUrl).toMatch(/^otpauth:\/\/totp\//);
  });

  test('verifyTotp returns false for wrong code', async () => {
    const { secret } = await generateMfaSecret('test@example.com');
    const result = verifyTotp('000000', secret);
    expect(result).toBe(false);
  });
});
