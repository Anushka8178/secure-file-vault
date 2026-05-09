require('../backend/config/env');
const mongoose = require('mongoose');
const { login } = require('../backend/auth/controllers/auth.controller');

(async () => {
  try {
    await mongoose.connect('mongodb://localhost:27017/secure-vault');
    const req = {
      body: { email: 'login_test@example.com', password: 'Password123!@#' },
      ip: '127.0.0.1',
      headers: { 'user-agent': 'test' }
    };
    const res = {
      cookie: (n, v, o) => console.log('SET COOKIE', n),
      status: (s) => ({ json: (d) => console.log('RES', s, d) })
    };
    await login(req, res);
  } catch(e) {
    console.error("ERROR CAUGHT:");
    console.error(e.stack);
  }
  process.exit();
})();
