const axios = require('axios');

(async () => {
  try {
    const client = axios.create({
      baseURL: 'http://127.0.0.1:5000',
      withCredentials: true,
    });
    
    console.log("Logging in...");
    const res = await client.post('/auth/login', {
      email: 'login_test@example.com',
      password: 'Password123!@#'
    });
    
    const cookies = res.headers['set-cookie'];
    console.log("Cookies received:", cookies);
    
    const cookieHeader = cookies.map(c => c.split(';')[0]).join('; ');
    console.log("Sending cookie header:", cookieHeader);
    
    const meRes = await client.get('/auth/me', {
      headers: { Cookie: cookieHeader }
    });
    
    console.log("Auth ME Success:", meRes.data);
  } catch (err) {
    console.error("Error:", err.response ? err.response.data : err.message);
  }
})();
