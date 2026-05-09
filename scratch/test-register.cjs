(async () => {
  try {
    const res = await fetch('http://localhost:5000/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Need to bypass CSRF or fetch the CSRF token first!
      },
      body: JSON.stringify({
        email: 'test_500@example.com',
        username: 'test500',
        password: 'Password123!@#'
      })
    });
    const data = await res.text();
    console.log("Status:", res.status);
    console.log("Response:", data);
  } catch (err) {
    console.error("Fetch Error:", err);
  }
})();
