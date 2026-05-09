#!/bin/bash
echo "Logging in via proxy..."
curl -i -X POST http://127.0.0.1:5173/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"login_test@example.com","password":"Password123!@#"}' \
  -c cookies.txt

echo -e "\n\nTesting /auth/me via proxy..."
curl -i -X GET http://127.0.0.1:5173/auth/me \
  -b cookies.txt
