# Group_7_APDS7311_POE_Part_2

A secure backend for the customer international payments portal. It provides API endpoints for customer registration, login and payment creation.

## Features

1. Secure Customer Registration: 
   - Validates and sanitizes input data
   - Encrypts sensitive information before storage
   - Implements strong password policies

2. Secure Customer Login:
   - Secure login process with rate limiting
   - JWT-based session management
   - Protection against brute-force attacks

3. Payment Creation:
   - Secure handling of payment details

4. Security Measures:
   - HTTPS/TLS 1.3 for all communications
   - AES-256 encryption for sensitive data
   - Input validation and sanitization

## Security Measures

1. HTTPS/TLS 1.3:
   - Ensures all data transmitted between the client and server is encrypted
   - Uses only strong, modern cipher suites

2. AES-256 Encryption:
   - Encrypts sensitive data before storage in the database
   - Separate encryption keys for different types of data

3. Password Security:
   - Implements bcrypt for password hashing
   - Enforces strong password policies

4. JWT (JSON Web Tokens):
   - Secure session management
   - Short expiration times

5. Input Validation and Sanitization:
   - Strict input validation using regular expressions
   - Sanitization of all user inputs to prevent injection attacks

6. Protection Against Common Attacks:
   - SQL Injection: Use of parameterized queries and ORM
   - XSS (Cross-Site Scripting): Strict output encoding
   - Clickjacking: Implementation of X-Frame-Options header

7. Rate Limiting:
   - Prevents brute-force attacks on login and other endpoints

8. Certificate Pinning:
   - Mitigates Man-in-the-Middle attacks by validating server certificates

9. Secure Headers:
   - Uses Helmet to set secure HTTP headers
   - Implements Content Security Policy (CSP)

## Prerequisites

- Node.js
- MongoDB
- OpenSSL (for generating SSL/TLS certificates)

## Installation

1. Install the required packages:
npm install express cors helmet bcrypt jsonwebtoken mongodb dotenv express-rate-limit cookie-parser express-brute

3. Set up your environment variables in a `.env` file:
PORT=3000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
ENCRYPTION_KEY=your_32_byte_encryption_key
ENCRYPTION_IV=your_16_byte_initialization_vector
ALLOWED_ORIGINS=https://yourdomain.com

4. Generate SSL/TLS certificates:
openssl req -x509 -newkey rsa:4096 -keyout keys/privatekey.pem -out keys/certificate.pem -days 365
openssl rsa -in keys/privatekey.pem -pubout -out keys/pinnedpublickey.pem

## Configuration

1. Database Setup:
   - Ensure MongoDB is running
   - Update the `MONGODB_URI` in your `.env` file

2. SSL/TLS Configuration:
   - Place your SSL/TLS certificates in the `keys` folder
   - Update the paths in `server.mjs` if necessary

3. CORS Configuration:
   - Update the `ALLOWED_ORIGINS` in your `.env` file with your domain(s)

## Running the Application

1. Start the server:
npm run dev

2. The server will start on the port specified in your `.env` file (default is 3000)

## API Endpoints

- POST `/customer/register`: Register a new customer
- POST `/customer/login`: Authenticate a customer
- POST `/payment`: Process an international payment (requires authentication)