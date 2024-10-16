import https from "https";
import fs from "fs";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import customers from "./routes/customer.mjs";
import payments from "./routes/payment.mjs";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import ExpressBrute from "express-brute";
import tls from 'tls';
import crypto from 'crypto';

// Sets up the server port
// This allows flexibility, where the environment variable is used if available,
// or defaulting to port 3000 if not specified
const PORT = process.env.PORT || 3000;

const app = express();

// Configures HTTPS options for secure communication
// These settings ensure that all data transmitted between the client and server is encrypted
const options = {
  // Reading the SSL/TLS certificate and private key
  key: fs.readFileSync("keys/privatekey.pem"),
  cert: fs.readFileSync("keys/certificate.pem"),

  // Forces the use of TLS version 1.3 only
  // This provides the latest security features and protects against vulnerabilities in older TLS versions
  minVersion: 'TLSv1.3',

  // Specifies allowed cipher suites
  // These are strong, modern ciphers that provide excellent security
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256'
  ].join(':'),

  honorCipherOrder: true,

  // Disables older, vulnerable SSL/TLS versions
  // This protects against downgrade attacks and ensures only secure protocols are used
  secureOptions: crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_TLSv1_2
};

// Implements certificate pinning
// This technique helps prevent man-in-the-middle attacks by ensuring 
// that the server presents the expected certificate
const pinnedPublicKey = fs.readFileSync('keys/pinnedpublickey.pem');
const pinnedFingerprint = crypto.createHash('sha256').update(pinnedPublicKey).digest('base64');

options.secureContext = tls.createSecureContext(options);
options.checkServerIdentity = (host, cert) => {
  const publicKey = cert.pubkey;
  const fingerprint = crypto.createHash('sha256').update(publicKey).digest('base64');
  if (fingerprint !== pinnedFingerprint) {
    throw new Error('Certificate verification error: The certificate does not match the pinned fingerprint');
  }
};

// Configures CORS (Cross-Origin Resource Sharing) options
// This helps prevent unauthorised access from different domains
const corsOptions = {
  // Only allows requests from specified origins
  origin: process.env.ALLOWED_ORIGINS.split(','),
  // Specifies which HTTP methods are allowed
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  // Specifies which headers are allowed in requests
  allowedHeaders: ['Content-Type', 'Authorization'],
  // Allows credentials to be sent with requests, such as cookies
  credentials: true,
  maxAge: 600
};

// Applies CORS with the specified options
app.use(cors(corsOptions));

app.use(express.json());

// Parses cookies in incoming requests
app.use(cookieParser());

// Applies Helmet for setting HTTP headers
// This helps protect against Cross-Site Scripting (XSS) and clickjacking
app.use(helmet({
  // Configures Content Security Policy (CSP)
  // This helps prevent Cross-Site Scripting (XSS)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],  // Only allows resources from the same origin
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Allows scripts from same origin and inline
      styleSrc: ["'self'", "'unsafe-inline'"],   // Allows styles from same origin and inline
      imgSrc: ["'self'", "data:", "https:"],     // Allows images from same origin, data URIs, and HTTPS
    },
  },
  // Sets Referrer Policy
  referrerPolicy: {
    policy: "strict-origin-when-cross-origin",
  },
  // Sets X-Frame-Options
  // This helps prevent clickjacking attacks by disabling iframes
  xFrameOptions: {
    action: "deny"
  }
}));

// Enables HTTP Strict Transport Security (HSTS)
// This tells browsers to always use HTTPS only for requests
app.use((req, res, next) => {
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  next();
});

// Implements rate limiting
// This helps protect against brute-force attacks and DDoS attempts
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per 15 minutes
});
app.use(limiter);

// Sets up brute force protection
// This strengthens defense against brute-force attacks
const store = new ExpressBrute.MemoryStore();
const bruteforce = new ExpressBrute(store);

// Routes
// Applies brute force protection
app.use("/customer", bruteforce.prevent, customers);
app.use("/payment", payments);

let server = https.createServer(options, app);

// Starts the server
console.log(`Server running on port ${PORT}`);
server.listen(PORT);