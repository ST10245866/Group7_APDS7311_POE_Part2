import crypto from 'crypto';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Encryption algorithm and configuration
const algorithm = 'aes-256-gcm';
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');

// Encrypts sensitive data
export const encryptData = (text) => {
  // Creates a cipher using the specified algorithm, key, and initialization vector
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  // Encrypts the input text
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Gets the authentication tag for integrity verification
  const tag = cipher.getAuthTag();

  // Returns the encrypted data along with the authentication tag
  return {
    encryptedData: encrypted,
    tag: tag.toString('hex')
  };
};

// Decrypts encrypted data
export const decryptData = (encryptedText) => {
  // Creates a decipher using the specified algorithm, key, and initialization vector
  const decipher = crypto.createDecipheriv(algorithm, key, iv);

  // Sets the authentication tag for integrity verification
  decipher.setAuthTag(Buffer.from(encryptedText.tag, 'hex'));

  // Decrypts the encrypted data
  let decrypted = decipher.update(encryptedText.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // Return the decrypted plaintext
  return decrypted;
};