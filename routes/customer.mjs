import express from "express";
import db from "../db/conn.mjs";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { encryptData, decryptData } from "../encryption.mjs";

const router = express.Router();

// Input Validation
// Using regular expressions to ensure that all user input meets specific criteria and formats
// This is crucial for maintaining data integrity and preventing malicious inputs

// Validates Full Name
// Ensures the name contains only letters and spaces, and is between 2 and 50 characters long
const validateFullName = (fullName) => {
  const regex = /^[a-zA-Z\s]{2,50}$/;
  return regex.test(fullName);
};

// Validates ID Number
// Ensures the ID number is exactly 13 digits long
const validateIdNumber = (idNumber) => {
  const regex = /^[0-9]{13}$/;
  return regex.test(idNumber);
};

// Validates Account Number
// Ensures the account number is exactly 10 digits long
const validateAccountNumber = (accountNumber) => {
  const regex = /^[0-9]{10}$/;
  return regex.test(accountNumber);
};

// Validates Password
// Ensures the password is at least 8 characters long and contains at least one uppercase letter,
// one lowercase letter, one number, and one special character
const validatePassword = (password) => {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return regex.test(password);
};

// Input Sanitization
// This removes potentially malicious content from all user input
// A crucial security measure to prevent various types of injection attacks
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  return input.replace(/<[^>]*>?/gm, '')  // Removes HTML tags
    .replace(/[&<>"']/g, (match) => {  // Replaces special characters
      const entities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      };
      return entities[match];
    })
    .replace(/[\$\{\}]/g, '')  // Removes potentially dangerous characters
    .trim()  // Removes whitespace
    .substring(0, 1000);  // Limits all user input lengths
};

// Customer Registration
router.post("/register", async (req, res, next) => {
  try {
    const { fullName, idNumber, accountNumber, password } = req.body;

    // Checks for empty inputs
    if (!fullName || !idNumber || !accountNumber || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Validates inputs
    // This ensures that all user inputs meet the required format and criteria
    if (!validateFullName(fullName)) {
      return res.status(400).json({ message: "Invalid full name. Please enter a valid full name" });
    }
    if (!validateIdNumber(idNumber)) {
      return res.status(400).json({ message: "Invalid ID number. Please enter valid 13 digit ID number" });
    }
    if (!validateAccountNumber(accountNumber)) {
      return res.status(400).json({ message: "Invalid account number. Please enter valid 10 digit account number" });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({ message: "Invalid password. Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character" });
    }

    // Sanitizes inputs
    // This removes any potentially malicious content from user inputs
    const sanitizedFullName = sanitizeInput(fullName);
    const sanitizedIdNumber = sanitizeInput(idNumber);
    const sanitizedAccountNumber = sanitizeInput(accountNumber);

    const collection = db.collection("customers");

    // Checks if account number already exists
    // This prevents duplicate accounts and enhances data integrity
    const encryptedAccountNumber = encryptData(sanitizedAccountNumber);
    const existingAccount = await collection.findOne({ 'accountNumber.encryptedData': encryptedAccountNumber.encryptedData });
    if (existingAccount) {
      return res.status(400).json({ message: "Registration failed. An account with this account number already exists" });
    }

    // Checks if ID number already exists
    // This prevents multiple accounts for the same individual
    const encryptedIdNumber = encryptData(sanitizedIdNumber);
    const existingId = await collection.findOne({ 'idNumber.encryptedData': encryptedIdNumber.encryptedData });
    if (existingId) {
      return res.status(400).json({ message: "Registration failed. An account with this ID number already exists" });
    }

    // Hashes the password for secure storage
    // This ensures that even if the database is compromised, passwords remain protected
    const hashedPassword = await bcrypt.hash(password, 12);

    const newCustomer = {
      fullName: sanitizedFullName,
      idNumber: encryptedIdNumber,
      accountNumber: encryptedAccountNumber,
      password: hashedPassword
    };

    // Inserts new customer into database
    const result = await collection.insertOne(newCustomer);
    console.log(`Customer registered: ${result.insertedId}`);
    res.status(201).json({ message: "Customer registered successfully" });
  } catch (error) {
    console.error(`Registration error: ${error.message}`);
    next(error);
  }
});

// Customer Login
router.post("/login", async (req, res, next) => {
  try {
    const { username, accountNumber, password } = req.body;

    // Checks for empty inputs
    if (!username || !accountNumber || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Sanitizes inputs
    const sanitizedUsername = sanitizeInput(username);
    const sanitizedAccountNumber = sanitizeInput(accountNumber);

    const collection = db.collection("customers");

    // Finds customer by account number
    const encryptedAccountNumber = encryptData(sanitizedAccountNumber);
    const customer = await collection.findOne({ 'accountNumber.encryptedData': encryptedAccountNumber.encryptedData });

    if (!customer) {
      console.log(`Login failed: Customer not found for account number ${sanitizedAccountNumber}`);
      return res.status(401).json({ message: "Authentication failed: Incorrect credentials. Please try again" });
    }

    // Compares provided password with stored hashed password
    // This verifies the user's identity without exposing the actual password
    const passwordMatch = await bcrypt.compare(password, customer.password);
    if (!passwordMatch) {
      console.log(`Login failed: Incorrect password for account number ${sanitizedAccountNumber}`);
      return res.status(401).json({ message: "Authentication failed: Incorrect credentials. Please try again" });
    }

    // Generates JWT token for authenticated session
    // This creates a secure, time-limited token for the user's session
    const token = jwt.sign(
      {
        username: sanitizedUsername,
        accountNumber: decryptData(customer.accountNumber)
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Sets token in HTTP-only cookie
    // This enhances security by making the token inaccessible to client-side scripts
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    console.log(`Login successful for account number ${sanitizedAccountNumber}`);
    res.status(200).json({ message: "Authentication successful", token });
  } catch (error) {
    console.error(`Login error: ${error.message}`);
    next(error);
  }
});

export default router;