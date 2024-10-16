import express from "express";
import db from "../db/conn.mjs";
import checkAuth from "../check-auth.mjs";
import { encryptData } from "../encryption.mjs";

const router = express.Router();

// Input Validation
// Using regular expressions to ensure that all user input meets specific criteria and formats
// This is crucial for maintaining data integrity and preventing malicious inputs

// Validates Amount
// Ensures the payment amount is a positive number with up to two decimal places and not exceeding 1,000,000
// This prevents negative amounts, excessive payments and ensures proper currency format
const validateAmount = (amount) => {
  const parsedAmount = parseFloat(amount);
  return !isNaN(parsedAmount) && parsedAmount > 0 && parsedAmount <= 1000000 && /^\d+(\.\d{1,2})?$/.test(amount);
};

// Validates Currency
// Ensures the currency code is exactly 3 uppercase letters (e.g., USD, EUR, ZAR)
// This prevents invalid currency codes
const validateCurrency = (currency) => {
  const regex = /^[A-Z]{3}$/;
  return regex.test(currency);
};

// Validate SWIFT Code
// Ensures the SWIFT code is in the correct format: 8 or 11 characters, starting with 6 letters
// This prevents invalid SWIFT codes that could lead to failed transactions
const validateSwiftCode = (swiftCode) => {
  const regex = /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/;
  return regex.test(swiftCode);
};

// Validates Provider
// Ensures the provider name is not empty and within a reasonable length
// This prevents blank or excessively long provider names
const validateSwiftProvider = (provider) => {
  return typeof provider === 'string' && provider.trim().length > 0 && provider.trim().length <= 100;
};

// Validates Payee Name
// Ensures the payee's name contains only letters and spaces, between 2 and 100 characters
// This prevents names with invalid characters or unreasonable lengths
const validatePayeeName = (name) => {
  const regex = /^[a-zA-Z\s]{2,100}$/;
  return regex.test(name);
};

// Validates Payee Account Number
// Ensures the account number is alphanumeric and between 8 and 34 characters
// This accommodates various international account number formats while preventing invalid inputs
const validatePayeeAccountNumber = (accountNumber) => {
  const regex = /^[A-Z0-9]{8,34}$/;
  return regex.test(accountNumber);
};

// Validates Payee Bank Name
// Ensures the bank name is not empty and within a reasonable length
// This prevents blank or excessively long bank names
const validatePayeeBankName = (bankName) => {
  return typeof bankName === 'string' && bankName.trim().length > 0 && bankName.trim().length <= 100;
};

// Validates Payee Address
// Ensures the address is not empty and within a reasonable length
// This prevents blank or excessively long addresses
const validatePayeeAddress = (address) => {
  return typeof address === 'string' && address.trim().length > 0 && address.trim().length <= 200;
};

// Validates Payee City
// Ensures the city name is not empty and within a reasonable length
// This prevents blank or excessively long city names
const validatePayeeCity = (city) => {
  return typeof city === 'string' && city.trim().length > 0 && city.trim().length <= 100;
};

// Validates Payee Postal Code
// Ensures the postal code is alphanumeric and between 3 and 10 characters
// This accommodates various international postal code formats while preventing invalid inputs
const validatePayeePostalCode = (postalCode) => {
  const regex = /^[A-Z0-9]{3,10}$/i;
  return regex.test(postalCode);
};

// Validates Payee Country
// Ensures the country code is exactly 2 uppercase letters
// This prevents invalid country codes
const validatePayeeCountry = (country) => {
  const regex = /^[A-Z]{2}$/;
  return regex.test(country);
};

// Validates IBAN (International Bank Account Number)
// Ensures the IBAN is in the correct format: 2 letters followed by 2 digits and up to 30 alphanumeric characters.
// This prevents invalid IBAN formats that could lead to failed transactions
const validateIBAN = (iban) => {
  const regex = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}$/;
  return regex.test(iban);
};

// Input Sanitization
// This removes potentially malicious content from all user input
// A crucial security measure to prevent various types of injection attacks
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  return input
    .replace(/<[^>]*>?/gm, '')  // Removes HTML tags
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

// Creates a new payment 
router.post("/", checkAuth, async (req, res, next) => {
  try {
    const {
      amount, currency, swiftProvider, swiftCode, payeeName, payeeAccountNumber,
      payeeBankName, payeeAddress, payeeCity, payeePostalCode, payeeCountry, iban
    } = req.body;

    // Checks for required inputs
    // This ensures that all necessary information is provided before processing the payment
    if (!amount || !currency || !swiftProvider || !swiftCode || !payeeName || !payeeAccountNumber ||
      !payeeBankName || !payeeAddress || !payeeCity || !payeePostalCode || !payeeCountry) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Input Validation
    // This prevents invalid or malicious data from entering the system
    if (!validateAmount(amount)) {
      return res.status(400).json({ message: "Invalid amount. Please enter a valid amount" });
    }
    if (!validateCurrency(currency)) {
      return res.status(400).json({ message: "Invalid currency. Please enter a valid 3-letter currency code (e.g., ZAR, USD, EUR)" });
    }
    if (!validateSwiftCode(swiftCode)) {
      return res.status(400).json({ message: "Invalid SWIFT code. Please enter a valid 8 or 11 character SWIFT code" });
    }
    if (!validateSwiftProvider(swiftProvider)) {
      return res.status(400).json({ message: "Invalid SWIFT provider. Please enter a valid SWIFT provider" });
    }
    if (!validatePayeeName(payeeName)) {
      return res.status(400).json({ message: "Invalid name. Please enter a valid name" });
    }
    if (!validatePayeeAccountNumber(payeeAccountNumber)) {
      return res.status(400).json({ message: "Invalid account number. Please enter a valid account number" });
    }
    if (!validatePayeeBankName(payeeBankName)) {
      return res.status(400).json({ message: "Invalid bank name. Please enter a valid bank name" });
    }
    if (!validatePayeeAddress(payeeAddress)) {
      return res.status(400).json({ message: "Invalid address. Please enter a valid address" });
    }
    if (!validatePayeeCity(payeeCity)) {
      return res.status(400).json({ message: "Invalid city name. Please enter a valid city name" });
    }
    if (!validatePayeePostalCode(payeePostalCode)) {
      return res.status(400).json({ message: "Invalid postal code. Please enter a valid postal code" });
    }
    if (!validatePayeeCountry(payeeCountry)) {
      return res.status(400).json({ message: "Invalid country. Please enter a valid 2-letter country code" });
    }
    if (iban && !validateIBAN(iban)) {
      return res.status(400).json({ message: "Invalid IBAN. Please enter a valid IBAN" });
    }

    // Input Sanitization
    // Each input is sanitized to remove any potentially harmful content
    // This adds an extra layer of protection against injection attacks
    const sanitizedAmount = sanitizeInput(amount);
    const sanitizedCurrency = sanitizeInput(currency);
    const sanitizedSwiftProvider = sanitizeInput(swiftProvider);
    const sanitizedSwiftCode = sanitizeInput(swiftCode);
    const sanitizedPayeeName = sanitizeInput(payeeName);
    const sanitizedPayeeAccountNumber = sanitizeInput(payeeAccountNumber);
    const sanitizedPayeeBankName = sanitizeInput(payeeBankName);
    const sanitizedPayeeAddress = sanitizeInput(payeeAddress);
    const sanitizedPayeeCity = sanitizeInput(payeeCity);
    const sanitizedPayeePostalCode = sanitizeInput(payeePostalCode);
    const sanitizedPayeeCountry = sanitizeInput(payeeCountry);
    const sanitizedIBAN = iban ? sanitizeInput(iban) : null;

    // Encrypts sensitive data
    // This ensures that sensitive information is not stored in plain text in the database
    // It protects against unauthorised access to sensitive data even if the database is compromised
    const encryptedPayeeAccountNumber = encryptData(sanitizedPayeeAccountNumber);
    const encryptedIBAN = sanitizedIBAN ? encryptData(sanitizedIBAN) : null;

    const newPayment = {
      amount: parseFloat(sanitizedAmount),
      currency: sanitizedCurrency,
      swiftProvider: sanitizedSwiftProvider,
      swiftCode: sanitizedSwiftCode,
      payeeInfo: {
        name: sanitizedPayeeName,
        accountNumber: encryptedPayeeAccountNumber,
        bankName: sanitizedPayeeBankName,
        address: sanitizedPayeeAddress,
        city: sanitizedPayeeCity,
        postalCode: sanitizedPayeePostalCode,
        country: sanitizedPayeeCountry,
        iban: encryptedIBAN
      }
    };

    // Inserts the new payment into the database
    const collection = db.collection("payments");
    const result = await collection.insertOne(newPayment);

    console.log(`Payment created: ${result.insertedId}`);
    res.status(201).json({ message: "Payment created successfully", paymentId: result.insertedId });
  } catch (error) {
    console.error(`Payment creation error: ${error.message}`);
    next(error);
  }
});

export default router;