import { MongoClient } from "mongodb";
import dotenv from "dotenv";

// Loads environment variables from .env file
dotenv.config();

// Retrieves the database connection string from environment variables
// This enhances security by keeping sensitive information out of the codebase
const connectionString = process.env.ATLAS_URI || "";

// Creates a new MongoClient instance
const client = new MongoClient(connectionString);

let conn;

try {
  // Attempts to connect to the database
  conn = await client.connect();
  console.log('mongoDB is CONNECTED!!! :)');
} catch (e) {
  // Logs any connection errors
  console.error(e);
}

const db = client.db("payments");

export default db;