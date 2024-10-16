// Imports the JSON Web Token library for token verification
import jwt from 'jsonwebtoken';

const checkAuth = (req, res, next) => {
  try {
    // Extracts the JWT token from the request cookies
    const token = req.cookies.token;

    // If no token is present, throws an authentication error
    if (!token) {
      throw new Error('Authentication failed');
    }

    // Verifies the token using the secret key
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    req.userData = {
      username: decodedToken.username,
      accountNumber: decodedToken.accountNumber
    };

    next();
  } catch (error) {
    // If any error occurs during verification, sends an authentication failure response
    res.status(401).json({ message: 'Authentication failed' });
  }
};

export default checkAuth;