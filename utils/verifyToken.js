import jwt from 'jsonwebtoken';
import 'dotenv/config';

const verifyToken = async (token) => {
  try {
    const secret = process.env.JWT_SECRET;

    if (!secret) {
      throw new Error('JWT_SECRET is not defined');
    }
    const decoded = jwt.verify(token, secret);
    return decoded;
  } catch (error) {
    throw new Error('Access denied');
  }
};

export default verifyToken;
