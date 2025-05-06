import express from 'express';
import { signup, verifyEmail, verificationToken } from '../controllers/auth.controller.js';

const router = express.Router();

router.post('/signup', signup);

router.post('/verification-token', verificationToken);

router.post('/verify-email', verifyEmail);

export default router;
