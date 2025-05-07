import express from 'express';
import {
    signup,
    verifyEmail,
    verificationToken,
    login,
    resetToken,
    isResetTokenValid,
    resetPassword,
} from '../controllers/auth.controller.js';

const router = express.Router();

router.post('/signup', signup);

router.post('/verification-token', verificationToken);

router.post('/verify-email', verifyEmail);

router.post('/login', login);

router.post('/reset-token', resetToken);

router.post('/is-reset-token-valid', isResetTokenValid);

router.post('/reset-password', resetPassword);

export default router;
