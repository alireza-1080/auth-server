import express from 'express';
import {
    signup,
    sendVerificationToken,
    verifyEmail,
    signin,
    resetToken,
    isResetTokenValid,
    resetPassword,
    isUserLoggedIn,
    deleteAccount,
} from '../controllers/auth.controller.js';

const router = express.Router();

router.post('/signup', signup);

router.post('/send-verification-token', sendVerificationToken);

router.post('/verify-email', verifyEmail);

router.post('/signin', signin);

router.post('/reset-token', resetToken);

router.post('/is-reset-token-valid', isResetTokenValid);

router.post('/reset-password', resetPassword);

router.post('/is-user-logged-in', isUserLoggedIn);

router.delete('/delete-account', deleteAccount);

export default router;
