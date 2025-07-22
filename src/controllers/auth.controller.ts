import { Request, Response } from 'express';
import { signupSchema } from '../validators/signup.validator.js';
import { ZodError } from 'zod';
import bcrypt from 'bcryptjs';
import prisma from '../services/prisma.service.js';
import {
    SignupRequestBody,
    VerifyEmailRequestBody,
    VerificationTokenRequestBody,
    LoginRequestBody,
    ResetTokenRequestBody,
    IsResetTokenValidRequestBody,
    ResetPasswordRequestBody,
    IsUserLoggedInRequestBody,
    DeleteAccountRequestBody,
} from '../types/auth.validator.js';
import { emailSchema } from '../validators/email.validator.js';
import { generateVerificationToken } from '../utils/generateVerificationToken.js';
import transporter from '../utils/nodeMailerTransporter.js';
import mailVerificationTokenOptions from '../utils/mailVerificationTokenOptions.js';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { generateResetToken } from '../utils/generateResetToken.js';
import mailResetTokenOptions from '../utils/mailResetTokenOptions.js';
import { passwordSchema } from '../validators/password.validator.js';
import { idSchema } from '../validators/id.validator.js';
import asyncHandler from '../utils/asyncHandler.js';

dotenv.config();

if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined');
}

const signup = asyncHandler(async (req: Request<object, object, SignupRequestBody>, res: Response) => {
    const { name, username, email, password } = signupSchema.parse(req.body);

    const existingUser = await prisma.user.findFirst({
        where: { OR: [{ email }, { username }] },
    });

    if (existingUser) {
        throw new Error('User with this email or username already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
        data: { name, username, email, password: hashedPassword },
        select: {
            id: true,
            name: true,
            username: true,
            email: true,
            createdAt: true,
            updatedAt: true,
        },
    });

    const verificationToken = generateVerificationToken();

    await prisma.user.update({
        where: { email },
        data: {
            verificationToken,
            verificationTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 10),
        },
    });

    await transporter.sendMail(mailVerificationTokenOptions(email, verificationToken));

    res.status(201).json({
        status: 'success',
        message: 'User created successfully. Please check your email to verify your account.',
    });
});

const sendVerificationToken = asyncHandler(
    async (req: Request<object, object, VerificationTokenRequestBody>, res: Response) => {
        const { email } = req.body;
        emailSchema.parse(email);

        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
            throw new Error('User not found');
        }

        if (user.isEmailVerified) {
            throw new Error('Email is already verified');
        }

        const verificationToken = generateVerificationToken();

        await prisma.user.update({
            where: { email },
            data: {
                verificationToken,
                verificationTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 10),
            },
        });

        await transporter.sendMail(mailVerificationTokenOptions(email, verificationToken));

        res.status(200).json({
            status: 'success',
            message: 'Verification token sent successfully',
        });
    },
);

const verifyEmail = asyncHandler(async (req: Request<object, object, VerifyEmailRequestBody>, res: Response) => {
    const { email, verificationToken } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        throw new Error('User not found');
    }

    if (user.isEmailVerified) {
        throw new Error('Email is already verified');
    }

    if (user.verificationToken !== verificationToken || !user.verificationTokenExpiresAt) {
        throw new Error('Invalid verification token');
    }

    if (user.verificationTokenExpiresAt < new Date()) {
        throw new Error('Verification token has expired');
    }

    await prisma.user.update({
        where: { email },
        data: {
            isEmailVerified: true,
            verificationToken: null,
            verificationTokenExpiresAt: null,
        },
    });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET!, { expiresIn: '7d' });

    res.status(200).json({
        status: 'success',
        message: 'Email verified successfully',
        token,
    });
});

const signin = asyncHandler(async (req: Request<object, object, LoginRequestBody>, res: Response) => {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        throw new Error('Invalid email or password');
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
        throw new Error('Invalid email or password');
    }

    if (!user.isEmailVerified) {
        const verificationToken = generateVerificationToken();
        await prisma.user.update({
            where: { email },
            data: {
                verificationToken,
                verificationTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 10),
            },
        });
        await transporter.sendMail(mailVerificationTokenOptions(email, verificationToken));
        res.status(403).json({
            status: 'error',
            message: 'Email not verified. A new verification token has been sent to your email.',
        });
        return;
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET!, { expiresIn: '7d' });

    await prisma.user.update({
        where: { email },
        data: { lastLogin: new Date() },
    });

    res.status(200).json({
        status: 'success',
        message: 'Login successful',
        token,
    });
});

const resetToken = asyncHandler(async (req: Request<object, object, ResetTokenRequestBody>, res: Response) => {
    const { email } = req.body;
    emailSchema.parse(email);

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        throw new Error('User not found');
    }

    const resetToken = generateResetToken();

    await prisma.user.update({
        where: { email },
        data: {
            resetPasswordToken: resetToken,
            resetPasswordTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 10),
        },
    });

    await transporter.sendMail(mailResetTokenOptions(email, resetToken));

    res.status(200).json({
        status: 'success',
        message: 'Password reset token sent successfully',
    });
});

const isResetTokenValid = asyncHandler(
    async (req: Request<object, object, IsResetTokenValidRequestBody>, res: Response) => {
        const { email, resetToken } = req.body;

        const user = await prisma.user.findUnique({ where: { email } });

        if (
            !user ||
            user.resetPasswordToken !== resetToken ||
            !user.resetPasswordTokenExpiresAt ||
            user.resetPasswordTokenExpiresAt < new Date()
        ) {
            throw new Error('Invalid or expired reset token');
        }

        res.status(200).json({
            status: 'success',
            message: 'Reset token is valid',
        });
    },
);

const resetPassword = asyncHandler(async (req: Request<object, object, ResetPasswordRequestBody>, res: Response) => {
    const { email, resetToken, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        throw new Error('Passwords do not match');
    }

    passwordSchema.parse({ password });

    const user = await prisma.user.findUnique({ where: { email } });

    if (
        !user ||
        user.resetPasswordToken !== resetToken ||
        !user.resetPasswordTokenExpiresAt ||
        user.resetPasswordTokenExpiresAt < new Date()
    ) {
        throw new Error('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.user.update({
        where: { email },
        data: {
            password: hashedPassword,
            resetPasswordToken: null,
            resetPasswordTokenExpiresAt: null,
        },
    });

    res.status(200).json({
        status: 'success',
        message: 'Password has been reset successfully',
    });
});

const isUserLoggedIn = asyncHandler(async (req: Request<object, object, IsUserLoggedInRequestBody>, res: Response) => {
    const { token } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { id: string };
    const { id } = decoded;
    idSchema.parse(id);

    const user = await prisma.user.findUnique({
        where: { id },
        select: { id: true, name: true, username: true, email: true, isEmailVerified: true },
    });

    if (!user) {
        throw new Error('User not found');
    }

    res.status(200).json({
        status: 'success',
        message: 'User is logged in',
        user,
    });
});

const deleteAccount = asyncHandler(async (req: Request<object, object, DeleteAccountRequestBody>, res: Response) => {
    const { userId } = req.body;
    idSchema.parse(userId);

    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
        throw new Error('User not found');
    }

    await prisma.user.delete({ where: { id: userId } });

    res.status(200).json({
        status: 'success',
        message: 'Account deleted successfully',
    });
});

export {
    signup,
    verifyEmail,
    sendVerificationToken,
    signin,
    resetToken,
    isResetTokenValid,
    resetPassword,
    isUserLoggedIn,
    deleteAccount,
};
