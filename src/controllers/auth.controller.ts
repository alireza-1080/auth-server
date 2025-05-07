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

dotenv.config();

const signup = async (req: Request<object, object, SignupRequestBody>, res: Response) => {
    try {
        // Get the body of the request
        const { name, username, email, password, confirmPassword } = req.body;

        // Check if the required fields are present
        if (!name) throw new Error('Name is required');
        if (!username) throw new Error('Username is required');
        if (!email) throw new Error('Email is required');
        if (!password) throw new Error('Password is required');
        if (!confirmPassword) throw new Error('Confirm password is required');

        // Validate the user data
        const validatedUser = signupSchema.parse(req.body);

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Check if the user already exists
        const existingUser = await prisma.user.findUnique({
            where: {
                email,
            },
        });

        if (existingUser) throw new Error('Email already in use, please use a different email or login');

        const existingUsername = await prisma.user.findUnique({
            where: {
                username,
            },
        });

        if (existingUsername) throw new Error('Username already in use, please use a different username or login');

        // Create the user
        const user = await prisma.user.create({
            data: {
                name: validatedUser.name,
                username: validatedUser.username,
                email: validatedUser.email,
                password: hashedPassword,
            },
            select: {
                id: true,
                name: true,
                username: true,
                email: true,
                createdAt: true,
                updatedAt: true,
            },
        });

        res.status(201).json({
            status: 'success',
            message: 'User created successfully',
            user,
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: error.errors.map((err) => ({
                    field: err.path.join('.'),
                    message: err.message,
                })),
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const verificationToken = async (req: Request<object, object, VerificationTokenRequestBody>, res: Response) => {
    try {
        // Get the body of the request
        const { email } = req.body;

        // Check if the email is present
        if (!email) throw new Error('Email is required');

        // Validate the email
        const validatedEmail = emailSchema.parse(email);

        // Check if the user exists
        const user = await prisma.user.findUnique({
            where: { email: validatedEmail },
        });

        if (!user) throw new Error('User not found');

        // Check if the user is already verified
        if (user.isEmailVerified) throw new Error('User already verified');

        // Generate the verification token
        const verificationToken = generateVerificationToken();

        // Update the user with the verification token
        await prisma.user.update({
            where: { email: validatedEmail },
            data: {
                verificationToken,
                verificationTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 10),
            },
        });

        // Send the verification token to the user's email
        await transporter.sendMail(mailVerificationTokenOptions(validatedEmail, verificationToken));

        res.status(200).json({
            status: 'success',
            message: 'Verification token generated successfully',
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Invalid email format',
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const verifyEmail = async (req: Request<object, object, VerifyEmailRequestBody>, res: Response) => {
    try {
        const { email, verificationToken } = req.body;

        if (!email) throw new Error('Email is required');
        if (!verificationToken) throw new Error('Verification token is required');

        const validatedEmail = emailSchema.parse(email);

        const user = await prisma.user.findUnique({
            where: { email: validatedEmail },
        });

        if (!user) throw new Error('User not found');

        // Check if the user is already verified
        if (user.isEmailVerified) throw new Error('User already verified');

        // Check if the verification token is valid
        if (user.verificationToken !== verificationToken) throw new Error('Invalid verification token');

        // Check if the verification token has expired
        if (!user.verificationTokenExpiresAt) throw new Error('Verification token expired');

        if (user.verificationTokenExpiresAt < new Date()) throw new Error('Verification token expired');

        await prisma.user.update({
            where: { email: validatedEmail },
            data: {
                isEmailVerified: true,
                verificationToken: null,
                verificationTokenExpiresAt: null,
            },
        });

        res.status(200).json({
            status: 'success',
            message: 'Email verified successfully',
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Invalid email format',
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const login = async (req: Request<object, object, LoginRequestBody>, res: Response) => {
    try {
        // Get the body of the request
        const { email, password } = req.body;

        // Check if the required fields are present
        if (!email) throw new Error('Email is required');
        if (!password) throw new Error('Password is required');

        // Validate the email
        const validatedEmail = emailSchema.parse(email);

        // Check if the user exists
        const user = await prisma.user.findUnique({
            where: { email: validatedEmail },
            select: {
                id: true,
                name: true,
                username: true,
                email: true,
                password: true,
            },
        });

        if (!user) throw new Error('User not found');

        // Check if the password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) throw new Error('Invalid password');

        if (!process.env.JWT_SECRET) throw new Error('JWT secret is not configured');
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        // Update the user last login date
        const updatedUser = await prisma.user.update({
            where: { email: validatedEmail },
            data: { lastLogin: new Date() },
            select: {
                id: true,
                name: true,
                username: true,
                email: true,
                isEmailVerified: true,
            },
        });

        res.status(200).json({
            status: 'success',
            message: 'Login successful',
            token,
            user: updatedUser,
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Invalid email format',
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const resetToken = async (req: Request<object, object, ResetTokenRequestBody>, res: Response) => {
    try {
        const { email } = req.body;

        if (!email) throw new Error('Email is required');

        const validatedEmail = emailSchema.parse(email);

        const user = await prisma.user.findUnique({
            where: { email: validatedEmail },
        });

        if (!user) throw new Error('User not found');

        const resetToken = generateResetToken();

        await prisma.user.update({
            where: { email: validatedEmail },
            data: {
                resetPasswordToken: resetToken,
                resetPasswordTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 10),
            },
        });

        await transporter.sendMail(mailResetTokenOptions(validatedEmail, resetToken));

        res.status(200).json({
            status: 'success',
            message: 'Reset token generated successfully',
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Invalid email format',
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const isResetTokenValid = async (req: Request<object, object, IsResetTokenValidRequestBody>, res: Response) => {
    try {
        const { email, resetToken } = req.body;

        if (!email) throw new Error('Email is required');
        if (!resetToken) throw new Error('Reset token is required');

        const validatedEmail = emailSchema.parse(email);

        const user = await prisma.user.findUnique({
            where: { email: validatedEmail },
        });

        if (!user) throw new Error('User not found');

        if (user.resetPasswordToken !== resetToken) throw new Error('Invalid reset token');

        if (!user.resetPasswordTokenExpiresAt) throw new Error('Reset token expired');
        if (user.resetPasswordTokenExpiresAt < new Date()) throw new Error('Reset token expired');

        res.status(200).json({
            status: 'success',
            message: 'Reset token is valid',
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Invalid email format',
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const resetPassword = async (req: Request<object, object, ResetPasswordRequestBody>, res: Response) => {
    try {
        const { email, resetToken, password, confirmPassword } = req.body;

        if (!email) throw new Error('Email is required');
        if (!resetToken) throw new Error('Reset token is required');
        if (!password) throw new Error('Password is required');
        if (!confirmPassword) throw new Error('Confirm password is required');

        const validatedEmail = emailSchema.parse(email);

        passwordSchema.parse(password);

        if (password !== confirmPassword) throw new Error('Passwords do not match');

        const user = await prisma.user.findUnique({
            where: { email: validatedEmail },
        });

        if (!user) throw new Error('User not found');

        if (user.resetPasswordToken !== resetToken) throw new Error('Invalid reset token');

        if (!user.resetPasswordTokenExpiresAt) throw new Error('Reset token expired');
        if (user.resetPasswordTokenExpiresAt < new Date()) throw new Error('Reset token expired');

        const hashedPassword = await bcrypt.hash(password, 10);

        await prisma.user.update({
            where: { email: validatedEmail },
            data: { password: hashedPassword, resetPasswordToken: null, resetPasswordTokenExpiresAt: null },
        });

        res.status(200).json({
            status: 'success',
            message: 'Password reset successfully',
        });

        return;
    } catch (error) {
        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Validation failed',
                errors: error.errors.map((err) => ({
                    field: err.path.join('.'),
                    message: err.message,
                })),
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

const isUserLoggedIn = async (req: Request<object, object, IsUserLoggedInRequestBody>, res: Response) => {
    try {
        const { token } = req.body;

        if (!token) throw new Error('Token is required');

        if (!process.env.JWT_SECRET) throw new Error('JWT secret is not configured');
        const decoded = jwt.verify(token, process.env.JWT_SECRET) as { id: string };
        const { id } = decoded;

        const validatedId = idSchema.parse(id);

        const user = await prisma.user.findUnique({
            where: { id: validatedId },
            select: {
                id: true,
                name: true,
                username: true,
                email: true,
                isEmailVerified: true,
            },
        });

        if (!user) throw new Error('User not found');

        res.status(200).json({
            status: 'success',
            message: 'User is logged in',
            user,
        });

        return;
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            res.status(401).json({
                status: 'error',
                message: 'Invalid token',
            });
            return;
        }

        if (error instanceof jwt.TokenExpiredError) {
            res.status(401).json({
                status: 'error',
                message: 'Token expired',
            });
            return;
        }

        if (error instanceof ZodError) {
            res.status(400).json({
                status: 'error',
                message: 'Invalid user ID',
            });
            return;
        }

        if (error instanceof Error) {
            res.status(400).json({
                status: 'error',
                message: error.message,
            });
            return;
        }

        res.status(500).json({
            status: 'error',
            message: 'An unexpected error occurred',
        });
    }
};

export { signup, verifyEmail, verificationToken, login, resetToken, isResetTokenValid, resetPassword, isUserLoggedIn };
