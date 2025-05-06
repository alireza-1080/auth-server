import { Request, Response } from 'express';
import { signupSchema } from '../validators/signup.validator.js';
import { ZodError } from 'zod';
import bcrypt from 'bcryptjs';
import prisma from '../services/prisma.service.js';
import { SignupRequestBody, VerifyEmailRequestBody, VerificationTokenRequestBody } from '../types/auth.validator.js';
import { emailSchema } from '../validators/email.validator.js';
import { generateVerificationToken } from '../utils/generateVerificationToken.js';

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
                verificationTokenExpiresAt: new Date(Date.now() + 1000 * 60 * 60),
            },
        });

        res.status(200).json({
            status: 'success',
            message: 'Verification token generated successfully',
            verificationToken,
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

export { signup, verifyEmail, verificationToken };
