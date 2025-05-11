import { z } from 'zod';

const signupSchema = z
    .object({
        name: z
            .string()
            .min(2, 'Name must be at least 2 characters')
            .max(50, 'Name must be 50 characters or less')
            .regex(/^[a-zA-Z\s\-\'\.]*$/, 'Name can only contain letters, spaces, hyphens, apostrophes, or periods')
            .trim()
            .refine((val) => !/\s{2,}/.test(val), 'Name cannot contain multiple consecutive spaces')
            .transform((val) =>
                val
                    .split(' ')
                    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
                    .join(' '),
            ),
        username: z
            .string()
            .min(3, 'Username must be at least 3 characters')
            .max(20, 'Username must be 20 characters or less')
            .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
            .transform((val) => val.toLowerCase()),
        email: z.string().email('Invalid email address').trim().toLowerCase(),
        password: z
            .string()
            .min(8, 'Password must be at least 8 characters')
            .regex(/[a-z]/, '1 lowercase letter required in password')
            .regex(/[A-Z]/, '1 uppercase letter required in password')
            .regex(/[0-9]/, '1 digit required in password')
            .regex(/[!@#$%^&*(),.?":{}|<>]/, '1 special character required in password'),
        confirmPassword: z.string().min(1, 'Confirm password is required'),
    })
    .refine((data) => data.password === data.confirmPassword, {
        path: ['confirmPassword'],
        message: 'Passwords do not match',
    });

export { signupSchema };