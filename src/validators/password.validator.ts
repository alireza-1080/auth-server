import { z } from 'zod';

const passwordSchema = z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[a-z]/, 'Password 1 lowercase letter required')
    .regex(/[A-Z]/, '1 uppercase letter required')
    .regex(/[0-9]/, '1 digit required')
    .regex(/[!@#$%^&*(),.?":{}|<>]/, '1 special character required');

export { passwordSchema };
