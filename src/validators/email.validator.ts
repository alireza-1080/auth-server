import { z } from 'zod';

const emailSchema = z.string().email('Invalid email address').trim().toLowerCase();

export { emailSchema };
