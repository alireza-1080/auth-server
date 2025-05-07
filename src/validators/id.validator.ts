import { z } from 'zod';

const idSchema = z.string().refine((value) => /^[0-9a-fA-F]{24}$/.test(value), { message: 'Invalid Id' });

export { idSchema };
