import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient({
    log: ['error', 'warn'],
});

const dbConnect = async () => {
    try {
        await prisma.$connect();
        console.log('Connected to database ✔️');
    } catch (error) {
        console.error('Failed to connect to database:', error);
        process.exit(1);
    }
};

export { dbConnect };

export default prisma;
