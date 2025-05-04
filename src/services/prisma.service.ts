import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

const dbConnect = async () => {
  try {
    await prisma.$connect()
    console.log('Connected to database ✔️')
  } catch (error) {
    console.error(error)
  }
}

export { dbConnect }

export default prisma
