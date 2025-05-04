import app from "./app.js";
import { config } from "dotenv";
import { dbConnect } from "./services/prisma.service.js";

config();

const PORT = process.env.PORT;

app.listen(PORT, async () => {
  await dbConnect();
  console.log(`Server is running on port ${PORT}`);
});
