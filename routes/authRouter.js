import express from 'express';
import { signUp, logIn, getMe, logOut, verify } from '../controllers/auth.js';

const authRouter = express.Router();

authRouter.post('/signup', signUp);

authRouter.post('/login', logIn);

authRouter.post('/me', getMe);

authRouter.post('/logout', logOut);

authRouter.get("/verify", verify);

export default authRouter;