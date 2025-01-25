import express from 'express';
import { signUp, logIn, getMe, logOut } from '../controllers/auth.js';

const authRouter = express.Router();

authRouter.post('/signup', signUp);

authRouter.post('/login', logIn);

authRouter.get('/me', getMe);

authRouter.post('/logout', logOut);

export default authRouter;