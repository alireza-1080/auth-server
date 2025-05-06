interface SignupRequestBody {
    name: string;
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
}

interface VerificationTokenRequestBody {
    email: string;
}

interface VerifyEmailRequestBody {
    email: string;
    verificationToken: string;
}

interface LoginRequestBody {
    email: string;
    password: string;
}

export type { SignupRequestBody, VerifyEmailRequestBody, VerificationTokenRequestBody, LoginRequestBody };
