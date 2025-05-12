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

interface ResetTokenRequestBody {
    email: string;
}

interface IsResetTokenValidRequestBody {
    email: string;
    resetToken: string;
}

interface ResetPasswordRequestBody {
    email: string;
    resetToken: string;
    password: string;
    confirmPassword: string;
}

interface IsUserLoggedInRequestBody {
    token: string;
}

export type {
    SignupRequestBody,
    VerifyEmailRequestBody,
    VerificationTokenRequestBody,
    LoginRequestBody,
    ResetTokenRequestBody,
    IsResetTokenValidRequestBody,
    ResetPasswordRequestBody,
    IsUserLoggedInRequestBody,
};
