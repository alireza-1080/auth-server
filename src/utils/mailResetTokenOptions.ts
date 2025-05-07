const mailResetTokenOptions = (email: string, resetToken: string) => {
    return {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Reset Password Token',
        html: `
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; border-radius: 5px;">
            <h1>Reset your password</h1>
            <p>Your reset password token is: ${resetToken}</p>
            <p>This token will expire in 10 minutes</p>
            <p>If you did not request this token, please ignore this email</p>
        </div>
        `,
    };
};

export default mailResetTokenOptions;
