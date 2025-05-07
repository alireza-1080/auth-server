import globals from 'globals';
import tseslint from 'typescript-eslint';
import { defineConfig } from 'eslint/config';

export default defineConfig([
    {
        files: ['src/**/*.{ts,tsx}'],
        ignores: ['src/generated/**'], // Ignore generated folder
        languageOptions: {
            globals: globals.node,
            parser: tseslint.parser,
            parserOptions: {
                project: './tsconfig.json',
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            ...tseslint.configs.recommended.rules,
        },
    },
]);
