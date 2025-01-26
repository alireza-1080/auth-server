import joi from 'joi';

const roleValidator = joi.object({
  role: joi.string().valid('ADMIN', 'USER').required(),
});

export default roleValidator;