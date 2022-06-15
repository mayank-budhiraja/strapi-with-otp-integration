'use strict';

const { yup, validateYupSchema } = require('@strapi/utils');

const callbackBodySchema = yup.object().shape({
  identifier: yup.string().required(),
  password: yup.string().required(),
});

const registerBodySchema = yup.object().shape({
  email: yup
    .string()
    .email(),
  password: yup.string(),
});

const sendEmailConfirmationBodySchema = yup.object().shape({
  email: yup
    .string(),
});

const validateLoginPhoneBody = yup.object().shape({
  phoneNumber: yup
    .string()
    .required(),
})

module.exports = {
  validateCallbackBody: validateYupSchema(callbackBodySchema),
  validateRegisterBody: validateYupSchema(registerBodySchema),
  validateSendEmailConfirmationBody: validateYupSchema(sendEmailConfirmationBodySchema),
  validateLoginPhoneBody: validateYupSchema(validateLoginPhoneBody)
};
