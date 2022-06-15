'use strict';

const forgotPasswordTemplate = require('./email-templates/forgot-password');

module.exports = {
  forgotPassword: {
    emailTemplate: forgotPasswordTemplate,
  },
};
