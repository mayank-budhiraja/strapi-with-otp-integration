'use strict';

module.exports = [
  {
    method: 'POST',
    path: '/login',
    handler: 'authentication.login',
    config: { auth: false },
  },
  {
    method: 'POST',
    path: '/renew-token',
    handler: 'authentication.renewToken',
    config: { auth: false },
  },
  {
    method: 'POST',
    path: '/register-admin',
    handler: 'authentication.registerAdmin',
    config: { auth: false },
  },
  {
    method: 'GET',
    path: '/registration-info',
    handler: 'authentication.registrationInfo',
    config: { auth: false },
  },
  {
    method: 'POST',
    path: '/register',
    handler: 'authentication.register',
    config: { auth: false },
  },
  {
    method: 'POST',
    path: '/forgot-password',
    handler: 'authentication.forgotPassword',
    config: { auth: false },
  },
  {
    method: 'POST',
    path: '/reset-password',
    handler: 'authentication.resetPassword',
    config: { auth: false },
  },
];
