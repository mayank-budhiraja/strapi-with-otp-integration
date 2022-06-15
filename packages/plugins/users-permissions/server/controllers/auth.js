'use strict';

/**
 * Auth.js controller
 *
 * @description: A set of functions called "actions" for managing `Auth`.
 */

/* eslint-disable no-useless-escape */
const crypto = require('crypto');
const _ = require('lodash');
const utils = require('@strapi/utils');
const axios = require('axios');
const otpGenerator = require('otp-generator')
const { getService } = require('../utils');
const {
  validateCallbackBody,
  validateLoginPhoneBody,
  validateRegisterBody,
  validateSendEmailConfirmationBody,
} = require('./validation/auth');

const { getAbsoluteAdminUrl, getAbsoluteServerUrl, sanitize } = utils;
const { ApplicationError, ValidationError } = utils.errors;

const emailRegExp = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
const phoneRegExp = /^((\\+[1-9]{1,4}[ \\-]*)|(\\([0-9]{2,3}\\)[ \\-]*)|([0-9]{2,4})[ \\-]*)*?[0-9]{3,4}?[ \\-]*[0-9]{3,4}?$/

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel('plugin::users-permissions.user');
  return sanitize.contentAPI.output(user, userSchema, { auth });
};

module.exports = {
  async callback(ctx) {
    const provider = ctx.params.provider || 'local';
    const params = ctx.request.body;

    const store = strapi.store({ type: 'plugin', name: 'users-permissions' });

    if (provider === 'local') {
      if (!_.get(await store.get({ key: 'grant' }), 'email.enabled')) {
        throw new ApplicationError('This provider is disabled');
      }

      await validateLoginPhoneBody(params);

      const query = { provider };

      // Check if the provided identifier is an email or not.
      const isEmail = emailRegExp.test(params.identifier);

      const isPhone = phoneRegExp.test(params.phoneNumber);

      // Set the identifier to the appropriate query field.
      if (isEmail) {
        query.email = params.identifier.toLowerCase();
      } else {
        query.username = params.identifier;
      }

      const addPhoneNumber = params.phoneNumber;

      if (isPhone) {

        // Generate random number
        const randomOTP = otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false });

        // send otp
        await axios.get('https://www.fast2sms.com/dev/bulkV2', {
          params: {
            "authorization": "M8ReHdNrjuFoDCGnL2fZ5O4thVslpIJTz6BSK3xa7wWXmbcvEgUNbHXs2qCOleW7Dpnf13kxi6SaVPQj",
            "variables_values": randomOTP.toString(),
            "route": "otp",
            "numbers": addPhoneNumber
          }
        }).then((response) => {
          ctx.send({
            data: response.data
          });
        }).catch((error) => {
          console.log('OTP error', error);
          throw new ValidationError('sending OTP Error');
        })

        // Check if user exists
        const user = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ select: ['phoneNumber'], where: { phoneNumber: addPhoneNumber } });

        console.log('user found --', user, randomOTP)

        if (user) {
          await strapi
            .query('plugin::users-permissions.user')
            .update({ select: ['phoneNumber', 'resetPasswordToken'], where: { phoneNumber: addPhoneNumber }, data: { resetPasswordToken: randomOTP } });
        } else {
          // save in database
          // we should create a user here
          await strapi
            .query('plugin::users-permissions.user')
            .create({ select: ['phoneNumber', 'resetPasswordToken'], data: { phoneNumber: addPhoneNumber, resetPasswordToken: randomOTP }, });
        }
      }

      const user = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ select: ['phoneNumber', 'resetPasswordToken'], where: { phoneNumber: addPhoneNumber } });

      console.log('user updated --', user)

      /*
      if (
        _.get(await store.get({ key: 'advanced' }), 'email_confirmation') &&
        user.confirmed !== true
      ) {
        throw new ApplicationError('Your account email is not confirmed');
      }
      */

      /*
      if (user.blocked === true) {
        // throw new ApplicationError('Your account has been blocked by an administrator');
      } */

      // The user never authenticated with the `local` provider.
      /* if (!user.password) {
       // not required
        throw new ApplicationError(
         'This user never set a local password, please login with the provider used during account creation'
       ); 
     }*/

      try {
        ctx.send({
          message: "OTP Sent"
        });
      } catch (err) {
        console.log('error while sending message')
      }
    } else {
      if (!_.get(await store.get({ key: 'grant' }), [provider, 'enabled'])) {
        throw new ApplicationError('This provider is disabled');
      }

      // Connect the user with the third-party provider.
      try {
        const user = await getService('providers').connect(provider, ctx.query);
        ctx.send({
          jwt: getService('jwt').issue({ id: user.id }),
          user: await sanitizeUser(user, ctx),
        });
      } catch (error) {
        throw new ApplicationError(error.message);
      }
    }
  },

  async verifyOTP(ctx) {
    const params = _.assign({}, ctx.request.body, ctx.params);

    if (params.phoneNumber && params.code) {
      // Compare client pass with db pass
      try {
        const user = await strapi
          .query('plugin::users-permissions.user')
          .findOne({ select: ['phoneNumber', 'resetPasswordToken', 'confirmed', 'id'], where: { phoneNumber: params.phoneNumber, resetPasswordToken: params.code } });

        if (!user.confirmed) {
          const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

          const settings = await pluginStore.get({
            key: 'advanced',
          });

          if (!settings.allow_register) {
            throw new ApplicationError('Register action is currently disabled');
          }

          const params = {
            ..._.omit(ctx.request.body, ['confirmed', 'confirmationToken', 'resetPasswordToken']),
            provider: 'local',
          };

          const role = await strapi
            .query('plugin::users-permissions.role')
            .findOne({ where: { type: settings.default_role } });

          if (!role) {
            throw new ApplicationError('Impossible to find the default role');
          }

          params.role = role.id;

          try {

            const newUser = await getService('user').edit(user.id, { ...params, confirmed: true, resetPasswordToken: null });

            console.log('find user -- confirmed', newUser)

            const sanitizedUser = await sanitizeUser(newUser, ctx);

            const jwt = getService('jwt').issue(_.pick(newUser, ['id']));

            return ctx.send({
              jwt,
              user: sanitizedUser,
            });
          } catch (err) {
            strapi.log.error(err);
            throw new ApplicationError('An error occurred during account creation');
          }
        } else if (user && user.confirmed) {
          console.log('findThis -- existing user 2')
          await getService('user').edit(user.id, {
            resetPasswordToken: null,
          });

          ctx.send({
            jwt: getService('jwt').issue({ id: user.id }),
            user: await sanitizeUser(user, ctx),
          });
        } else {
          throw new ValidationError('Incorrect OTP provided');
        }
      } catch (err) {
        // TODO: Create an API to resend OTP
        throw new ValidationError('try logging again');
      }
    } else {
      throw new ValidationError('Incorrect params provided');
    }
  },

  async resetPassword(ctx) {
    const params = _.assign({}, ctx.request.body, ctx.params);

    if (
      params.password &&
      params.passwordConfirmation &&
      params.password === params.passwordConfirmation &&
      params.code
    ) {
      const user = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ where: { resetPasswordToken: `${params.code}` } });

      if (!user) {
        throw new ValidationError('Incorrect code provided');
      }

      await getService('user').edit(user.id, {
        resetPasswordToken: null,
        password: params.password,
      });
      // Update the user.
      ctx.send({
        jwt: getService('jwt').issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } else if (
      params.password &&
      params.passwordConfirmation &&
      params.password !== params.passwordConfirmation
    ) {
      throw new ValidationError('Passwords do not match');
    } else {
      throw new ValidationError('Incorrect params provided');
    }
  },

  async connect(ctx, next) {
    const grant = require('grant-koa');

    const providers = await strapi
      .store({ type: 'plugin', name: 'users-permissions', key: 'grant' })
      .get();

    const apiPrefix = strapi.config.get('api.rest.prefix');
    const grantConfig = {
      defaults: {
        prefix: `${apiPrefix}/connect`,
      },
      ...providers,
    };

    const [requestPath] = ctx.request.url.split('?');
    const provider = requestPath.split('/connect/')[1].split('/')[0];

    if (!_.get(grantConfig[provider], 'enabled')) {
      throw new ApplicationError('This provider is disabled');
    }

    if (!strapi.config.server.url.startsWith('http')) {
      strapi.log.warn(
        'You are using a third party provider for login. Make sure to set an absolute url in config/server.js. More info here: https://docs.strapi.io/developer-docs/latest/plugins/users-permissions.html#setting-up-the-server-url'
      );
    }

    // Ability to pass OAuth callback dynamically
    grantConfig[provider].callback =
      _.get(ctx, 'query.callback') ||
      _.get(ctx, 'session.grant.dynamic.callback') ||
      grantConfig[provider].callback;
    grantConfig[provider].redirect_uri = getService('providers').buildRedirectUri(provider);

    return grant(grantConfig)(ctx, next);
  },

  async forgotPassword(ctx) {
    let { email } = ctx.request.body;

    // Check if the provided email is valid or not.
    const isEmail = emailRegExp.test(email);

    if (isEmail) {
      email = email.toLowerCase();
    } else {
      throw new ValidationError('Please provide a valid email address');
    }

    const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

    // Find the user by email.
    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { email: email.toLowerCase() } });

    // User not found.
    if (!user) {
      throw new ApplicationError('This email does not exist');
    }

    // User blocked
    if (user.blocked) {
      throw new ApplicationError('This user is disabled');
    }

    // Generate random token.
    const resetPasswordToken = crypto.randomBytes(64).toString('hex');

    const settings = await pluginStore.get({ key: 'email' }).then(storeEmail => {
      try {
        return storeEmail['reset_password'].options;
      } catch (error) {
        return {};
      }
    });

    const advanced = await pluginStore.get({
      key: 'advanced',
    });

    const userInfo = await sanitizeUser(user, ctx);

    settings.message = await getService('users-permissions').template(settings.message, {
      URL: advanced.email_reset_password,
      SERVER_URL: getAbsoluteServerUrl(strapi.config),
      ADMIN_URL: getAbsoluteAdminUrl(strapi.config),
      USER: userInfo,
      TOKEN: resetPasswordToken,
    });

    settings.object = await getService('users-permissions').template(settings.object, {
      USER: userInfo,
    });

    try {
      // Send an email to the user.
      await strapi
        .plugin('email')
        .service('email')
        .send({
          to: user.email,
          from:
            settings.from.email || settings.from.name
              ? `${settings.from.name} <${settings.from.email}>`
              : undefined,
          replyTo: settings.response_email,
          subject: settings.object,
          text: settings.message,
          html: settings.message,
        });
    } catch (err) {
      throw new ApplicationError(err.message);
    }

    // Update the user.
    await strapi
      .query('plugin::users-permissions.user')
      .update({ where: { id: user.id }, data: { resetPasswordToken } });

    ctx.send({ ok: true });
  },

  async register(ctx) {
    const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

    const settings = await pluginStore.get({
      key: 'advanced',
    });

    if (!settings.allow_register) {
      throw new ApplicationError('Register action is currently disabled');
    }

    const params = {
      ..._.omit(ctx.request.body, ['confirmed', 'confirmationToken', 'resetPasswordToken']),
      provider: 'local',
    };

    await validateRegisterBody(params);

    // Throw an error if the password selected by the user
    // contains more than three times the symbol '$'.
    if (getService('user').isHashed(params.password)) {
      throw new ValidationError(
        'Your password cannot contain more than three times the symbol `$`'
      );
    }

    const role = await strapi
      .query('plugin::users-permissions.role')
      .findOne({ where: { type: settings.default_role } });

    if (!role) {
      throw new ApplicationError('Impossible to find the default role');
    }

    // Check if the provided email is valid or not.
    const isEmail = emailRegExp.test(params.email);

    if (isEmail) {
      params.email = params.email.toLowerCase();
    } else {
      throw new ValidationError('Please provide a valid email address');
    }

    params.role = role.id;

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { email: params.email },
    });

    if (user && user.provider === params.provider) {
      throw new ApplicationError('Email is already taken');
    }

    if (user && user.provider !== params.provider && settings.unique_email) {
      throw new ApplicationError('Email is already taken');
    }

    try {
      if (!settings.email_confirmation) {
        params.confirmed = true;
      }
      console.log('till here')
      const user = await getService('user').add(params);

      console.log('findworking', user)
      const sanitizedUser = await sanitizeUser(user, ctx);

      if (settings.email_confirmation) {
        try {
          await getService('user').sendConfirmationEmail(sanitizedUser);
        } catch (err) {
          throw new ApplicationError(err.message);
        }

        return ctx.send({ user: sanitizedUser });
      }

      const jwt = getService('jwt').issue(_.pick(user, ['id']));

      return ctx.send({
        jwt,
        user: sanitizedUser,
      });
    } catch (err) {
      strapi.log.error(err);
      throw new ApplicationError('An error occurred during account creation');
    }
  },

  async emailConfirmation(ctx, next, returnUser) {
    const { confirmation: confirmationToken } = ctx.query;

    const userService = getService('user');
    const jwtService = getService('jwt');

    if (_.isEmpty(confirmationToken)) {
      throw new ValidationError('token.invalid');
    }

    const user = await userService.fetch({ confirmationToken }, []);

    if (!user) {
      throw new ValidationError('token.invalid');
    }

    await userService.edit(user.id, { confirmed: true, confirmationToken: null });

    if (returnUser) {
      ctx.send({
        jwt: jwtService.issue({ id: user.id }),
        user: await sanitizeUser(user, ctx),
      });
    } else {
      const settings = await strapi
        .store({ type: 'plugin', name: 'users-permissions', key: 'advanced' })
        .get();

      ctx.redirect(settings.email_confirmation_redirection || '/');
    }
  },

  async sendEmailConfirmation(ctx) {
    const params = _.assign(ctx.request.body);

    await validateSendEmailConfirmationBody(params);

    const isEmail = emailRegExp.test(params.email);

    if (isEmail) {
      params.email = params.email.toLowerCase();
    } else {
      throw new ValidationError('wrong.email');
    }

    const user = await strapi.query('plugin::users-permissions.user').findOne({
      where: { email: params.email },
    });

    if (!user) {
      return ctx.send({
        email: params.email,
        sent: true,
      });
    }

    if (user.confirmed) {
      throw new ApplicationError('already.confirmed');
    }

    if (user.blocked) {
      throw new ApplicationError('blocked.user');
    }

    try {
      await getService('user').sendConfirmationEmail(user);
      ctx.send({
        email: user.email,
        sent: true,
      });
    } catch (err) {
      throw new ApplicationError(err.message);
    }
  },
};
