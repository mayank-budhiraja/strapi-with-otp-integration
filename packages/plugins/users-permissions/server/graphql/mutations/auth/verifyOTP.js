'use strict';

const { toPlainObject } = require('lodash/fp');

const { checkBadRequest } = require('../../utils');

module.exports = ({ nexus, strapi }) => {
    const { nonNull } = nexus;

    return {
        type: 'UsersPermissionsLoginPayload',

        args: {
            code: nonNull('String'),
        },

        description: 'Reset user password. Confirm with a code (resetToken from forgotPassword)',

        async resolve(parent, args, context) {
            const { koaContext } = context;

            koaContext.request.body = toPlainObject(args);

            await strapi
                .plugin('users-permissions')
                .controller('auth')
                .verifyOTP(koaContext);

            const output = koaContext.body;

            checkBadRequest(output);

            return {
                user: output.user || output,
                jwt: output.jwt,
            };
        },
    };
};
