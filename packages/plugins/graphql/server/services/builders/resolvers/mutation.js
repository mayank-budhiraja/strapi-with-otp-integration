'use strict';

const { pick } = require('lodash/fp');

const pickCreateArgs = pick(['params', 'data', 'files']);

module.exports = ({ strapi }) => ({
  buildMutationsResolvers({ contentType }) {
    const { uid } = contentType;

    return {
      async create(parent, args) {
        // todo[v4]: Might be interesting to generate dynamic yup schema to validate payloads with more complex checks (on top of graphql validation)
        const params = pickCreateArgs(args);

        // todo[v4]: Sanitize args to only keep params / data / files (or do it in the base resolver)
        return strapi.entityService.create(uid, params);
      },

      async update(parent, args) {
        const { id, data } = args;

        return strapi.entityService.update(uid, id, { data });
      },

      async delete(parent, args) {
        const { id, ...rest } = args;

        return strapi.entityService.delete(uid, id, rest);
      },
    };
  },
});
