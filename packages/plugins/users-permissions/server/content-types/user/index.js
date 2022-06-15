'use strict';

const schemaConfig = require('./schema-config');

module.exports = {
  collectionName: 'up_users',
  info: {
    name: 'user',
    description: '',
    singularName: 'user',
    pluralName: 'users',
    displayName: 'User',
  },
  options: {
    draftAndPublish: false,
    timestamps: true,
  },
  attributes: {
    username: {
      type: 'string',
      unique: false,
      configurable: true,
      required: false,
    },
    email: {
      type: 'email',
      minLength: 6,
      configurable: false,
      required: false,
    },
    provider: {
      type: 'string',
      configurable: false,
    },
    resetPasswordToken: {
      type: 'string',
      configurable: false,
      private: true,
    },
    blocked: {
      type: 'boolean',
      default: false,
      configurable: false,
    },
    role: {
      type: 'relation',
      relation: 'manyToOne',
      target: 'plugin::users-permissions.role',
      inversedBy: 'users',
      configurable: false,
    },
    phoneNumber: {
      type: 'string',
      unique: false,
      configurable: true,
      required: true,
    }
  },

  config: schemaConfig, // TODO: to move to content-manager options
};
