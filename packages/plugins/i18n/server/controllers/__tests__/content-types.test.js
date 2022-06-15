'use strict';

const { ApplicationError } = require('@strapi/utils').errors;
const { getNonLocalizedAttributes } = require('../content-types');
const ctService = require('../../services/content-types')();

describe('i18n - Controller - content-types', () => {
  describe('getNonLocalizedAttributes', () => {
    beforeEach(() => {
      const contentType = () => ({});
      const getModel = () => ({});
      global.strapi = {
        contentType,
        getModel,
        plugins: { i18n: { services: { 'content-types': ctService } } },
        admin: { services: { constants: { READ_ACTION: 'read', CREATE_ACTION: 'create' } } },
      };
    });

    test('model not localized', async () => {
      const badRequest = jest.fn();
      const ctx = {
        state: { user: {} },
        request: {
          body: {
            model: 'api::country.country',
            id: 1,
            locale: 'fr',
          },
        },
        badRequest,
      };

      expect.assertions(2);

      try {
        await getNonLocalizedAttributes(ctx);
      } catch (e) {
        expect(e instanceof ApplicationError).toBe(true);
        expect(e.message).toEqual('model.not.localized');
      }
    });

    test('entity not found', async () => {
      const notFound = jest.fn();
      const findOne = jest.fn(() => Promise.resolve(undefined));
      const contentType = jest.fn(() => ({ pluginOptions: { i18n: { localized: true } } }));

      global.strapi.query = () => ({ findOne });
      global.strapi.contentType = contentType;
      const ctx = {
        state: { user: {} },
        request: {
          body: {
            model: 'api::country.country',
            id: 1,
            locale: 'fr',
          },
        },
        notFound,
      };
      await getNonLocalizedAttributes(ctx);

      expect(notFound).toHaveBeenCalledWith();
    });

    test('returns nonLocalizedFields', async () => {
      const model = {
        pluginOptions: { i18n: { localized: true } },
        attributes: {
          name: { type: 'string' },
          averagePrice: { type: 'integer' },
          description: { type: 'string', pluginOptions: { i18n: { localized: true } } },
        },
      };
      const entity = {
        id: 1,
        name: "Papailhau's Pizza",
        description: 'Best pizza restaurant of the town',
        locale: 'en',
        publishedAt: '2021-03-30T09:34:54.042Z',
        localizations: [{ id: 2, locale: 'it', publishedAt: null }],
      };
      const permissions = [
        { properties: { fields: ['name', 'averagePrice'], locales: ['it'] } },
        { properties: { fields: ['name', 'description'], locales: ['fr'] } },
        { properties: { fields: ['name'], locales: ['fr'] } },
      ];

      const findOne = jest.fn(() => Promise.resolve(entity));
      const findMany = jest.fn(() => Promise.resolve(permissions));
      const contentType = jest.fn(() => model);

      global.strapi.query = () => ({ findOne });
      global.strapi.contentType = contentType;
      global.strapi.admin.services.permission = { findMany };
      const ctx = {
        state: { user: { roles: [{ id: 1 }, { id: 2 }] } },
        request: {
          body: {
            model: 'api::country.country',
            id: 1,
            locale: 'fr',
          },
        },
      };
      await getNonLocalizedAttributes(ctx);
      expect(findMany).toHaveBeenCalledWith({
        where: {
          action: ['read', 'create'],
          subject: 'api::country.country',
          role: {
            id: [1, 2],
          },
        },
      });
      expect(ctx.body).toEqual({
        nonLocalizedFields: { name: "Papailhau's Pizza" },
        localizations: [
          { id: 2, locale: 'it', publishedAt: null },
          { id: 1, locale: 'en', publishedAt: '2021-03-30T09:34:54.042Z' },
        ],
      });
    });
  });
});
