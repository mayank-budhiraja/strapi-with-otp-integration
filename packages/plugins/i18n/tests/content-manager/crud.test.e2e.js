'use strict';

const { createStrapiInstance } = require('../../../../../test/helpers/strapi');
const { createAuthRequest } = require('../../../../../test/helpers/request');
const { createTestBuilder } = require('../../../../../test/helpers/builder');

let strapi;
let rq;

const categoryModel = {
  kind: 'collectionType',
  collectionName: 'categories',
  displayName: 'Category',
  singularName: 'category',
  pluralName: 'categories',
  description: '',
  name: 'Category',
  options: {
    draftAndPublish: false,
  },
  pluginOptions: {
    i18n: {
      localized: true,
    },
  },
  attributes: {
    name: {
      type: 'string',
      pluginOptions: {
        i18n: {
          localized: true,
        },
      },
    },
  },
};

const data = {
  categories: [],
};

describe('i18n - Content API', () => {
  const builder = createTestBuilder();

  beforeAll(async () => {
    await builder
      .addContentTypes([categoryModel])
      .addFixtures('plugin::i18n.locale', [{ name: 'Ko', code: 'ko' }])
      .build();

    strapi = await createStrapiInstance();
    rq = await createAuthRequest({ strapi });
  });

  afterAll(async () => {
    await strapi.destroy();
    await builder.cleanup();
  });

  describe('Create', () => {
    test('default locale', async () => {
      const res = await rq({
        method: 'POST',
        url: '/content-manager/collection-types/api::category.category',
        body: {
          name: 'category in english',
        },
      });

      const { statusCode, body } = res;

      expect(statusCode).toBe(200);
      expect(body).toMatchObject({
        locale: 'en',
        localizations: [],
        name: 'category in english',
      });
      data.categories.push(res.body);
    });

    test('non-default locale', async () => {
      const res = await rq({
        method: 'POST',
        url: '/content-manager/collection-types/api::category.category?plugins[i18n][locale]=ko',
        body: {
          name: 'category in korean',
        },
      });

      const { statusCode, body } = res;

      expect(statusCode).toBe(200);
      expect(body).toMatchObject({
        locale: 'ko',
        localizations: [],
        name: 'category in korean',
      });
      data.categories.push(res.body);
    });
  });

  describe('Bulk Delete', () => {
    test('default locale', async () => {
      const res = await rq({
        method: 'POST',
        url: '/content-manager/collection-types/api::category.category/actions/bulkDelete',
        body: {
          ids: [data.categories[0].id],
        },
      });

      const { statusCode, body } = res;

      expect(statusCode).toBe(200);
      expect(body).toMatchObject({ count: 1 });
      data.categories.shift();
    });

    test('non-default locale', async () => {
      const res = await rq({
        method: 'POST',
        url: '/content-manager/collection-types/api::category.category/actions/bulkDelete',
        body: {
          ids: [data.categories[0].id],
        },
      });

      const { statusCode, body } = res;

      expect(statusCode).toBe(200);
      expect(body).toMatchObject({ count: 1 });
      data.categories.shift();
    });
  });
});
