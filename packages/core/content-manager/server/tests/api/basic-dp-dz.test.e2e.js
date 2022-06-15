'use strict';

// Test a simple default API with no relations

const { createTestBuilder } = require('../../../../../../test/helpers/builder');
const { createStrapiInstance } = require('../../../../../../test/helpers/strapi');
const { createAuthRequest } = require('../../../../../../test/helpers/request');

const builder = createTestBuilder();
let strapi;
let rq;
let data = {
  productsWithDzAndDP: [],
};

const compo = {
  displayName: 'compo',
  attributes: {
    name: {
      type: 'string',
      required: true,
    },
    description: {
      type: 'text',
      minLength: 4,
      maxLength: 30,
    },
  },
};

const productWithCompoAndDP = {
  attributes: {
    name: {
      type: 'string',
    },
    description: {
      type: 'text',
    },
    dz: {
      components: ['default.compo'],
      type: 'dynamiczone',
      required: true,
    },
  },
  draftAndPublish: true,
  displayName: 'product with dz and DP',
  singularName: 'product-with-dz-and-dp',
  pluralName: 'product-with-dz-and-dps',
  description: '',
  collectionName: '',
};

describe('CM API - Basic + dz + draftAndPublish', () => {
  beforeAll(async () => {
    await builder
      .addComponent(compo)
      .addContentType(productWithCompoAndDP)
      .build();

    strapi = await createStrapiInstance();
    rq = await createAuthRequest({ strapi });
  });

  afterAll(async () => {
    await strapi.destroy();
    await builder.cleanup();
  });

  test('Create product with compo', async () => {
    const product = {
      name: 'Product 1',
      description: 'Product description',
      dz: [
        {
          __component: 'default.compo',
          name: 'compo name',
          description: 'short',
        },
      ],
    };
    const res = await rq({
      method: 'POST',
      url: '/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp',
      body: product,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject(product);
    expect(res.body.publishedAt).toBeNull();
    data.productsWithDzAndDP.push(res.body);
  });

  test('Read product with compo', async () => {
    const res = await rq({
      method: 'GET',
      url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${data.productsWithDzAndDP[0].id}`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject(data.productsWithDzAndDP[0]);
    expect(res.body.publishedAt).toBeNull();
  });

  test('Update product with compo', async () => {
    const product = {
      name: 'Product 1 updated',
      description: 'Updated Product description',
      dz: [
        {
          __component: 'default.compo',
          name: 'compo name updated',
          description: 'update',
        },
      ],
    };
    const res = await rq({
      method: 'PUT',
      url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${data.productsWithDzAndDP[0].id}`,
      body: product,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject(product);
    expect(res.body.id).toEqual(data.productsWithDzAndDP[0].id);
    expect(res.body.publishedAt).toBeNull();
    data.productsWithDzAndDP[0] = res.body;
  });

  test('Delete product with compo', async () => {
    const res = await rq({
      method: 'DELETE',
      url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${data.productsWithDzAndDP[0].id}`,
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject(data.productsWithDzAndDP[0]);
    expect(res.body.id).toEqual(data.productsWithDzAndDP[0].id);
    expect(res.body.publishedAt).toBeNull();
    data.productsWithDzAndDP.shift();
  });

  describe('validation', () => {
    describe.each(['create', 'update'])('%p', method => {
      test(`Can ${method} product with compo - compo required - []`, async () => {
        const product = {
          name: 'Product 1',
          description: 'Product description',
          dz: [],
        };
        const res = await rq({
          method: method === 'create' ? 'POST' : 'PUT',
          url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${
            method === 'update' ? data.productsWithDzAndDP[0].id : ''
          }`,
          body: product,
        });

        expect(res.statusCode).toBe(200);
        expect(res.body).toMatchObject(product);
        data.productsWithDzAndDP.push(res.body);
      });

      test(`Can ${method} product with compo - minLength`, async () => {
        const product = {
          name: 'Product 1',
          description: 'Product description',
          dz: [
            {
              __component: 'default.compo',
              name: 'compo name',
              description: 'k',
            },
          ],
        };
        const res = await rq({
          method: method === 'create' ? 'POST' : 'PUT',
          url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${
            method === 'update' ? data.productsWithDzAndDP[0].id : ''
          }`,
          body: product,
        });

        expect(res.statusCode).toBe(200);
        expect(res.body).toMatchObject(product);
        data.productsWithDzAndDP.push(res.body);
      });

      test(`Cannot ${method} product with compo - maxLength`, async () => {
        const product = {
          name: 'Product 1',
          description: 'Product description',
          dz: [
            {
              __component: 'default.compo',
              name: 'compo name',
              description: 'A very long description that exceed the min length.',
            },
          ],
        };
        const res = await rq({
          method: method === 'create' ? 'POST' : 'PUT',
          url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${
            method === 'update' ? data.productsWithDzAndDP[0].id : ''
          }`,
          body: product,
        });

        expect(res.statusCode).toBe(400);
        expect(res.body).toMatchObject({
          data: null,
          error: {
            status: 400,
            name: 'ValidationError',
            message: 'dz[0].description must be at most 30 characters',
            details: {
              errors: [
                {
                  path: ['dz', '0', 'description'],
                  message: 'dz[0].description must be at most 30 characters',
                  name: 'ValidationError',
                },
              ],
            },
          },
        });
      });

      test(`Can ${method} product with compo - required`, async () => {
        const product = {
          name: 'Product 1',
          description: 'Product description',
          dz: [
            {
              __component: 'default.compo',
              description: 'short',
            },
          ],
        };
        const res = await rq({
          method: method === 'create' ? 'POST' : 'PUT',
          url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${
            method === 'update' ? data.productsWithDzAndDP[0].id : ''
          }`,
          body: product,
        });

        expect(res.statusCode).toBe(200);
        expect(res.body).toMatchObject(product);
        data.productsWithDzAndDP.push(res.body);
      });

      test(`Cannot ${method} product with compo - missing __component`, async () => {
        const product = {
          name: 'Product 1',
          description: 'Product description',
          dz: [
            {
              name: 'Product 1',
              description: 'short',
            },
          ],
        };
        const res = await rq({
          method: method === 'create' ? 'POST' : 'PUT',
          url: `/content-manager/collection-types/api::product-with-dz-and-dp.product-with-dz-and-dp/${
            method === 'update' ? data.productsWithDzAndDP[0].id : ''
          }`,
          body: product,
        });

        expect(res.statusCode).toBe(400);
        expect(res.body).toMatchObject({
          data: null,
          error: {
            status: 400,
            name: 'ValidationError',
            message: 'dz[0].__component is a required field',
            details: {
              errors: [
                {
                  path: ['dz', '0', '__component'],
                  message: 'dz[0].__component is a required field',
                  name: 'ValidationError',
                },
              ],
            },
          },
        });
      });
    });
  });
});
