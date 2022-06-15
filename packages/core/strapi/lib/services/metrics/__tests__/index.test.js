'use strict';

jest.mock('node-fetch', () => jest.fn(() => Promise.resolve()));

const { get } = require('lodash/fp');
const fetch = require('node-fetch');
const metrics = require('../index');

describe('metrics', () => {
  test('Initializes a middleware', () => {
    const use = jest.fn();

    metrics({
      config: {
        get(path) {
          return get(path, this);
        },
        uuid: 'test',
        environment: 'dev',
        info: {
          strapi: '0.0.0',
        },
      },
      server: {
        use,
      },
    }).register();

    expect(use).toHaveBeenCalled();
  });

  test('Does not init middleware if disabled', () => {
    const use = jest.fn();

    metrics({
      config: {
        get(path) {
          return get(path, this);
        },
        uuid: false,
        environment: 'dev',
        info: {
          strapi: '0.0.0',
        },
      },
      server: {
        use,
      },
    }).register();

    expect(use).not.toHaveBeenCalled();
  });

  test('Send payload with meta', () => {
    const { send } = metrics({
      config: {
        get(path) {
          return get(path, this);
        },
        uuid: 'test',
        environment: 'dev',
        info: {
          strapi: '0.0.0',
        },
      },
      server: {
        use() {},
      },
    });

    send('someEvent');

    expect(fetch).toHaveBeenCalled();
    expect(fetch.mock.calls[0][0]).toBe('https://analytics.strapi.io/track');
    expect(fetch.mock.calls[0][1].method).toBe('POST');
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toMatchObject({
      event: 'someEvent',
      uuid: 'test',
      properties: {
        projectType: 'Community',
      },
    });

    fetch.mockClear();
  });

  test('Does not send payload when disabled', () => {
    const { send } = metrics({
      config: {
        get(path) {
          return get(path, this);
        },
        uuid: false,
        packageJsonStrapi: {},
        environment: 'dev',
        info: {
          strapi: '0.0.0',
        },
      },
      server: {
        use() {},
      },
    });

    send('someEvent');

    expect(fetch).not.toHaveBeenCalled();
  });
});
