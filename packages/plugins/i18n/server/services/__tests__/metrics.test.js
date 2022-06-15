'use strict';

const metricsLoader = require('../metrics');
const { isLocalizedContentType } = require('../content-types')();

describe('Metrics', () => {
  test('sendDidInitializeEvent', async () => {
    global.strapi = {
      contentTypes: {
        withI18n: {
          pluginOptions: {
            i18n: {
              localized: true,
            },
          },
        },
        withoutI18n: {
          pluginOptions: {
            i18n: {
              localized: false,
            },
          },
        },
        withNoOption: {
          pluginOptions: {},
        },
      },
      plugins: {
        i18n: {
          services: {
            ['content-types']: {
              isLocalizedContentType,
            },
          },
        },
      },
      telemetry: {
        send: jest.fn(),
      },
    };

    const { sendDidInitializeEvent } = metricsLoader({ strapi });

    await sendDidInitializeEvent();

    expect(strapi.telemetry.send).toHaveBeenCalledWith('didInitializeI18n', {
      numberOfContentTypes: 1,
    });
  });

  test('sendDidUpdateI18nLocalesEvent', async () => {
    global.strapi = {
      contentTypes: {
        withI18n: {
          pluginOptions: {
            i18n: {
              localized: true,
            },
          },
        },
        withoutI18n: {
          pluginOptions: {
            i18n: {
              localized: false,
            },
          },
        },
        withNoOption: {
          pluginOptions: {},
        },
      },
      plugins: {
        i18n: {
          services: {
            locales: {
              count: jest.fn(() => 3),
            },
          },
        },
      },
      telemetry: {
        send: jest.fn(),
      },
    };

    const { sendDidUpdateI18nLocalesEvent } = metricsLoader({ strapi });

    await sendDidUpdateI18nLocalesEvent();

    expect(strapi.telemetry.send).toHaveBeenCalledWith('didUpdateI18nLocales', {
      numberOfLocales: 3,
    });
  });
});
