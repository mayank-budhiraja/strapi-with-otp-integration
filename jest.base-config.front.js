'use strict';

const IS_EE = process.env.IS_EE === 'true';

const moduleNameMapper = {
  '.*\\.(css|less|styl|scss|sass)$': '<rootDir>/packages/admin-test-utils/lib/mocks/cssModule.js',
  '.*\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga|ico)$':
    '<rootDir>/packages/admin-test-utils/lib/mocks/image.js',
  '^ee_else_ce(/.*)$': IS_EE
    ? [
        '<rootDir>/packages/core/admin/ee/admin$1',
        '<rootDir>/packages/core/content-manager/ee/admin/src$1',
        '<rootDir>/packages/core/content-type-builder/ee/admin/src$1',
        '<rootDir>/packages/core/upload/ee/admin/src$1',
        '<rootDir>/packages/core/email/ee/admin/src$1',
        '<rootDir>/packages/plugins/*/ee/admin/src$1',
      ]
    : [
        '<rootDir>/packages/core/admin/admin/src$1',
        '<rootDir>/packages/core/content-manager/admin/src$1',
        '<rootDir>/packages/core/content-type-builder/admin/src$1',
        '<rootDir>/packages/core/upload/admin/src$1',
        '<rootDir>/packages/core/email/admin/src$1',
        '<rootDir>/packages/plugins/*/admin/src$1',
      ],
};

module.exports = {
  rootDir: __dirname,
  moduleNameMapper,
  collectCoverageFrom: [
    '<rootDir>/packages/core/*/admin/src/**/*.js',
    '<rootDir>/packages/plugins/*/admin/src/**/*.js',
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '<rootDir>/examples/getstarted/',
    '<rootDir>/examples/kitchensink/',
    '<rootDir>/packages/strapi-helper-plugin/dist/',
    '__tests__',
  ],
  globalSetup: '<rootDir>/test/config/front/global-setup.js',
  setupFiles: [
    '<rootDir>/packages/admin-test-utils/lib/setup/test-bundler.js',
    '<rootDir>/packages/admin-test-utils/lib/mocks/LocalStorageMock.js',
    '<rootDir>/packages/admin-test-utils/lib/mocks/IntersectionObserver.js',
    '<rootDir>/packages/admin-test-utils/lib/mocks/ResizeObserver.js',
    '<rootDir>/packages/admin-test-utils/lib/mocks/windowMatchMedia.js',
  ],
  setupFilesAfterEnv: [
    '<rootDir>/packages/admin-test-utils/lib/setup/styled-components.js',
    '<rootDir>/packages/admin-test-utils/lib/setup/strapi.js',
  ],
  transform: {
    '^.+\\.js$': ['@swc-node/jest', { jsx: true, dynamicImport: true }],
    '\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$':
      '<rootDir>/fileTransformer.js',
  },
  transformIgnorePatterns: ['node_modules/(?!(react-dnd|dnd-core|react-dnd-html5-backend)/)'],
  testMatch: ['/**/tests/**/?(*.)+(spec|test).[jt]s?(x)'],
  testURL: 'http://localhost:1337/admin',
};
