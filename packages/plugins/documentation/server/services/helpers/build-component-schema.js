'use strict';
const _ = require('lodash');

const cleanSchemaAttributes = require('./utils/clean-schema-attributes');
const loopContentTypeNames = require('./utils/loop-content-type-names');
const pascalCase = require('./utils/pascal-case');
const { hasFindMethod, isLocalizedPath } = require('./utils/routes');

/**
 * @decription Get all open api schema objects for a given content type
 *
 * @param {object} apiInfo
 * @property {string} apiInfo.uniqueName - Api name | Api name + Content type name
 * @property {object} apiInfo.attributes - Attributes on content type
 * @property {object} apiInfo.routeInfo - The routes for the api
 *
 * @returns {object} Open API schemas
 */
const getAllSchemasForContentType = ({ routeInfo, attributes, uniqueName }) => {
  // Store response and request schemas in an object
  let schemas = {};
  // Get all the route methods
  const routeMethods = routeInfo.routes.map(route => route.method);
  // Check for localized paths
  const hasLocalizationPath = routeInfo.routes.filter(route => isLocalizedPath(route.path)).length;
  // When the route methods contain any post or put requests
  if (routeMethods.includes('POST') || routeMethods.includes('PUT')) {
    const attributesToOmit = [
      'createdAt',
      'updatedAt',
      'publishedAt',
      'publishedBy',
      'updatedBy',
      'createdBy',
      'localizations',
    ];
    const attributesForRequest = _.omit(attributes, attributesToOmit);

    // Get a list of required attribute names
    const requiredAttributes = Object.entries(attributesForRequest).reduce((acc, attribute) => {
      const [attributeKey, attributeValue] = attribute;

      if (attributeValue.required) {
        acc.push(attributeKey);
      }

      return acc;
    }, []);

    if (hasLocalizationPath) {
      schemas = {
        ...schemas,
        [`${pascalCase(uniqueName)}LocalizationRequest`]: {
          required: [...requiredAttributes, 'locale'],
          type: 'object',
          properties: cleanSchemaAttributes(attributesForRequest, { isRequest: true }),
        },
      };
    }

    // Build the request schema
    schemas = {
      ...schemas,
      [`${pascalCase(uniqueName)}Request`]: {
        type: 'object',
        required: ['data'],
        properties: {
          data: {
            required: requiredAttributes,
            type: 'object',
            properties: cleanSchemaAttributes(attributesForRequest, { isRequest: true }),
          },
        },
      },
    };
  }

  if (hasLocalizationPath) {
    schemas = {
      ...schemas,
      [`${pascalCase(uniqueName)}LocalizationResponse`]: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          ...cleanSchemaAttributes(attributes),
        },
      },
    };
  }

  // Check for routes that need to return a list
  const hasListOfEntities = routeInfo.routes.filter(route => hasFindMethod(route.handler)).length;
  if (hasListOfEntities) {
    // Build the list response schema
    schemas = {
      ...schemas,
      [`${pascalCase(uniqueName)}ListResponse`]: {
        type: 'object',
        properties: {
          data: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                attributes: { type: 'object', properties: cleanSchemaAttributes(attributes) },
              },
            },
          },
          meta: {
            type: 'object',
            properties: {
              pagination: {
                properties: {
                  page: { type: 'integer' },
                  pageSize: { type: 'integer', minimum: 25 },
                  pageCount: { type: 'integer', maximum: 1 },
                  total: { type: 'integer' },
                },
              },
            },
          },
        },
      },
    };
  }

  // Build the response schema
  schemas = {
    ...schemas,
    [`${pascalCase(uniqueName)}Response`]: {
      type: 'object',
      properties: {
        data: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            attributes: { type: 'object', properties: cleanSchemaAttributes(attributes) },
          },
        },
        meta: { type: 'object' },
      },
    },
  };

  return schemas;
};

const buildComponentSchema = api => {
  // A reusable loop for building paths and component schemas
  // Uses the api param to build a new set of params for each content type
  // Passes these new params to the function provided
  return loopContentTypeNames(api, getAllSchemasForContentType);
};

module.exports = buildComponentSchema;
