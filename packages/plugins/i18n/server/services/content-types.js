'use strict';

const _ = require('lodash');
const { pick, pipe, has, prop, isNil, cloneDeep, isArray, difference } = require('lodash/fp');
const {
  isRelationalAttribute,
  getVisibleAttributes,
  isTypedAttribute,
  getScalarAttributes,
} = require('@strapi/utils').contentTypes;
const { ApplicationError } = require('@strapi/utils').errors;
const { getService } = require('../utils');

const hasLocalizedOption = modelOrAttribute => {
  return prop('pluginOptions.i18n.localized', modelOrAttribute) === true;
};

const getValidLocale = async locale => {
  const localesService = getService('locales');

  if (isNil(locale)) {
    return localesService.getDefaultLocale();
  }

  const foundLocale = await localesService.findByCode(locale);
  if (!foundLocale) {
    throw new ApplicationError('Locale not found');
  }

  return locale;
};

/**
 * Get the related entity used for entity creation
 * @param {Object} relatedEntity related entity
 * @returns {id[]} related entity
 */
const getNewLocalizationsFrom = async relatedEntity => {
  if (relatedEntity) {
    return [relatedEntity.id, ...relatedEntity.localizations.map(prop('id'))];
  }

  return [];
};

/**
 * Get the related entity used for entity creation
 * @param {id} relatedEntityId related entity id
 * @param {string} model corresponding model
 * @param {string} locale locale of the entity to create
 * @returns {Object} related entity
 */
const getAndValidateRelatedEntity = async (relatedEntityId, model, locale) => {
  const { kind } = strapi.getModel(model);
  let relatedEntity;

  if (kind === 'singleType') {
    relatedEntity = await strapi.query(model).findOne({ populate: ['localizations'] });
  } else if (relatedEntityId) {
    relatedEntity = await strapi
      .query(model)
      .findOne({ where: { id: relatedEntityId }, populate: ['localizations'] });
  }

  if (relatedEntityId && !relatedEntity) {
    throw new ApplicationError("The related entity doesn't exist");
  }

  if (
    relatedEntity &&
    (relatedEntity.locale === locale ||
      relatedEntity.localizations.map(prop('locale')).includes(locale))
  ) {
    throw new ApplicationError('The entity already exists in this locale');
  }

  return relatedEntity;
};

/**
 * Returns whether an attribute is localized or not
 * @param {*} attribute
 * @returns
 */
const isLocalizedAttribute = attribute => {
  return (
    hasLocalizedOption(attribute) ||
    isRelationalAttribute(attribute) ||
    isTypedAttribute(attribute, 'uid')
  );
};

/**
 * Returns whether a model is localized or not
 * @param {*} model
 * @returns
 */
const isLocalizedContentType = model => {
  return hasLocalizedOption(model);
};

/**
 * Returns the list of attribute names that are not localized
 * @param {object} model
 * @returns {string[]}
 */
const getNonLocalizedAttributes = model => {
  return getVisibleAttributes(model).filter(
    attrName => !isLocalizedAttribute(model.attributes[attrName])
  );
};

const removeId = value => {
  if (typeof value === 'object' && has('id', value)) {
    delete value.id;
  }
};

const removeIds = model => entry => removeIdsMut(model, cloneDeep(entry));

const removeIdsMut = (model, entry) => {
  if (isNil(entry)) {
    return entry;
  }

  removeId(entry);

  _.forEach(model.attributes, (attr, attrName) => {
    const value = entry[attrName];
    if (attr.type === 'dynamiczone' && isArray(value)) {
      value.forEach(compo => {
        if (has('__component', compo)) {
          const model = strapi.components[compo.__component];
          removeIdsMut(model, compo);
        }
      });
    } else if (attr.type === 'component') {
      const model = strapi.components[attr.component];
      if (isArray(value)) {
        value.forEach(compo => removeIdsMut(model, compo));
      } else {
        removeIdsMut(model, value);
      }
    }
  });

  return entry;
};

/**
 * Returns a copy of an entry picking only its non localized attributes
 * @param {object} model
 * @param {object} entry
 * @returns {object}
 */
const copyNonLocalizedAttributes = (model, entry) => {
  const nonLocalizedAttributes = getNonLocalizedAttributes(model);

  return pipe(pick(nonLocalizedAttributes), removeIds(model))(entry);
};

/**
 * Returns the list of attribute names that are localized
 * @param {object} model
 * @returns {string[]}
 */
const getLocalizedAttributes = model => {
  return getVisibleAttributes(model).filter(attrName =>
    isLocalizedAttribute(model.attributes[attrName])
  );
};

/**
 * Fill non localized fields of an entry if there are nil
 * @param {Object} entry entry to fill
 * @param {Object} relatedEntry values used to fill
 * @param {Object} options
 * @param {Object} options.model corresponding model
 */
const fillNonLocalizedAttributes = (entry, relatedEntry, { model }) => {
  if (isNil(relatedEntry)) {
    return;
  }

  const modelDef = strapi.getModel(model);
  const relatedEntryCopy = copyNonLocalizedAttributes(modelDef, relatedEntry);

  _.forEach(relatedEntryCopy, (value, field) => {
    if (isNil(entry[field])) {
      entry[field] = value;
    }
  });
};

/**
 * build the populate param to
 * @param {String} modelUID uid of the model, could be of a content-type or a component
 */
const getNestedPopulateOfNonLocalizedAttributes = modelUID => {
  const schema = strapi.getModel(modelUID);
  const scalarAttributes = getScalarAttributes(schema);
  const nonLocalizedAttributes = getNonLocalizedAttributes(schema);
  const currentAttributesToPopulate = difference(nonLocalizedAttributes, scalarAttributes);
  const attributesToPopulate = [...currentAttributesToPopulate];

  for (let attrName of currentAttributesToPopulate) {
    const attr = schema.attributes[attrName];
    if (attr.type === 'component') {
      const nestedPopulate = getNestedPopulateOfNonLocalizedAttributes(attr.component).map(
        nestedAttr => `${attrName}.${nestedAttr}`
      );
      attributesToPopulate.push(...nestedPopulate);
    } else if (attr.type === 'dynamiczone') {
      attr.components.forEach(componentName => {
        const nestedPopulate = getNestedPopulateOfNonLocalizedAttributes(componentName).map(
          nestedAttr => `${attrName}.${nestedAttr}`
        );
        attributesToPopulate.push(...nestedPopulate);
      });
    }
  }

  return attributesToPopulate;
};

module.exports = () => ({
  isLocalizedContentType,
  getValidLocale,
  getNewLocalizationsFrom,
  getLocalizedAttributes,
  getNonLocalizedAttributes,
  copyNonLocalizedAttributes,
  getAndValidateRelatedEntity,
  fillNonLocalizedAttributes,
  getNestedPopulateOfNonLocalizedAttributes,
});
