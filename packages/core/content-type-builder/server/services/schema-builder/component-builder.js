'use strict';

const path = require('path');
const _ = require('lodash');
const pluralize = require('pluralize');

const { nameToSlug, nameToCollectionName } = require('@strapi/utils');
const { ApplicationError } = require('@strapi/utils').errors;
const { isConfigurable } = require('../../utils/attributes');
const createSchemaHandler = require('./schema-handler');

module.exports = function createComponentBuilder() {
  return {
    /**
     * Returns a uid from a component infos
     * @param {Object} options options
     * @param {string} options.category component category
     * @param {string} options.displayName component displayName
     */
    createComponentUID({ category, displayName }) {
      return `${nameToSlug(category)}.${nameToSlug(displayName)}`;
    },

    createNewComponentUIDMap(components) {
      return components.reduce((uidMap, component) => {
        uidMap[component.tmpUID] = this.createComponentUID(component);
        return uidMap;
      }, {});
    },

    /**
     * create a component in the tmpComponent map
     */
    createComponent(infos) {
      const uid = this.createComponentUID(infos);

      if (this.components.has(uid)) {
        throw new ApplicationError('component.alreadyExists');
      }

      const handler = createSchemaHandler({
        dir: path.join(strapi.dirs.components, nameToSlug(infos.category)),
        filename: `${nameToSlug(infos.displayName)}.json`,
      });

      const collectionName = `components_${nameToCollectionName(
        infos.category
      )}_${nameToCollectionName(pluralize(infos.displayName))}`;

      handler
        .setUID(uid)
        .set('collectionName', collectionName)
        .set(['info', 'displayName'], infos.displayName)
        .set(['info', 'icon'], infos.icon)
        .set(['info', 'description'], infos.description)
        .set('pluginOptions', infos.pluginOptions)
        .set('config', infos.config)
        .setAttributes(this.convertAttributes(infos.attributes));

      if (this.components.size === 0) {
        strapi.telemetry.send('didCreateFirstComponent');
      } else {
        strapi.telemetry.send('didCreateComponent');
      }

      this.components.set(uid, handler);

      return handler;
    },

    /**
     * create a component in the tmpComponent map
     */
    editComponent(infos) {
      const { uid } = infos;

      if (!this.components.has(uid)) {
        throw new ApplicationError('component.notFound');
      }

      const component = this.components.get(uid);

      const [, nameUID] = uid.split('.');

      const newCategory = nameToSlug(infos.category);
      const newUID = `${newCategory}.${nameUID}`;

      if (newUID !== uid && this.components.has(newUID)) {
        throw new ApplicationError('component.edit.alreadyExists');
      }

      const newDir = path.join(strapi.dirs.components, newCategory);

      const oldAttributes = component.schema.attributes;

      const newAttributes = _.omitBy(infos.attributes, (attr, key) => {
        return _.has(oldAttributes, key) && !isConfigurable(oldAttributes[key]);
      });

      component
        .setUID(newUID)
        .setDir(newDir)
        .set(['info', 'displayName'], infos.displayName)
        .set(['info', 'icon'], infos.icon)
        .set(['info', 'description'], infos.description)
        .set('pluginOptions', infos.pluginOptions)
        .setAttributes(this.convertAttributes(newAttributes));

      if (newUID !== uid) {
        this.components.forEach(compo => {
          compo.updateComponent(uid, newUID);
        });

        this.contentTypes.forEach(ct => {
          ct.updateComponent(uid, newUID);
        });
      }

      return component;
    },

    deleteComponent(uid) {
      if (!this.components.has(uid)) {
        throw new ApplicationError('component.notFound');
      }

      this.components.forEach(compo => {
        compo.removeComponent(uid);
      });

      this.contentTypes.forEach(ct => {
        ct.removeComponent(uid);
      });

      return this.components.get(uid).delete();
    },
  };
};
