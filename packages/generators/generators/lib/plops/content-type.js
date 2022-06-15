'use strict';

const { join } = require('path');
const slugify = require('@sindresorhus/slugify');
const fs = require('fs-extra');
const { isKebabCase } = require('@strapi/utils');

const getDestinationPrompts = require('./prompts/get-destination-prompts');
const getFilePath = require('./utils/get-file-path');
const ctNamesPrompts = require('./prompts/ct-names-prompts');
const kindPrompts = require('./prompts/kind-prompts');
const draftAndPublishPrompts = require('./prompts/draft-and-publish-prompts');
const getAttributesPrompts = require('./prompts/get-attributes-prompts');
const bootstrapApiPrompts = require('./prompts/bootstrap-api-prompts');

module.exports = plop => {
  // Model generator
  plop.setGenerator('content-type', {
    description: 'Generate a content type for an API',
    async prompts(inquirer) {
      const config = await inquirer.prompt([
        ...ctNamesPrompts,
        ...kindPrompts,
        ...draftAndPublishPrompts,
      ]);
      const attributes = await getAttributesPrompts(inquirer);

      const api = await inquirer.prompt([
        ...getDestinationPrompts('model', plop.getDestBasePath()),
        {
          when: answers => answers.destination === 'new',
          type: 'input',
          name: 'id',
          default: config.singularName,
          message: 'Name of the new API?',
          async validate(input) {
            if (!isKebabCase(input)) {
              return 'Value must be in kebab-case';
            }

            const apiPath = join(plop.getDestBasePath(), 'api');
            const exists = await fs.pathExists(apiPath);

            if (!exists) {
              return true;
            }

            const apiDir = await fs.readdir(apiPath, { withFileTypes: true });
            const apiDirContent = apiDir.filter(fd => fd.isDirectory());

            if (apiDirContent.findIndex(api => api.name === input) !== -1) {
              throw new Error('This name is already taken.');
            }

            return true;
          },
        },
        ...bootstrapApiPrompts,
      ]);

      return {
        ...config,
        ...api,
        attributes,
      };
    },
    actions(answers) {
      const attributes = answers.attributes.reduce((object, answer) => {
        const val = { type: answer.attributeType };

        if (answer.attributeType === 'enumeration') {
          val.enum = answer.enum.split(',').map(item => item.trim());
        }

        if (answer.attributeType === 'media') {
          val.allowedTypes = ['images', 'files', 'videos', 'audios'];
          val.multiple = answer.multiple;
        }

        return Object.assign(object, { [answer.attributeName]: val }, {});
      }, {});

      const filePath = getFilePath(answers.destination);

      const baseActions = [
        {
          type: 'add',
          path: `${filePath}/content-types/{{ singularName }}/schema.json`,
          templateFile: 'templates/content-type.schema.json.hbs',
          data: {
            collectionName: slugify(answers.pluralName, { separator: '_' }),
          },
        },
      ];

      if (Object.entries(attributes).length > 0) {
        baseActions.push({
          type: 'modify',
          path: `${filePath}/content-types/{{ singularName }}/schema.json`,
          transform(template) {
            const parsedTemplate = JSON.parse(template);
            parsedTemplate.attributes = attributes;
            return JSON.stringify(parsedTemplate, null, 2);
          },
        });
      }

      if (answers.bootstrapApi) {
        const { singularName } = answers;

        let uid;
        if (answers.destination === 'new') {
          uid = `api::${answers.id}.${singularName}`;
        } else if (answers.api) {
          uid = `api::${answers.api}.${singularName}`;
        } else if (answers.plugin) {
          uid = `plugin::${answers.plugin}.${singularName}`;
        }

        baseActions.push(
          {
            type: 'add',
            path: `${filePath}/controllers/{{singularName}}.js`,
            templateFile: 'templates/core-controller.js.hbs',
            data: { uid },
          },
          {
            type: 'add',
            path: `${filePath}/services/{{singularName}}.js`,
            templateFile: 'templates/core-service.js.hbs',
            data: { uid },
          },
          {
            type: 'add',
            path: `${filePath}/routes/{{singularName}}.js`,
            templateFile: `templates/core-router.js.hbs`,
            data: { uid },
          }
        );
      }

      return baseActions;
    },
  });
};
