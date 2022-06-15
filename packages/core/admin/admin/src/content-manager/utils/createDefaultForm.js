import { get } from 'lodash';

const createDefaultForm = (attributes, allComponentsSchema) => {
  return Object.keys(attributes).reduce((acc, current) => {
    const attribute = get(attributes, [current], {});
    const { default: defaultValue, component, type, required, min, repeatable } = attribute;

    if (type === 'json') {
      acc[current] = null;
    }

    if (type === 'json' && required === true) {
      acc[current] = {};
    }

    if (defaultValue !== undefined) {
      acc[current] = defaultValue;
    }

    if (type === 'component') {
      const currentComponentSchema = get(allComponentsSchema, [component, 'attributes'], {});
      const currentComponentDefaultForm = createDefaultForm(
        currentComponentSchema,
        allComponentsSchema
      );

      if (required === true) {
        acc[current] = repeatable === true ? [] : currentComponentDefaultForm;
      }

      if (min && repeatable === true && required) {
        acc[current] = [];

        for (let i = 0; i < min; i += 1) {
          acc[current].push(currentComponentDefaultForm);
        }
      }
    }

    if (type === 'dynamiczone') {
      if (required === true) {
        acc[current] = [];
      }
    }

    return acc;
  }, {});
};

export default createDefaultForm;
