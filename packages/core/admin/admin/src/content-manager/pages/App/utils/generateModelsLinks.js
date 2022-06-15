import { chain, get } from 'lodash';
import { stringify } from 'qs';

const generateLinks = (links, type, configurations = []) => {
  return links
    .filter(link => link.isDisplayed)
    .map(link => {
      const collectionTypesPermissions = [
        { action: 'plugin::content-manager.explorer.create', subject: link.uid },
        { action: 'plugin::content-manager.explorer.read', subject: link.uid },
      ];
      const singleTypesPermissions = [
        { action: 'plugin::content-manager.explorer.read', subject: link.uid },
      ];
      const permissions =
        type === 'collectionTypes' ? collectionTypesPermissions : singleTypesPermissions;

      const currentContentTypeConfig = configurations.find(({ uid }) => uid === link.uid);

      let search = null;

      if (currentContentTypeConfig) {
        const searchParams = {
          page: 1,
          pageSize: currentContentTypeConfig.settings.pageSize,
          sort: `${currentContentTypeConfig.settings.defaultSortBy}:${currentContentTypeConfig.settings.defaultSortOrder}`,
        };

        search = stringify(searchParams, { encode: false });
      }

      return {
        permissions,
        search,
        kind: link.kind,
        title: link.info.displayName,
        to: `/content-manager/${link.kind}/${link.uid}`,
        uid: link.uid,
        // Used for the list item key in the helper plugin
        name: link.uid,
        isDisplayed: link.isDisplayed,
      };
    });
};

const generateModelsLinks = (models, modelsConfigurations) => {
  const [collectionTypes, singleTypes] = chain(models)
    .groupBy('kind')
    .map((value, key) => ({ name: key, links: value }))
    .sortBy('name')
    .value();

  return {
    collectionTypesSectionLinks: generateLinks(
      get(collectionTypes, 'links', []),
      'collectionTypes',
      modelsConfigurations
    ),
    singleTypesSectionLinks: generateLinks(get(singleTypes, 'links', []), 'singleTypes'),
  };
};

export default generateModelsLinks;
export { generateLinks };
