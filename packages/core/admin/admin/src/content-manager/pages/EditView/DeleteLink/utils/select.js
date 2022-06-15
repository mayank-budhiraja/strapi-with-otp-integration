import { isEmpty } from 'lodash';
import { useCMEditViewDataManager } from '@strapi/helper-plugin';

function useSelect() {
  const { hasDraftAndPublish, modifiedData } = useCMEditViewDataManager();

  let trackerProperty = {};

  if (hasDraftAndPublish) {
    const isDraft = isEmpty(modifiedData.publishedAt);

    trackerProperty = isDraft ? { status: 'draft' } : { status: 'published' };
  }

  return {
    hasDraftAndPublish,
    trackerProperty,
  };
}

export default useSelect;
