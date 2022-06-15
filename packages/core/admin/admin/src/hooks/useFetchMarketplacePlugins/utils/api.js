import axios from 'axios';

const MARKETPLACE_API_URL = 'https://market-api.strapi.io';

const fetchMarketplacePlugins = async () => {
  const { data: response } = await axios.get(`${MARKETPLACE_API_URL}/plugins`);

  // Only keep v4 plugins
  const filteredResponse = {
    ...response,
    data: response.data.filter(plugin => plugin.attributes.strapiCompatibility === 'v4'),
  };

  return filteredResponse;
};

export { fetchMarketplacePlugins };
