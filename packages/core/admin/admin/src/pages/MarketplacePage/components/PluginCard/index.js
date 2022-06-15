import React from 'react';
import PropTypes from 'prop-types';
import { useIntl } from 'react-intl';
import styled from 'styled-components';
import { Box } from '@strapi/design-system/Box';
import { Stack } from '@strapi/design-system/Stack';
import { Typography } from '@strapi/design-system/Typography';
import { LinkButton } from '@strapi/design-system/v2/LinkButton';
import { Flex } from '@strapi/design-system/Flex';
import { Icon } from '@strapi/design-system/Icon';
import { Tooltip } from '@strapi/design-system/Tooltip';
import ExternalLink from '@strapi/icons/ExternalLink';
import CheckCircle from '@strapi/icons/CheckCircle';
import { useTracking } from '@strapi/helper-plugin';
import madeByStrapiIcon from '../../../../assets/images/icon_made-by-strapi.svg';
import InstallPluginButton from './InstallPluginButton';

// Custom component to have an ellipsis after the 2nd line
const EllipsisText = styled(Typography)`
  /* stylelint-disable value-no-vendor-prefix, property-no-vendor-prefix */
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  /* stylelint-enable value-no-vendor-prefix, property-no-vendor-prefix */
  overflow: hidden;
`;

const PluginCard = ({ plugin, installedPluginNames, useYarn, isInDevelopmentMode }) => {
  const { attributes } = plugin;
  const { formatMessage } = useIntl();
  const { trackUsage } = useTracking();

  const isInstalled = installedPluginNames.includes(attributes.npmPackageName);

  const commandToCopy = useYarn
    ? `yarn add ${attributes.npmPackageName}`
    : `npm install ${attributes.npmPackageName}`;

  const madeByStrapiMessage = formatMessage({
    id: 'admin.pages.MarketPlacePage.plugin.tooltip.madeByStrapi',
    defaultMessage: 'Made by Strapi',
  });

  return (
    <Flex
      direction="column"
      justifyContent="space-between"
      paddingTop={4}
      paddingRight={4}
      paddingBottom={4}
      paddingLeft={4}
      hasRadius
      background="neutral0"
      shadow="tableShadow"
      height="100%"
      alignItems="normal"
    >
      <Box>
        <Box
          as="img"
          src={attributes.logo.url}
          alt={`${attributes.name} logo`}
          hasRadius
          width={11}
          height={11}
        />
        <Box paddingTop={4}>
          <Typography as="h3" variant="delta">
            <Flex alignItems="center">
              {attributes.name}
              {attributes.validated && !attributes.madeByStrapi && (
                <Tooltip
                  description={formatMessage({
                    id: 'admin.pages.MarketPlacePage.plugin.tooltip.verified',
                    defaultMessage: 'Plugin verified by Strapi',
                  })}
                >
                  <Flex>
                    <Icon as={CheckCircle} marginLeft={2} color="success600" />
                  </Flex>
                </Tooltip>
              )}
              {attributes.madeByStrapi && (
                <Tooltip description={madeByStrapiMessage}>
                  <Flex>
                    <Box
                      as="img"
                      src={madeByStrapiIcon}
                      alt={madeByStrapiMessage}
                      marginLeft={1}
                      width={6}
                      height="auto"
                    />
                  </Flex>
                </Tooltip>
              )}
            </Flex>
          </Typography>
        </Box>
        <Box paddingTop={2}>
          <EllipsisText as="p" variant="omega" textColor="neutral600">
            {attributes.description}
          </EllipsisText>
        </Box>
      </Box>

      <Stack horizontal spacing={2} style={{ alignSelf: 'flex-end' }} paddingTop={6}>
        <LinkButton
          size="S"
          href={`https://market.strapi.io/plugins/${attributes.slug}`}
          isExternal
          endIcon={<ExternalLink />}
          aria-label={formatMessage(
            {
              id: 'admin.pages.MarketPlacePage.plugin.info.label',
              defaultMessage: 'Learn more about {pluginName}',
            },
            { pluginName: attributes.name }
          )}
          variant="tertiary"
          onClick={() => trackUsage('didPluginLearnMore')}
        >
          {formatMessage({
            id: 'admin.pages.MarketPlacePage.plugin.info.text',
            defaultMessage: 'Learn more',
          })}
        </LinkButton>
        <InstallPluginButton
          isInstalled={isInstalled}
          isInDevelopmentMode={isInDevelopmentMode}
          commandToCopy={commandToCopy}
        />
      </Stack>
    </Flex>
  );
};

PluginCard.defaultProps = {
  isInDevelopmentMode: false,
};

PluginCard.propTypes = {
  plugin: PropTypes.shape({
    id: PropTypes.string.isRequired,
    attributes: PropTypes.shape({
      name: PropTypes.string.isRequired,
      description: PropTypes.string.isRequired,
      slug: PropTypes.string.isRequired,
      npmPackageName: PropTypes.string.isRequired,
      npmPackageUrl: PropTypes.string.isRequired,
      repositoryUrl: PropTypes.string.isRequired,
      logo: PropTypes.object.isRequired,
      developerName: PropTypes.string.isRequired,
      validated: PropTypes.bool.isRequired,
      madeByStrapi: PropTypes.bool.isRequired,
      strapiCompatibility: PropTypes.oneOf(['v3', 'v4']).isRequired,
    }).isRequired,
  }).isRequired,
  installedPluginNames: PropTypes.arrayOf(PropTypes.string).isRequired,
  useYarn: PropTypes.bool.isRequired,
  isInDevelopmentMode: PropTypes.bool,
};

export default PluginCard;
