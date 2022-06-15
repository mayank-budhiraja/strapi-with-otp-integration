import React from 'react';
import PropTypes from 'prop-types';
import { Link } from '@strapi/helper-plugin';
import { Box } from '@strapi/design-system/Box';
import { Flex } from '@strapi/design-system/Flex';
import { Typography } from '@strapi/design-system/Typography';
import Cog from '@strapi/icons/Cog';
import { useIntl } from 'react-intl';
import get from 'lodash/get';
import { Grid, GridItem } from '@strapi/design-system/Grid';
import useLayoutDnd from '../../../hooks/useLayoutDnd';
import getTrad from '../../../utils/getTrad';

const ComponentFieldList = ({ componentUid }) => {
  const { componentLayouts } = useLayoutDnd();
  const { formatMessage } = useIntl();
  const componentData = get(componentLayouts, [componentUid], {});
  const componentLayout = get(componentData, ['layouts', 'edit'], []);

  return (
    <Box padding={3}>
      {componentLayout.map((row, index) => (
        // eslint-disable-next-line react/no-array-index-key
        <Grid gap={4} key={index}>
          {row.map(rowContent => (
            <GridItem key={rowContent.name} col={rowContent.size}>
              <Box paddingTop={2}>
                <Flex
                  alignItems="center"
                  background="neutral0"
                  paddingLeft={3}
                  paddingRight={3}
                  height={`${32 / 16}rem`}
                  hasRadius
                  borderColor="neutral200"
                >
                  <Typography textColor="neutral800">{rowContent.name}</Typography>
                </Flex>
              </Box>
            </GridItem>
          ))}
        </Grid>
      ))}
      <Box paddingTop={2}>
        <Link
          startIcon={<Cog />}
          to={`/content-manager/components/${componentUid}/configurations/edit`}
        >
          {formatMessage({
            id: getTrad('components.FieldItem.linkToComponentLayout'),
            defaultMessage: "Set the component's layout",
          })}
        </Link>
      </Box>
    </Box>
  );
};

ComponentFieldList.propTypes = {
  componentUid: PropTypes.string.isRequired,
};

export default ComponentFieldList;
