import React from 'react';
import PropTypes from 'prop-types';
import { useIntl } from 'react-intl';
import styled from 'styled-components';
import { pxToRem } from '@strapi/helper-plugin';
import Check from '@strapi/icons/Check';
import Cross from '@strapi/icons/Cross';
import Loader from '@strapi/icons/Loader';
import { Box } from '@strapi/design-system/Box';
import { Flex } from '@strapi/design-system/Flex';
import { Typography } from '@strapi/design-system/Typography';
import { Stack } from '@strapi/design-system/Stack';
import { Grid, GridItem } from '@strapi/design-system/Grid';

// Being discussed in Notion: create a <Icon /> component in Parts
const Icon = styled.svg(
  ({ theme, color }) => `
  width: ${12 / 16}rem;
  height: ${12 / 16}rem;

  path {
    fill: ${theme.colors[color]};
  }
`
);

const Status = ({ isPending, statusCode }) => {
  const { formatMessage } = useIntl();

  if (isPending) {
    return (
      <Stack horizontal spacing={2} style={{ alignItems: 'center' }}>
        <Icon as={Loader} />
        <Typography>
          {formatMessage({ id: 'Settings.webhooks.trigger.pending', defaultMessage: 'pending' })}
        </Typography>
      </Stack>
    );
  }

  if (statusCode >= 200 && statusCode < 300) {
    return (
      <Stack horizontal spacing={2} style={{ alignItems: 'center' }}>
        <Icon as={Check} color="success700" />
        <Typography>
          {formatMessage({ id: 'Settings.webhooks.trigger.success', defaultMessage: 'success' })}
        </Typography>
      </Stack>
    );
  }

  if (statusCode >= 300) {
    return (
      <Stack horizontal spacing={2} style={{ alignItems: 'center' }}>
        <Icon as={Cross} color="danger700" />
        <Typography>
          {formatMessage({ id: 'Settings.error', defaultMessage: 'error' })} {statusCode}
        </Typography>
      </Stack>
    );
  }

  return null;
};
Status.propTypes = {
  isPending: PropTypes.bool.isRequired,
  statusCode: PropTypes.number,
};
Status.defaultProps = {
  statusCode: undefined,
};

const Message = ({ statusCode, message }) => {
  const { formatMessage } = useIntl();

  if (statusCode >= 200 && statusCode < 300) {
    return (
      <Flex justifyContent="flex-end">
        <Typography textColor="neutral600" ellipsis>
          {formatMessage({
            id: 'Settings.webhooks.trigger.success.label',
            defaultMessage: 'Trigger succeeded',
          })}
        </Typography>
      </Flex>
    );
  }

  if (statusCode >= 300) {
    return (
      <Flex justifyContent="flex-end">
        <Flex maxWidth={pxToRem(250)} justifyContent="flex-end" title={message}>
          <Typography ellipsis textColor="neutral600">
            {message}
          </Typography>
        </Flex>
      </Flex>
    );
  }

  return null;
};
Message.propTypes = {
  statusCode: PropTypes.number,
  message: PropTypes.string,
};
Message.defaultProps = {
  statusCode: undefined,
  message: undefined,
};

const CancelButton = ({ onCancel }) => {
  const { formatMessage } = useIntl();

  return (
    <Flex justifyContent="flex-end">
      <button onClick={onCancel} type="button">
        <Stack horizontal spacing={2} style={{ alignItems: 'center' }}>
          <Typography textColor="neutral400">
            {formatMessage({ id: 'Settings.webhooks.trigger.cancel', defaultMessage: 'cancel' })}
          </Typography>
          <Icon as={Cross} color="neutral400" />
        </Stack>
      </button>
    </Flex>
  );
};

CancelButton.propTypes = { onCancel: PropTypes.func.isRequired };

const TriggerContainer = ({ isPending, onCancel, response }) => {
  const { statusCode, message } = response;
  const { formatMessage } = useIntl();

  return (
    <Box background="neutral0" padding={5} shadow="filterShadow" hasRadius>
      <Grid gap={4} style={{ alignItems: 'center' }}>
        <GridItem col={3}>
          <Typography>
            {formatMessage({
              id: 'Settings.webhooks.trigger.test',
              defaultMessage: 'Test-trigger',
            })}
          </Typography>
        </GridItem>
        <GridItem col={3}>
          <Status isPending={isPending} statusCode={statusCode} />
        </GridItem>
        <GridItem col={6}>
          {!isPending ? (
            <Message statusCode={statusCode} message={message} />
          ) : (
            <CancelButton onCancel={onCancel} />
          )}
        </GridItem>
      </Grid>
    </Box>
  );
};

TriggerContainer.defaultProps = {
  isPending: false,
  onCancel: () => {},
  response: {},
};

TriggerContainer.propTypes = {
  isPending: PropTypes.bool,
  onCancel: PropTypes.func,
  response: PropTypes.object,
};

export default TriggerContainer;
