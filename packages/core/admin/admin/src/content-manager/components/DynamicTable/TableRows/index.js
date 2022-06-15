import React from 'react';
import PropTypes from 'prop-types';
import { BaseCheckbox } from '@strapi/design-system/BaseCheckbox';
import { Box } from '@strapi/design-system/Box';
import { IconButton } from '@strapi/design-system/IconButton';
import { Tbody, Td, Tr } from '@strapi/design-system/Table';
import { Flex } from '@strapi/design-system/Flex';
import Trash from '@strapi/icons/Trash';
import Duplicate from '@strapi/icons/Duplicate';
import Pencil from '@strapi/icons/Pencil';
import { useTracking, stopPropagation, onRowClick } from '@strapi/helper-plugin';
import { useHistory } from 'react-router-dom';
import { useIntl } from 'react-intl';
import { usePluginsQueryParams } from '../../../hooks';
import CellContent from '../CellContent';
import { getFullName } from '../../../../utils';

const TableRows = ({
  canCreate,
  canDelete,
  headers,
  entriesToDelete,
  onClickDelete,
  onSelectRow,
  withMainAction,
  withBulkActions,
  rows,
}) => {
  const {
    push,
    location: { pathname },
  } = useHistory();
  const { formatMessage } = useIntl();

  const { trackUsage } = useTracking();
  const pluginsQueryParams = usePluginsQueryParams();

  return (
    <Tbody>
      {rows.map((data, index) => {
        const isChecked = entriesToDelete.findIndex(id => id === data.id) !== -1;
        const itemLineText = formatMessage(
          {
            id: 'content-manager.components.DynamicTable.row-line',
            defaultMessage: 'item line {number}',
          },
          { number: index }
        );

        return (
          <Tr
            key={data.id}
            {...onRowClick({
              fn: () => {
                trackUsage('willEditEntryFromList');
                push({
                  pathname: `${pathname}/${data.id}`,
                  state: { from: pathname },
                  search: pluginsQueryParams,
                });
              },
              condition: withBulkActions,
            })}
          >
            {withMainAction && (
              <Td {...stopPropagation}>
                <BaseCheckbox
                  aria-label={formatMessage(
                    {
                      id: 'app.component.table.select.one-entry',
                      defaultMessage: `Select {target}`,
                    },
                    { target: getFullName(data.firstname, data.lastname) }
                  )}
                  checked={isChecked}
                  onChange={() => {
                    onSelectRow({ name: data.id, value: !isChecked });
                  }}
                />
              </Td>
            )}
            {headers.map(({ key, cellFormatter, name, ...rest }) => {
              return (
                <Td key={key}>
                  {typeof cellFormatter === 'function' ? (
                    cellFormatter(data, { key, name, ...rest })
                  ) : (
                    <CellContent
                      content={data[name.split('.')[0]]}
                      name={name}
                      {...rest}
                      rowId={data.id}
                    />
                  )}
                </Td>
              );
            })}

            {withBulkActions && (
              <Td>
                <Flex justifyContent="end" {...stopPropagation}>
                  <IconButton
                    onClick={() => {
                      trackUsage('willEditEntryFromButton');
                      push({
                        pathname: `${pathname}/${data.id}`,
                        state: { from: pathname },
                        search: pluginsQueryParams,
                      });
                    }}
                    label={formatMessage(
                      { id: 'app.component.table.edit', defaultMessage: 'Edit {target}' },
                      { target: itemLineText }
                    )}
                    noBorder
                    icon={<Pencil />}
                  />

                  {canCreate && (
                    <Box paddingLeft={1}>
                      <IconButton
                        onClick={() => {
                          push({
                            pathname: `${pathname}/create/clone/${data.id}`,
                            state: { from: pathname },
                            search: pluginsQueryParams,
                          });
                        }}
                        label={formatMessage(
                          {
                            id: 'app.component.table.duplicate',
                            defaultMessage: 'Duplicate {target}',
                          },
                          { target: itemLineText }
                        )}
                        noBorder
                        icon={<Duplicate />}
                      />
                    </Box>
                  )}

                  {canDelete && (
                    <Box paddingLeft={1}>
                      <IconButton
                        onClick={() => {
                          trackUsage('willDeleteEntryFromList');

                          onClickDelete(data.id);
                        }}
                        label={formatMessage(
                          { id: 'global.delete-target', defaultMessage: 'Delete {target}' },
                          { target: itemLineText }
                        )}
                        noBorder
                        icon={<Trash />}
                      />
                    </Box>
                  )}
                </Flex>
              </Td>
            )}
          </Tr>
        );
      })}
    </Tbody>
  );
};

TableRows.defaultProps = {
  canCreate: false,
  canDelete: false,
  entriesToDelete: [],
  onClickDelete: () => {},
  onSelectRow: () => {},
  rows: [],
  withBulkActions: false,
  withMainAction: false,
};

TableRows.propTypes = {
  canCreate: PropTypes.bool,
  canDelete: PropTypes.bool,
  entriesToDelete: PropTypes.array,
  headers: PropTypes.array.isRequired,
  onClickDelete: PropTypes.func,
  onSelectRow: PropTypes.func,
  rows: PropTypes.array,
  withBulkActions: PropTypes.bool,
  withMainAction: PropTypes.bool,
};

export default TableRows;
