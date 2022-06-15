import React from 'react';
import { CheckPagePermissions } from '@strapi/helper-plugin';
import adminPermissions from '../../../../../../../admin/src/permissions';
import ListPage from '../ListPage';

const ProtectedListPage = () => (
  <CheckPagePermissions permissions={adminPermissions.settings.roles.main}>
    <ListPage />
  </CheckPagePermissions>
);

export default ProtectedListPage;
