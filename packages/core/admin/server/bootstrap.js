'use strict';

const { merge } = require('lodash/fp');
const { getService } = require('./utils');
const adminActions = require('./config/admin-actions');
const adminConditions = require('./config/admin-conditions');

const defaultAdminAuthSettings = {
  providers: {
    autoRegister: false,
    defaultRole: null,
  },
};

const registerPermissionActions = async () => {
  await getService('permission').actionProvider.registerMany(adminActions.actions);
};

const registerAdminConditions = async () => {
  await getService('permission').conditionProvider.registerMany(adminConditions.conditions);
};

const registerModelHooks = () => {
  const { sendDidChangeInterfaceLanguage } = getService('metrics');

  strapi.db.lifecycles.subscribe({
    models: ['admin::user'],
    afterCreate: sendDidChangeInterfaceLanguage,
    afterDelete: sendDidChangeInterfaceLanguage,
    afterUpdate({ params }) {
      if (params.data.preferedLanguage) {
        sendDidChangeInterfaceLanguage();
      }
    },
  });
};

const syncAuthSettings = async () => {
  const adminStore = await strapi.store({ type: 'core', name: 'admin' });
  const adminAuthSettings = await adminStore.get({ key: 'auth' });
  const newAuthSettings = merge(defaultAdminAuthSettings, adminAuthSettings);

  const roleExists = await getService('role').exists({
    id: newAuthSettings.providers.defaultRole,
  });

  // Reset the default SSO role if it has been deleted manually
  if (!roleExists) {
    newAuthSettings.providers.defaultRole = null;
  }

  await adminStore.set({ key: 'auth', value: newAuthSettings });
};

module.exports = async () => {
  await registerAdminConditions();
  await registerPermissionActions();
  registerModelHooks();

  const permissionService = getService('permission');
  const userService = getService('user');
  const roleService = getService('role');
  const apiTokenService = getService('api-token');
  const tokenService = getService('token');

  await roleService.createRolesIfNoneExist();
  await roleService.resetSuperAdminPermissions();
  await roleService.displayWarningIfNoSuperAdmin();

  await permissionService.ensureBoundPermissionsInDatabase();
  await permissionService.cleanPermissionsInDatabase();

  await userService.displayWarningIfUsersDontHaveRole();

  await syncAuthSettings();

  apiTokenService.checkSaltIsDefined();
  tokenService.checkSecretIsDefined();
};
