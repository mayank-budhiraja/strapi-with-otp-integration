'use strict';

const { prop, pick } = require('lodash/fp');
const { MANY_RELATIONS } = require('@strapi/utils').relations.constants;
const { setCreatorFields, pipeAsync } = require('@strapi/utils');

const { getService, pickWritableAttributes } = require('../utils');
const { validateBulkDeleteInput, validatePagination } = require('./validation');

module.exports = {
  async find(ctx) {
    const { userAbility } = ctx.state;
    const { model } = ctx.params;
    const { query } = ctx.request;

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.read()) {
      return ctx.forbidden();
    }

    const permissionQuery = permissionChecker.buildReadQuery(query);

    const { results, pagination } = await entityManager.findWithRelationCounts(
      permissionQuery,
      model
    );

    const sanitizedResults = await Promise.all(
      results.map(result => permissionChecker.sanitizeOutput(result))
    );

    ctx.body = {
      results: sanitizedResults,
      pagination,
    };
  },

  async findOne(ctx) {
    const { userAbility } = ctx.state;
    const { model, id } = ctx.params;

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.read()) {
      return ctx.forbidden();
    }

    const entity = await entityManager.findOneWithCreatorRoles(id, model);

    if (!entity) {
      return ctx.notFound();
    }

    if (permissionChecker.cannot.read(entity)) {
      return ctx.forbidden();
    }

    ctx.body = await permissionChecker.sanitizeOutput(entity);
  },

  async create(ctx) {
    const { userAbility, user } = ctx.state;
    const { model } = ctx.params;
    const { body } = ctx.request;

    const totalEntries = await strapi.query(model).count();

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.create()) {
      return ctx.forbidden();
    }

    const pickWritables = pickWritableAttributes({ model });
    const pickPermittedFields = permissionChecker.sanitizeCreateInput;
    const setCreator = setCreatorFields({ user });

    const sanitizeFn = pipeAsync(pickWritables, pickPermittedFields, setCreator);

    const sanitizedBody = await sanitizeFn(body);
    const entity = await entityManager.create(sanitizedBody, model);

    ctx.body = await permissionChecker.sanitizeOutput(entity);

    if (totalEntries === 0) {
      strapi.telemetry.send('didCreateFirstContentTypeEntry', { model });
    }
  },

  async update(ctx) {
    const { userAbility, user } = ctx.state;
    const { id, model } = ctx.params;
    const { body } = ctx.request;

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.update()) {
      return ctx.forbidden();
    }

    const entity = await entityManager.findOneWithCreatorRoles(id, model);

    if (!entity) {
      return ctx.notFound();
    }

    if (permissionChecker.cannot.update(entity)) {
      return ctx.forbidden();
    }

    const pickWritables = pickWritableAttributes({ model });
    const pickPermittedFields = permissionChecker.sanitizeUpdateInput(entity);
    const setCreator = setCreatorFields({ user, isEdition: true });

    const sanitizeFn = pipeAsync(pickWritables, pickPermittedFields, setCreator);

    const sanitizedBody = await sanitizeFn(body);
    const updatedEntity = await entityManager.update(entity, sanitizedBody, model);

    ctx.body = await permissionChecker.sanitizeOutput(updatedEntity);
  },

  async delete(ctx) {
    const { userAbility } = ctx.state;
    const { id, model } = ctx.params;

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.delete()) {
      return ctx.forbidden();
    }

    const entity = await entityManager.findOneWithCreatorRoles(id, model);

    if (!entity) {
      return ctx.notFound();
    }

    if (permissionChecker.cannot.delete(entity)) {
      return ctx.forbidden();
    }

    const result = await entityManager.delete(entity, model);

    ctx.body = await permissionChecker.sanitizeOutput(result);
  },

  async publish(ctx) {
    const { userAbility, user } = ctx.state;
    const { id, model } = ctx.params;

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.publish()) {
      return ctx.forbidden();
    }

    const entity = await entityManager.findOneWithCreatorRoles(id, model);

    if (!entity) {
      return ctx.notFound();
    }

    if (permissionChecker.cannot.publish(entity)) {
      return ctx.forbidden();
    }

    const result = await entityManager.publish(
      entity,
      setCreatorFields({ user, isEdition: true })({}),
      model
    );

    ctx.body = await permissionChecker.sanitizeOutput(result);
  },

  async unpublish(ctx) {
    const { userAbility, user } = ctx.state;
    const { id, model } = ctx.params;

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.unpublish()) {
      return ctx.forbidden();
    }

    const entity = await entityManager.findOneWithCreatorRoles(id, model);

    if (!entity) {
      return ctx.notFound();
    }

    if (permissionChecker.cannot.unpublish(entity)) {
      return ctx.forbidden();
    }

    const result = await entityManager.unpublish(
      entity,
      setCreatorFields({ user, isEdition: true })({}),
      model
    );

    ctx.body = await permissionChecker.sanitizeOutput(result);
  },

  async bulkDelete(ctx) {
    const { userAbility } = ctx.state;
    const { model } = ctx.params;
    const { query, body } = ctx.request;
    const { ids } = body;

    await validateBulkDeleteInput(body);

    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.delete()) {
      return ctx.forbidden();
    }

    // TODO: fix
    const permissionQuery = permissionChecker.buildDeleteQuery(query);

    const idsWhereClause = { id: { $in: ids } };
    const params = {
      ...permissionQuery,
      filters: {
        $and: [idsWhereClause].concat(permissionQuery.filters || []),
      },
    };

    const { count } = await entityManager.deleteMany(params, model);

    ctx.body = { count };
  },

  async previewManyRelations(ctx) {
    const { userAbility } = ctx.state;
    const { model, id, targetField } = ctx.params;
    const { pageSize = 10, page = 1 } = ctx.request.query;

    validatePagination({ page, pageSize });

    const contentTypeService = getService('content-types');
    const entityManager = getService('entity-manager');
    const permissionChecker = getService('permission-checker').create({ userAbility, model });

    if (permissionChecker.cannot.read()) {
      return ctx.forbidden();
    }

    const modelDef = strapi.getModel(model);
    const assoc = modelDef.attributes[targetField];

    if (!assoc || !MANY_RELATIONS.includes(assoc.relation)) {
      return ctx.badRequest('Invalid target field');
    }

    const entity = await entityManager.findOneWithCreatorRoles(id, model);

    if (!entity) {
      return ctx.notFound();
    }

    if (permissionChecker.cannot.read(entity, targetField)) {
      return ctx.forbidden();
    }

    let relationList;
    // FIXME: load relations using query.load
    if (!assoc.inversedBy && !assoc.mappedBy) {
      const populatedEntity = await entityManager.findOne(id, model, [targetField]);
      const relationsListIds = populatedEntity[targetField].map(prop('id'));

      relationList = await entityManager.findPage(
        {
          page,
          pageSize,
          filters: {
            id: relationsListIds,
          },
        },
        assoc.target
      );
    } else {
      relationList = await entityManager.findPage(
        {
          page,
          pageSize,
          filters: {
            [assoc.inversedBy || assoc.mappedBy]: entity.id,
          },
        },
        assoc.target
      );
    }

    const config = await contentTypeService.findConfiguration({ uid: model });
    const mainField = prop(['metadatas', targetField, 'edit', 'mainField'], config);

    ctx.body = {
      pagination: relationList.pagination,
      results: relationList.results.map(pick(['id', mainField])),
    };
  },
};
