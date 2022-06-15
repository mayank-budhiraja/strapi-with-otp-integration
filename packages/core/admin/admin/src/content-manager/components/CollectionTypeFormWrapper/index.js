import { memo, useCallback, useEffect, useMemo, useRef } from 'react';
import { useHistory } from 'react-router-dom';
import axios from 'axios';
import get from 'lodash/get';
import {
  useTracking,
  useNotification,
  useQueryParams,
  formatContentTypeData,
  contentManagementUtilRemoveFieldsFromData,
  useGuidedTour,
} from '@strapi/helper-plugin';
import { useSelector, useDispatch } from 'react-redux';
import PropTypes from 'prop-types';
import isEqual from 'react-fast-compare';
import { axiosInstance } from '../../../core/utils';
import {
  createDefaultForm,
  getTrad,
  getRequestUrl,
  removePasswordFieldsFromData,
} from '../../utils';
import { useFindRedirectionLink } from '../../hooks';
import {
  getData,
  getDataSucceeded,
  initForm,
  resetProps,
  setDataStructures,
  setStatus,
  submitSucceeded,
} from '../../sharedReducers/crudReducer/actions';
import selectCrudReducer from '../../sharedReducers/crudReducer/selectors';

// This container is used to handle the CRUD
const CollectionTypeFormWrapper = ({ allLayoutData, children, slug, id, origin }) => {
  const toggleNotification = useNotification();
  const { setCurrentStep } = useGuidedTour();
  const { trackUsage } = useTracking();
  const { push, replace } = useHistory();
  const [{ rawQuery }] = useQueryParams();
  const dispatch = useDispatch();
  const {
    componentsDataStructure,
    contentTypeDataStructure,
    data,
    isLoading,
    status,
  } = useSelector(selectCrudReducer);
  const redirectionLink = useFindRedirectionLink(slug);

  const isMounted = useRef(true);
  const trackUsageRef = useRef(trackUsage);

  const allLayoutDataRef = useRef(allLayoutData);

  const isCreatingEntry = id === null;

  const requestURL = useMemo(() => {
    if (isCreatingEntry && !origin) {
      return null;
    }

    return getRequestUrl(`collection-types/${slug}/${origin || id}`);
  }, [slug, id, isCreatingEntry, origin]);

  const cleanClonedData = useCallback(
    data => {
      if (!origin) {
        return data;
      }

      const cleaned = contentManagementUtilRemoveFieldsFromData(
        data,
        allLayoutDataRef.current.contentType,
        allLayoutDataRef.current.components
      );

      return cleaned;
    },
    [origin]
  );

  const cleanReceivedData = useCallback(data => {
    const cleaned = removePasswordFieldsFromData(
      data,
      allLayoutDataRef.current.contentType,
      allLayoutDataRef.current.components
    );

    return formatContentTypeData(
      cleaned,
      allLayoutDataRef.current.contentType,
      allLayoutDataRef.current.components
    );
  }, []);

  // SET THE DEFAULT LAYOUT the effect is applied when the slug changes
  useEffect(() => {
    const componentsDataStructure = Object.keys(allLayoutData.components).reduce((acc, current) => {
      const defaultComponentForm = createDefaultForm(
        get(allLayoutData, ['components', current, 'attributes'], {}),
        allLayoutData.components
      );

      acc[current] = formatContentTypeData(
        defaultComponentForm,
        allLayoutData.components[current],
        allLayoutData.components
      );

      return acc;
    }, {});

    const contentTypeDataStructure = createDefaultForm(
      allLayoutData.contentType.attributes,
      allLayoutData.components
    );

    const contentTypeDataStructureFormatted = formatContentTypeData(
      contentTypeDataStructure,
      allLayoutData.contentType,
      allLayoutData.components
    );

    dispatch(setDataStructures(componentsDataStructure, contentTypeDataStructureFormatted));
  }, [allLayoutData, dispatch]);

  useEffect(() => {
    return () => {
      dispatch(resetProps());
    };
  }, [dispatch]);

  useEffect(() => {
    const CancelToken = axios.CancelToken;
    const source = CancelToken.source();

    const fetchData = async source => {
      dispatch(getData());

      try {
        const { data } = await axiosInstance.get(requestURL, { cancelToken: source.token });

        dispatch(getDataSucceeded(cleanReceivedData(cleanClonedData(data))));
      } catch (err) {
        if (axios.isCancel(err)) {
          return;
        }

        console.error(err);

        const resStatus = get(err, 'response.status', null);

        if (resStatus === 404) {
          push(redirectionLink);

          return;
        }

        // Not allowed to read a document
        if (resStatus === 403) {
          toggleNotification({
            type: 'info',
            message: { id: getTrad('permissions.not-allowed.update') },
          });

          push(redirectionLink);
        }
      }
    };

    // This is needed in order to reset the form when the query changes
    const init = async () => {
      await dispatch(getData());
      await dispatch(initForm(rawQuery));
    };

    if (!isMounted.current) {
      return () => {};
    }

    if (requestURL) {
      fetchData(source);
    } else {
      init();
    }

    return () => {
      source.cancel('Operation canceled by the user.');
    };
  }, [
    cleanClonedData,
    cleanReceivedData,
    push,
    requestURL,
    dispatch,
    rawQuery,
    redirectionLink,
    toggleNotification,
  ]);

  const displayErrors = useCallback(
    err => {
      const errorPayload = err.response.data;
      let errorMessage = get(errorPayload, ['error', 'message'], 'Bad Request');

      // TODO handle errors correctly when back-end ready
      if (Array.isArray(errorMessage)) {
        errorMessage = get(errorMessage, ['0', 'messages', '0', 'id']);
      }

      if (typeof errorMessage === 'string') {
        toggleNotification({ type: 'warning', message: errorMessage });
      }
    },
    [toggleNotification]
  );

  const onDelete = useCallback(
    async trackerProperty => {
      try {
        trackUsageRef.current('willDeleteEntry', trackerProperty);

        const { data } = await axiosInstance.delete(
          getRequestUrl(`collection-types/${slug}/${id}`)
        );

        toggleNotification({
          type: 'success',
          message: { id: getTrad('success.record.delete') },
        });

        trackUsageRef.current('didDeleteEntry', trackerProperty);

        return Promise.resolve(data);
      } catch (err) {
        trackUsageRef.current('didNotDeleteEntry', { error: err, ...trackerProperty });

        return Promise.reject(err);
      }
    },
    [id, slug, toggleNotification]
  );

  const onDeleteSucceeded = useCallback(() => {
    replace(redirectionLink);
  }, [redirectionLink, replace]);

  const onPost = useCallback(
    async (body, trackerProperty) => {
      const endPoint = `${getRequestUrl(`collection-types/${slug}`)}${rawQuery}`;

      try {
        // Show a loading button in the EditView/Header.js && lock the app => no navigation
        dispatch(setStatus('submit-pending'));

        const { data } = await axiosInstance.post(endPoint, body);

        trackUsageRef.current('didCreateEntry', trackerProperty);
        toggleNotification({
          type: 'success',
          message: { id: getTrad('success.record.save') },
        });

        setCurrentStep('contentManager.success');

        dispatch(submitSucceeded(cleanReceivedData(data)));
        // Enable navigation and remove loaders
        dispatch(setStatus('resolved'));

        replace(`/content-manager/collectionType/${slug}/${data.id}${rawQuery}`);

        return Promise.resolve(data);
      } catch (err) {
        displayErrors(err);
        trackUsageRef.current('didNotCreateEntry', { error: err, trackerProperty });
        dispatch(setStatus('resolved'));

        return Promise.reject(err);
      }
    },
    [
      cleanReceivedData,
      displayErrors,
      replace,
      slug,
      dispatch,
      rawQuery,
      toggleNotification,
      setCurrentStep,
    ]
  );

  const onPublish = useCallback(async () => {
    try {
      trackUsageRef.current('willPublishEntry');
      const endPoint = getRequestUrl(`collection-types/${slug}/${id}/actions/publish`);

      dispatch(setStatus('publish-pending'));

      const { data } = await axiosInstance.post(endPoint);

      trackUsageRef.current('didPublishEntry');

      dispatch(submitSucceeded(cleanReceivedData(data)));
      dispatch(setStatus('resolved'));

      toggleNotification({
        type: 'success',
        message: { id: getTrad('success.record.publish') },
      });

      return Promise.resolve(data);
    } catch (err) {
      displayErrors(err);
      dispatch(setStatus('resolved'));

      return Promise.reject(err);
    }
  }, [cleanReceivedData, displayErrors, id, slug, dispatch, toggleNotification]);

  const onPut = useCallback(
    async (body, trackerProperty) => {
      const endPoint = getRequestUrl(`collection-types/${slug}/${id}`);

      try {
        trackUsageRef.current('willEditEntry', trackerProperty);

        dispatch(setStatus('submit-pending'));

        const { data } = await axiosInstance.put(endPoint, body);

        trackUsageRef.current('didEditEntry', { trackerProperty });
        toggleNotification({
          type: 'success',
          message: { id: getTrad('success.record.save') },
        });

        dispatch(submitSucceeded(cleanReceivedData(data)));

        dispatch(setStatus('resolved'));

        return Promise.resolve(data);
      } catch (err) {
        trackUsageRef.current('didNotEditEntry', { error: err, trackerProperty });
        displayErrors(err);

        dispatch(setStatus('resolved'));

        return Promise.reject(err);
      }
    },
    [cleanReceivedData, displayErrors, slug, id, dispatch, toggleNotification]
  );

  const onUnpublish = useCallback(async () => {
    const endPoint = getRequestUrl(`collection-types/${slug}/${id}/actions/unpublish`);

    dispatch(setStatus('unpublish-pending'));

    try {
      trackUsageRef.current('willUnpublishEntry');

      const { data } = await axiosInstance.post(endPoint);

      trackUsageRef.current('didUnpublishEntry');
      toggleNotification({
        type: 'success',
        message: { id: getTrad('success.record.unpublish') },
      });

      dispatch(submitSucceeded(cleanReceivedData(data)));
      dispatch(setStatus('resolved'));

      return Promise.resolve(data);
    } catch (err) {
      dispatch(setStatus('resolved'));
      displayErrors(err);

      return Promise.reject(err);
    }
  }, [cleanReceivedData, displayErrors, id, slug, dispatch, toggleNotification]);

  return children({
    componentsDataStructure,
    contentTypeDataStructure,
    data,
    isCreatingEntry,
    isLoadingForData: isLoading,
    onDelete,
    onDeleteSucceeded,
    onPost,
    onPublish,
    onPut,
    onUnpublish,
    status,
    redirectionLink,
  });
};

CollectionTypeFormWrapper.defaultProps = {
  id: null,
  origin: null,
};

CollectionTypeFormWrapper.propTypes = {
  allLayoutData: PropTypes.exact({
    components: PropTypes.object.isRequired,
    contentType: PropTypes.shape({
      apiID: PropTypes.string.isRequired,
      attributes: PropTypes.object.isRequired,
      info: PropTypes.object.isRequired,
      isDisplayed: PropTypes.bool.isRequired,
      kind: PropTypes.string.isRequired,
      layouts: PropTypes.object.isRequired,
      metadatas: PropTypes.object.isRequired,
      options: PropTypes.object.isRequired,
      pluginOptions: PropTypes.object,
      settings: PropTypes.object.isRequired,
      uid: PropTypes.string.isRequired,
    }).isRequired,
  }).isRequired,
  children: PropTypes.func.isRequired,
  id: PropTypes.string,
  origin: PropTypes.string,
  slug: PropTypes.string.isRequired,
};

export default memo(CollectionTypeFormWrapper, isEqual);
