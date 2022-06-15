import React, { useEffect, useReducer } from 'react';
import axios from 'axios';
import camelCase from 'lodash/camelCase';
import get from 'lodash/get';
import omit from 'lodash/omit';
import { Redirect, useRouteMatch, useHistory } from 'react-router-dom';
import { auth, useQuery, useGuidedTour, useTracking } from '@strapi/helper-plugin';
import PropTypes from 'prop-types';
import forms from 'ee_else_ce/pages/AuthPage/utils/forms';
import persistStateToLocaleStorage from '../../components/GuidedTour/utils/persistStateToLocaleStorage';
import useLocalesProvider from '../../components/LocalesProvider/useLocalesProvider';
import formatAPIErrors from '../../utils/formatAPIErrors';
import init from './init';
import { initialState, reducer } from './reducer';

const AuthPage = ({ hasAdmin, setHasAdmin }) => {
  const {
    push,
    location: { search },
  } = useHistory();
  const { changeLocale } = useLocalesProvider();
  const { setSkipped } = useGuidedTour();
  const { trackUsage } = useTracking();
  const {
    params: { authType },
  } = useRouteMatch('/auth/:authType');
  const query = useQuery();
  const { Component, endPoint, fieldsToDisable, fieldsToOmit, inputsPrefix, schema, ...rest } = get(
    forms,
    authType,
    {}
  );
  const [{ formErrors, modifiedData, requestError }, dispatch] = useReducer(
    reducer,
    initialState,
    init
  );
  const CancelToken = axios.CancelToken;
  const source = CancelToken.source();

  useEffect(() => {
    // Cancel request on unmount
    return () => {
      source.cancel('Component unmounted');
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Reset the state on navigation change
  useEffect(() => {
    dispatch({
      type: 'RESET_PROPS',
    });
  }, [authType]);

  const handleChange = ({ target: { name, value } }) => {
    dispatch({
      type: 'ON_CHANGE',
      keys: name,
      value,
    });
  };

  const handleSubmit = async (e, { setSubmitting, setErrors }) => {
    setSubmitting(true);
    const body = omit(e, fieldsToOmit);
    const requestURL = `/admin/${endPoint}`;

    if (authType === 'login') {
      await loginRequest(e, requestURL, { setSubmitting, setErrors });
    }

    if (authType === 'register' || authType === 'register-admin') {
      await registerRequest(e, requestURL, { setSubmitting, setErrors });
    }

    if (authType === 'forgot-password') {
      await forgotPasswordRequest(body, requestURL, { setSubmitting, setErrors });
    }

    if (authType === 'reset-password') {
      await resetPasswordRequest(body, requestURL, { setSubmitting, setErrors });
    }
  };

  const forgotPasswordRequest = async (body, requestURL, { setSubmitting, setErrors }) => {
    try {
      await axios({
        method: 'POST',
        url: `${strapi.backendURL}${requestURL}`,
        data: body,
        cancelToken: source.token,
      });

      push('/auth/forgot-password-success');
    } catch (err) {
      console.error(err);

      setErrors({ errorMessage: 'notification.error' });
    } finally {
      setSubmitting(false);
    }
  };

  const loginRequest = async (body, requestURL, { setSubmitting, setErrors }) => {
    try {
      const {
        data: {
          data: { token, user },
        },
      } = await axios({
        method: 'POST',
        url: `${strapi.backendURL}${requestURL}`,
        data: omit(body, fieldsToOmit),
        cancelToken: source.token,
      });

      if (user.preferedLanguage) {
        changeLocale(user.preferedLanguage);
      }

      auth.setToken(token, body.rememberMe);
      auth.setUserInfo(user, body.rememberMe);

      redirectToPreviousLocation();
    } catch (err) {
      if (err.response) {
        const errorMessage = get(
          err,
          ['response', 'data', 'error', 'message'],
          'Something went wrong'
        );

        if (camelCase(errorMessage).toLowerCase() === 'usernotactive') {
          push('/auth/oops');

          dispatch({
            type: 'RESET_PROPS',
          });

          return;
        }

        setErrors({ errorMessage });
      }
    } finally {
      setSubmitting(false);
    }
  };

  const registerRequest = async (body, requestURL, { setSubmitting, setErrors }) => {
    try {
      trackUsage('willCreateFirstAdmin');

      const {
        data: {
          data: { token, user },
        },
      } = await axios({
        method: 'POST',
        url: `${strapi.backendURL}${requestURL}`,
        data: omit(body, fieldsToOmit),
        cancelToken: source.token,
      });

      auth.setToken(token, false);
      auth.setUserInfo(user, false);

      setSubmitting(false);
      setHasAdmin(true);

      const { roles } = user;

      if (roles) {
        const isUserSuperAdmin = roles.find(({ code }) => code === 'strapi-super-admin');

        if (isUserSuperAdmin) {
          persistStateToLocaleStorage.setSkipped(false);
          setSkipped(false);
          trackUsage('didLaunchGuidedtour');
        }
      }

      if (
        (authType === 'register' && body.userInfo.news === true) ||
        (authType === 'register-admin' && body.news === true)
      ) {
        push({
          pathname: '/usecase',
          search: `?hasAdmin=${hasAdmin}`,
        });

        return;
      }

      redirectToPreviousLocation();
    } catch (err) {
      trackUsage('didNotCreateFirstAdmin');

      if (err.response) {
        const { data } = err.response;
        const apiErrors = formatAPIErrors(data);

        setErrors({ apiErrors });
      }
    }
  };

  const resetPasswordRequest = async (body, requestURL, { setErrors, setSubmitting }) => {
    try {
      const {
        data: {
          data: { token, user },
        },
      } = await axios({
        method: 'POST',
        url: `${strapi.backendURL}${requestURL}`,
        data: { ...body, resetPasswordToken: query.get('code') },
        cancelToken: source.token,
      });

      auth.setToken(token, false);
      auth.setUserInfo(user, false);

      // Redirect to the homePage
      push('/');
    } catch (err) {
      if (err.response) {
        const errorMessage = get(err, ['response', 'data', 'message'], 'Something went wrong');
        const errorStatus = get(err, ['response', 'data', 'statusCode'], 400);

        dispatch({
          type: 'SET_REQUEST_ERROR',
          errorMessage,
          errorStatus,
        });
        setErrors({ errorMessage });
      }
    } finally {
      setSubmitting(false);
    }
  };

  const redirectToPreviousLocation = () => {
    if (authType === 'login') {
      const redirectTo = query.get('redirectTo');
      const redirectUrl = redirectTo ? decodeURIComponent(redirectTo) : '/';

      push(redirectUrl);
    } else {
      push('/');
    }
  };

  // Redirect the user to the login page if
  // the endpoint does not exist or
  // there is already an admin user oo
  // the user is already logged in
  if (!forms[authType] || (hasAdmin && authType === 'register-admin') || auth.getToken()) {
    return <Redirect to="/" />;
  }

  // Redirect the user to the register-admin if it is the first user
  if (!hasAdmin && authType !== 'register-admin') {
    return (
      <Redirect
        to={{
          pathname: '/auth/register-admin',
          // Forward the `?redirectTo` from /auth/login
          // /abc => /auth/login?redirectTo=%2Fabc => /auth/register-admin?redirectTo=%2Fabc
          search,
        }}
      />
    );
  }

  return (
    <Component
      {...rest}
      authType={authType}
      fieldsToDisable={fieldsToDisable}
      formErrors={formErrors}
      inputsPrefix={inputsPrefix}
      modifiedData={modifiedData}
      onChange={handleChange}
      onSubmit={handleSubmit}
      requestError={requestError}
      schema={schema}
    />
  );
};

AuthPage.defaultProps = {
  hasAdmin: false,
};

AuthPage.propTypes = {
  hasAdmin: PropTypes.bool,
  setHasAdmin: PropTypes.func.isRequired,
};

export default AuthPage;
