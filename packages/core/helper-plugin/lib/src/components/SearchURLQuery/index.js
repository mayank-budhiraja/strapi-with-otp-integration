import React, { useLayoutEffect, useState, useRef } from 'react';
import PropTypes from 'prop-types';
import { useIntl } from 'react-intl';
import SearchIcon from '@strapi/icons/Search';
import { Searchbar, SearchForm } from '@strapi/design-system/Searchbar';
import { IconButton } from '@strapi/design-system/IconButton';
import { Icon } from '@strapi/design-system/Icon';
import useQueryParams from '../../hooks/useQueryParams';
import useTracking from '../../hooks/useTracking';

const SearchURLQuery = ({ label, placeholder, trackedEvent }) => {
  const wrapperRef = useRef(null);
  const iconButtonRef = useRef(null);

  const [{ query }, setQuery] = useQueryParams();
  const [value, setValue] = useState(query?._q || '');
  const [isOpen, setIsOpen] = useState(!!value);
  const { formatMessage } = useIntl();
  const { trackUsage } = useTracking();

  const handleToggle = () => setIsOpen(prev => !prev);

  useLayoutEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        wrapperRef.current.querySelector('input').focus();
      }, 0);
    }
  }, [isOpen]);

  const handleClear = () => {
    setValue('');
    setQuery({ _q: '' }, 'remove');
  };

  const handleSubmit = e => {
    e.preventDefault();

    if (value) {
      if (trackedEvent) {
        trackUsage(trackedEvent);
      }
      setQuery({ _q: value, page: 1 });
    } else {
      handleToggle();
      setQuery({ _q: '' }, 'remove');
    }
  };

  if (isOpen) {
    return (
      <div ref={wrapperRef}>
        <SearchForm onSubmit={handleSubmit}>
          <Searchbar
            name="search"
            onChange={({ target: { value } }) => setValue(value)}
            value={value}
            clearLabel={formatMessage({ id: 'clearLabel', defaultMessage: 'Clear' })}
            onClear={handleClear}
            size="S"
            placeholder={placeholder}
          >
            {label}
          </Searchbar>
        </SearchForm>
      </div>
    );
  }

  return (
    <IconButton
      ref={iconButtonRef}
      icon={<Icon as={SearchIcon} color="neutral800" />}
      label="Search"
      onClick={handleToggle}
    />
  );
};

SearchURLQuery.defaultProps = {
  placeholder: undefined,
  trackedEvent: null,
};

SearchURLQuery.propTypes = {
  label: PropTypes.string.isRequired,
  placeholder: PropTypes.string,
  trackedEvent: PropTypes.string,
};

export default SearchURLQuery;
