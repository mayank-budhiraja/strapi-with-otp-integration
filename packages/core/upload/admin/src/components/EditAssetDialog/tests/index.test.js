/**
 *
 * Tests for EditAssetDialog
 *
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider, lightTheme } from '@strapi/design-system';
import { IntlProvider } from 'react-intl';
import { QueryClient, QueryClientProvider } from 'react-query';
import { NotificationsProvider } from '@strapi/helper-plugin';
import { EditAssetDialog } from '../index';
import en from '../../../translations/en.json';
import { downloadFile } from '../../../utils/downloadFile';

jest.mock('../../../utils/downloadFile');

const messageForPlugin = Object.keys(en).reduce((acc, curr) => {
  acc[curr] = `upload.${en[curr]}`;

  return acc;
}, {});

const asset = {
  id: 8,
  name: 'Screenshot 2.png',
  alternativeText: null,
  caption: null,
  width: 1476,
  height: 780,
  formats: {
    thumbnail: {
      name: 'thumbnail_Screenshot 2.png',
      hash: 'thumbnail_Screenshot_2_5d4a574d61',
      ext: '.png',
      mime: 'image/png',
      width: 245,
      height: 129,
      size: 10.7,
      path: null,
      url: '/uploads/thumbnail_Screenshot_2_5d4a574d61.png',
    },
    large: {
      name: 'large_Screenshot 2.png',
      hash: 'large_Screenshot_2_5d4a574d61',
      ext: '.png',
      mime: 'image/png',
      width: 1000,
      height: 528,
      size: 97.1,
      path: null,
      url: '/uploads/large_Screenshot_2_5d4a574d61.png',
    },
    medium: {
      name: 'medium_Screenshot 2.png',
      hash: 'medium_Screenshot_2_5d4a574d61',
      ext: '.png',
      mime: 'image/png',
      width: 750,
      height: 396,
      size: 58.7,
      path: null,
      url: '/uploads/medium_Screenshot_2_5d4a574d61.png',
    },
    small: {
      name: 'small_Screenshot 2.png',
      hash: 'small_Screenshot_2_5d4a574d61',
      ext: '.png',
      mime: 'image/png',
      width: 500,
      height: 264,
      size: 31.06,
      path: null,
      url: '/uploads/small_Screenshot_2_5d4a574d61.png',
    },
  },
  hash: 'Screenshot_2_5d4a574d61',
  ext: '.png',
  mime: 'image/png',
  size: 102.01,
  url: '/uploads/Screenshot_2_5d4a574d61.png',
  previewUrl: null,
  provider: 'local',
  provider_metadata: null,
  createdAt: '2021-10-04T09:42:31.670Z',
  updatedAt: '2021-10-04T09:42:31.670Z',
};

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
    },
  },
});

const renderCompo = (toggleNotification = jest.fn()) =>
  render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={lightTheme}>
        <NotificationsProvider toggleNotification={toggleNotification}>
          <IntlProvider locale="en" messages={messageForPlugin} defaultLocale="en">
            <EditAssetDialog asset={asset} onClose={jest.fn()} canUpdate canCopyLink canDownload />
          </IntlProvider>
        </NotificationsProvider>
      </ThemeProvider>
    </QueryClientProvider>,
    { container: document.body }
  );

describe('<EditAssetDialog />', () => {
  const RealNow = Date.now;

  beforeAll(() => {
    global.Date.now = jest.fn(() => new Date('2021-09-20').getTime());
  });

  afterAll(() => {
    global.Date.now = RealNow;
  });

  it('renders and matches the snapshot', () => {
    const { container } = renderCompo();

    expect(container).toMatchSnapshot();
  });

  describe('PreviewBox', () => {
    it('opens the delete dialog when pressing the delete button', () => {
      renderCompo();

      fireEvent.click(screen.getByLabelText('Delete'));

      expect(screen.getByText('Confirmation')).toBeVisible();
      expect(screen.getByText('Are you sure you want to delete this?')).toBeVisible();
    });

    it('copies the link and shows a notification when pressing "Copy link"', () => {
      const toggleNotificationSpy = jest.fn();
      renderCompo(toggleNotificationSpy);

      fireEvent.click(screen.getByLabelText('Copy link'));

      expect(toggleNotificationSpy).toHaveBeenCalledWith({
        message: {
          defaultMessage: 'Link copied into the clipboard',
          id: 'notification.link-copied',
        },
        type: 'success',
      });
    });

    it('downloads the file when pressing "Download"', () => {
      renderCompo();

      fireEvent.click(screen.getByLabelText('Download'));
      expect(downloadFile).toHaveBeenCalledWith(
        'http://localhost:1337/uploads/Screenshot_2_5d4a574d61.png?updated_at=2021-10-04T09:42:31.670Z',
        'Screenshot 2.png'
      );
    });
  });
});
