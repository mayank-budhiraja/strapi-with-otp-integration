import { renderHook } from '@testing-library/react-hooks';
import { useTrackUsage } from '..';

const trackUsageMock = jest.fn();

jest.mock('@strapi/helper-plugin', () => ({
  useTracking: jest.fn(() => ({ trackUsage: trackUsageMock })),
}));

describe('Admin | pages | Admin | useTrackUsage', () => {
  it('should call the trackUsage method on mount with didAccessAuthenticatedAdministration', () => {
    const { rerender } = renderHook(() => useTrackUsage());
    rerender();

    expect(trackUsageMock).toHaveBeenCalledTimes(1);
    expect(trackUsageMock).toHaveBeenCalledWith('didAccessAuthenticatedAdministration');
  });
});
