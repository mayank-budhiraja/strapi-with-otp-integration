import init from '../init';

describe('CONTENT MANAGER | containers | EditSettingsView | init', () => {
  it('should return the correct initialState', () => {
    const initialState = { test: true };
    const mainLayout = { metadata: {}, layouts: { edit: [], list: ['test'] } };
    const expected = {
      test: true,
      initialData: { metadata: {}, layouts: { edit: [], list: ['test'] } },
      modifiedData: { metadata: {}, layouts: { edit: [], list: ['test'] } },
      componentLayouts: {},
    };

    const result = init(initialState, mainLayout, {});

    expect(result).toEqual(expected);
  });
});
