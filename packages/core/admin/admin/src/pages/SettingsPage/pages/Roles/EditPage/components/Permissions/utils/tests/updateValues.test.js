import updateValues from '../updateValues';

describe('ADMIN | COMPONENTS | Permissions | utils | updateValues', () => {
  it('should not the conditions values of given object', () => {
    const simpleObject = {
      properties: {
        enabled: true,
      },
      conditions: 'test',
    };
    const expected = {
      properties: {
        enabled: false,
      },
      conditions: 'test',
    };

    expect(updateValues(simpleObject, false)).toEqual(expected);
  });

  it('set the leafs of an object with the second argument passed to the function', () => {
    const complexeObject = {
      conditions: 'test',
      properties: {
        enabled: true,
        f1: {
          enabled: true,
          f1: {
            conditions: 'test',
            enabled: false,
            f2: {
              enabled: true,
            },
          },
        },
      },
    };
    const expected = {
      conditions: 'test',
      properties: {
        enabled: false,
        f1: {
          enabled: false,
          f1: {
            conditions: 'test',
            enabled: false,
            f2: {
              enabled: false,
            },
          },
        },
      },
    };

    expect(updateValues(complexeObject, false)).toEqual(expected);
  });
});
