import * as React from 'react';
import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@strapi/design-system/ThemeProvider';
import { lightTheme } from '@strapi/design-system/themes';
import DateTimePicker from '../index';

describe('DateTimePicker', () => {
  it('snapshots the component', () => {
    const { container } = render(
      <ThemeProvider theme={lightTheme}>
        <DateTimePicker
          value={new Date('2021-10-13T10:00:00.000Z')}
          onChange={() => {}}
          name="datetimepicker"
          label="Date time picker"
          hint="This is a super description"
        />
      </ThemeProvider>
    );

    expect(container.firstChild).toMatchSnapshot();
  });

  it('should initialize the two inputs', () => {
    render(
      <ThemeProvider theme={lightTheme}>
        <DateTimePicker
          value={new Date('2021-10-13T13:43:00.000Z')}
          step={15}
          onChange={() => {}}
          name="datetimepicker"
          label="Date time picker"
          hint="This is a super description"
        />
      </ThemeProvider>
    );

    expect(screen.getByText('13:45')).toBeInTheDocument();
    const datepicker = screen.getByTestId('datetimepicker-date');

    expect(datepicker.value).toBe('10/13/2021');
  });
});
