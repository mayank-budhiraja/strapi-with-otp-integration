import React from 'react';
import { ThemeProvider, lightTheme } from '@strapi/design-system';
import { render as renderTL } from '@testing-library/react';
import { DocAssetCard } from '../DocAssetCard';
import en from '../../../translations/en.json';

jest.mock('../../../utils', () => ({
  ...jest.requireActual('../../../utils'),
  getTrad: x => x,
}));

jest.mock('react-intl', () => ({
  useIntl: () => ({ formatMessage: jest.fn(({ id }) => en[id]) }),
}));

describe('DocAssetCard', () => {
  it('snapshots the component', () => {
    const { container } = renderTL(
      <ThemeProvider theme={lightTheme}>
        <DocAssetCard
          name="hello.png"
          extension="png"
          selected={false}
          onSelect={jest.fn()}
          onEdit={jest.fn()}
          size="S"
        />
      </ThemeProvider>
    );

    expect(container).toMatchInlineSnapshot(`
      .c28 {
        border: 0;
        -webkit-clip: rect(0 0 0 0);
        clip: rect(0 0 0 0);
        height: 1px;
        margin: -1px;
        overflow: hidden;
        padding: 0;
        position: absolute;
        width: 1px;
      }

      .c0 {
        background: #ffffff;
        border-radius: 4px;
        box-shadow: 0px 1px 4px rgba(33,33,52,0.1);
      }

      .c3 {
        position: start;
      }

      .c8 {
        position: end;
      }

      .c16 {
        padding-top: 8px;
        padding-right: 12px;
        padding-bottom: 8px;
        padding-left: 12px;
      }

      .c24 {
        background: #f6f6f9;
        padding: 4px;
        border-radius: 4px;
        min-width: 20px;
      }

      .c1 {
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-flex-direction: row;
        -ms-flex-direction: row;
        flex-direction: row;
        -webkit-box-pack: center;
        -webkit-justify-content: center;
        -ms-flex-pack: center;
        justify-content: center;
      }

      .c4 {
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-flex-direction: row;
        -ms-flex-direction: row;
        flex-direction: row;
      }

      .c17 {
        -webkit-align-items: flex-start;
        -webkit-box-align: flex-start;
        -ms-flex-align: flex-start;
        align-items: flex-start;
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-flex-direction: row;
        -ms-flex-direction: row;
        flex-direction: row;
      }

      .c25 {
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        display: -webkit-inline-box;
        display: -webkit-inline-flex;
        display: -ms-inline-flexbox;
        display: inline-flex;
        -webkit-flex-direction: row;
        -ms-flex-direction: row;
        flex-direction: row;
        -webkit-box-pack: center;
        -webkit-justify-content: center;
        -ms-flex-pack: center;
        justify-content: center;
      }

      .c5 > * {
        margin-left: 0;
        margin-right: 0;
      }

      .c5 > * + * {
        margin-left: 8px;
      }

      .c6 {
        position: absolute;
        top: 12px;
        left: 12px;
      }

      .c9 {
        position: absolute;
        top: 12px;
        right: 12px;
      }

      .c20 {
        font-weight: 600;
        color: #32324d;
        font-size: 0.75rem;
        line-height: 1.33;
      }

      .c21 {
        color: #666687;
        font-size: 0.75rem;
        line-height: 1.33;
      }

      .c27 {
        color: #666687;
        font-weight: 600;
        font-size: 0.6875rem;
        line-height: 1.45;
        text-transform: uppercase;
      }

      .c23 {
        margin-left: auto;
        -webkit-flex-shrink: 0;
        -ms-flex-negative: 0;
        flex-shrink: 0;
      }

      .c26 {
        margin-left: 4px;
      }

      .c7 {
        margin: 0;
        height: 18px;
        min-width: 18px;
        border-radius: 4px;
        border: 1px solid #c0c0cf;
        -webkit-appearance: none;
        background-color: #ffffff;
        cursor: pointer;
      }

      .c7:checked {
        background-color: #4945ff;
        border: 1px solid #4945ff;
      }

      .c7:checked:after {
        content: '';
        display: block;
        position: relative;
        background: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iOCIgdmlld0JveD0iMCAwIDEwIDgiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPHBhdGgKICAgIGQ9Ik04LjU1MzIzIDAuMzk2OTczQzguNjMxMzUgMC4zMTYzNTUgOC43NjA1MSAwLjMxNTgxMSA4LjgzOTMxIDAuMzk1NzY4TDkuODYyNTYgMS40MzQwN0M5LjkzODkzIDEuNTExNTcgOS45MzkzNSAxLjYzNTkgOS44NjM0OSAxLjcxMzlMNC4wNjQwMSA3LjY3NzI0QzMuOTg1OSA3Ljc1NzU1IDMuODU3MDcgNy43NTgwNSAzLjc3ODM0IDcuNjc4MzRMMC4xMzg2NiAzLjk5MzMzQzAuMDYxNzc5OCAzLjkxNTQ5IDAuMDYxNzEwMiAzLjc5MDMyIDAuMTM4NTA0IDMuNzEyNEwxLjE2MjEzIDIuNjczNzJDMS4yNDAzOCAyLjU5NDMyIDEuMzY4NDMgMi41OTQyMiAxLjQ0NjggMi42NzM0OEwzLjkyMTc0IDUuMTc2NDdMOC41NTMyMyAwLjM5Njk3M1oiCiAgICBmaWxsPSJ3aGl0ZSIKICAvPgo8L3N2Zz4=) no-repeat no-repeat center center;
        width: 10px;
        height: 10px;
        left: 50%;
        top: 50%;
        -webkit-transform: translateX(-50%) translateY(-50%);
        -ms-transform: translateX(-50%) translateY(-50%);
        transform: translateX(-50%) translateY(-50%);
      }

      .c7:checked:disabled:after {
        background: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iOCIgdmlld0JveD0iMCAwIDEwIDgiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPHBhdGgKICAgIGQ9Ik04LjU1MzIzIDAuMzk2OTczQzguNjMxMzUgMC4zMTYzNTUgOC43NjA1MSAwLjMxNTgxMSA4LjgzOTMxIDAuMzk1NzY4TDkuODYyNTYgMS40MzQwN0M5LjkzODkzIDEuNTExNTcgOS45MzkzNSAxLjYzNTkgOS44NjM0OSAxLjcxMzlMNC4wNjQwMSA3LjY3NzI0QzMuOTg1OSA3Ljc1NzU1IDMuODU3MDcgNy43NTgwNSAzLjc3ODM0IDcuNjc4MzRMMC4xMzg2NiAzLjk5MzMzQzAuMDYxNzc5OCAzLjkxNTQ5IDAuMDYxNzEwMiAzLjc5MDMyIDAuMTM4NTA0IDMuNzEyNEwxLjE2MjEzIDIuNjczNzJDMS4yNDAzOCAyLjU5NDMyIDEuMzY4NDMgMi41OTQyMiAxLjQ0NjggMi42NzM0OEwzLjkyMTc0IDUuMTc2NDdMOC41NTMyMyAwLjM5Njk3M1oiCiAgICBmaWxsPSIjOEU4RUE5IgogIC8+Cjwvc3ZnPg==) no-repeat no-repeat center center;
      }

      .c7:disabled {
        background-color: #dcdce4;
        border: 1px solid #c0c0cf;
      }

      .c7:indeterminate {
        background-color: #4945ff;
        border: 1px solid #4945ff;
      }

      .c7:indeterminate:after {
        content: '';
        display: block;
        position: relative;
        color: white;
        height: 2px;
        width: 10px;
        background-color: #ffffff;
        left: 50%;
        top: 50%;
        -webkit-transform: translateX(-50%) translateY(-50%);
        -ms-transform: translateX(-50%) translateY(-50%);
        transform: translateX(-50%) translateY(-50%);
      }

      .c7:indeterminate:disabled {
        background-color: #dcdce4;
        border: 1px solid #c0c0cf;
      }

      .c7:indeterminate:disabled:after {
        background-color: #8e8ea9;
      }

      .c18 {
        word-break: break-all;
      }

      .c2 {
        position: relative;
        border-bottom: 1px solid #eaeaef;
      }

      .c19 {
        padding-top: 4px;
      }

      .c12 {
        width: 100%;
        height: 5.5rem;
      }

      .c13 {
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-flex-direction: row;
        -ms-flex-direction: row;
        flex-direction: row;
        -webkit-box-pack: center;
        -webkit-justify-content: center;
        -ms-flex-pack: center;
        justify-content: center;
      }

      .c10 {
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        cursor: pointer;
        padding: 8px;
        border-radius: 4px;
        background: #ffffff;
        border: 1px solid #dcdce4;
        position: relative;
        outline: none;
      }

      .c10 svg {
        height: 12px;
        width: 12px;
      }

      .c10 svg > g,
      .c10 svg path {
        fill: #ffffff;
      }

      .c10[aria-disabled='true'] {
        pointer-events: none;
      }

      .c10:after {
        -webkit-transition-property: all;
        transition-property: all;
        -webkit-transition-duration: 0.2s;
        transition-duration: 0.2s;
        border-radius: 8px;
        content: '';
        position: absolute;
        top: -4px;
        bottom: -4px;
        left: -4px;
        right: -4px;
        border: 2px solid transparent;
      }

      .c10:focus-visible {
        outline: none;
      }

      .c10:focus-visible:after {
        border-radius: 8px;
        content: '';
        position: absolute;
        top: -5px;
        bottom: -5px;
        left: -5px;
        right: -5px;
        border: 2px solid #4945ff;
      }

      .c11 {
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        -webkit-box-pack: center;
        -webkit-justify-content: center;
        -ms-flex-pack: center;
        justify-content: center;
        height: 2rem;
        width: 2rem;
      }

      .c11 svg > g,
      .c11 svg path {
        fill: #8e8ea9;
      }

      .c11:hover svg > g,
      .c11:hover svg path {
        fill: #666687;
      }

      .c11:active svg > g,
      .c11:active svg path {
        fill: #a5a5ba;
      }

      .c11[aria-disabled='true'] {
        background-color: #eaeaef;
      }

      .c11[aria-disabled='true'] svg path {
        fill: #666687;
      }

      .c22 {
        text-transform: uppercase;
      }

      .c15 svg {
        font-size: 3rem;
      }

      .c14 {
        border-radius: 4px 4px 0 0;
        background: linear-gradient(180deg,#ffffff 0%,#f6f6f9 121.48%);
      }

      <div>
        <article
          aria-labelledby="card-1-title"
          class="c0"
          tabindex="0"
        >
          <div
            class="c1 c2"
          >
            <div
              class="c3 c4 c5 c6"
              spacing="2"
            >
              <input
                aria-labelledby="card-1-title"
                class="c7"
                type="checkbox"
              />
            </div>
            <div
              class="c8 c4 c5 c9"
              spacing="2"
            >
              <span>
                <button
                  aria-disabled="false"
                  aria-labelledby="tooltip-1"
                  class="c10 c11"
                  tabindex="0"
                  type="button"
                >
                  <svg
                    fill="none"
                    height="1em"
                    viewBox="0 0 24 24"
                    width="1em"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      clip-rule="evenodd"
                      d="M23.604 3.514c.528.528.528 1.36 0 1.887l-2.622 2.607-4.99-4.99L18.6.396a1.322 1.322 0 011.887 0l3.118 3.118zM0 24v-4.99l14.2-14.2 4.99 4.99L4.99 24H0z"
                      fill="#212134"
                      fill-rule="evenodd"
                    />
                  </svg>
                </button>
              </span>
            </div>
            <div
              class="c12 c13 c14"
              height="5.5rem"
              width="100%"
            >
              <span
                class="c15"
              >
                <svg
                  aria-label="hello.png"
                  fill="none"
                  height="1em"
                  viewBox="0 0 24 33"
                  width="1em"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    clip-rule="evenodd"
                    d="M16.39.749l6.915 7.377A2.59 2.59 0 0124 9.877v19.638c0 1.381-1.042 2.493-2.337 2.493H2.337C1.042 32.008 0 30.896 0 29.515V2.5C0 1.827.253 1.22.695.75 1.137.277 1.705.008 2.337.008h12.41c.6 0 1.2.27 1.643.74zm.473 7.983h5.116L15.82 2.197V7.62c0 .607.474 1.112 1.042 1.112zM2.337 30.559h19.326c.537 0 .98-.471.98-1.044V10.18h-5.78c-1.326 0-2.4-1.145-2.4-2.56V1.456H2.337a.949.949 0 00-.695.303c-.19.203-.284.472-.284.741v27.015c0 .573.442 1.044.979 1.044zm3.358-5.248h12.442c.379 0 .695.326.726.718 0 .392-.316.718-.694.718H5.695c-.38 0-.695-.326-.695-.718 0-.392.316-.718.695-.718zm12.442-5.287H5.695c-.38 0-.695.327-.695.718 0 .392.316.718.695.718h12.474c.378 0 .694-.326.694-.718 0-.391-.347-.718-.726-.718zM5.695 14.738h12.442c.379 0 .726.326.726.718 0 .391-.316.718-.694.718H5.695c-.38 0-.695-.327-.695-.718 0-.392.316-.718.695-.718z"
                    fill="#C0C0CF"
                    fill-rule="evenodd"
                  />
                </svg>
              </span>
            </div>
          </div>
          <div
            class="c16"
          >
            <div
              class="c17"
            >
              <div
                class="c18"
              >
                <div
                  class="c19"
                >
                  <h2
                    class="c20"
                    id="card-1-title"
                  >
                    hello.png
                  </h2>
                </div>
                <div
                  class="c21"
                >
                  <span
                    class="c22"
                  >
                    png
                  </span>
                </div>
              </div>
              <div
                class="c23"
              >
                <div
                  class="c24 c25 c26"
                >
                  <span
                    class="c27"
                  >
                    Doc
                  </span>
                </div>
              </div>
            </div>
          </div>
        </article>
        <div
          class="c28"
        >
          <p
            aria-live="polite"
            aria-relevant="all"
            id="live-region-log"
            role="log"
          />
          <p
            aria-live="polite"
            aria-relevant="all"
            id="live-region-status"
            role="status"
          />
          <p
            aria-live="assertive"
            aria-relevant="all"
            id="live-region-alert"
            role="alert"
          />
        </div>
      </div>
    `);
  });
});
