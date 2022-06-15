import React from 'react';
import { ThemeProvider, lightTheme } from '@strapi/design-system';
import { render as renderTL } from '@testing-library/react';
import { FromComputerForm } from '../FromComputerForm';
import en from '../../../../translations/en.json';

jest.mock('../../../../utils/getTrad', () => x => x);

jest.mock('react-intl', () => ({
  useIntl: () => ({ formatMessage: jest.fn(({ id }) => en[id] || 'App level translation') }),
}));

describe('FromComputerForm', () => {
  it('snapshots the component', async () => {
    const { container } = renderTL(
      <ThemeProvider theme={lightTheme}>
        <FromComputerForm onClose={jest.fn()} onAddAssets={jest.fn()} />
      </ThemeProvider>
    );

    expect(container).toMatchInlineSnapshot(`
      .c22 {
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
        padding-top: 24px;
        padding-right: 40px;
        padding-bottom: 24px;
        padding-left: 40px;
      }

      .c1 {
        background: #f6f6f9;
        padding-top: 64px;
        padding-bottom: 64px;
        border-radius: 4px;
        border-color: #c0c0cf;
        border: 1px solid #c0c0cf;
        position: relative;
      }

      .c7 {
        padding-top: 12px;
        padding-bottom: 20px;
      }

      .c9 {
        position: absolute;
        left: 0px;
        right: 0px;
        top: 0px;
        bottom: 0px;
        z-index: 1;
        width: 100%;
      }

      .c11 {
        position: relative;
      }

      .c3 {
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

      .c8 {
        color: #666687;
        font-weight: 500;
        font-size: 1rem;
        line-height: 1.25;
      }

      .c15 {
        font-weight: 600;
        color: #32324d;
        font-size: 0.75rem;
        line-height: 1.33;
      }

      .c12 {
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

      .c12 svg {
        height: 12px;
        width: 12px;
      }

      .c12 svg > g,
      .c12 svg path {
        fill: #ffffff;
      }

      .c12[aria-disabled='true'] {
        pointer-events: none;
      }

      .c12:after {
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

      .c12:focus-visible {
        outline: none;
      }

      .c12:focus-visible:after {
        border-radius: 8px;
        content: '';
        position: absolute;
        top: -5px;
        bottom: -5px;
        left: -5px;
        right: -5px;
        border: 2px solid #4945ff;
      }

      .c13 {
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        padding: 8px 16px;
        background: #4945ff;
        border: 1px solid #4945ff;
      }

      .c13 .sc-gJbFto {
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
      }

      .c13 .c14 {
        color: #ffffff;
      }

      .c13[aria-disabled='true'] {
        border: 1px solid #dcdce4;
        background: #eaeaef;
      }

      .c13[aria-disabled='true'] .c14 {
        color: #666687;
      }

      .c13[aria-disabled='true'] svg > g,
      .c13[aria-disabled='true'] svg path {
        fill: #666687;
      }

      .c13[aria-disabled='true']:active {
        border: 1px solid #dcdce4;
        background: #eaeaef;
      }

      .c13[aria-disabled='true']:active .c14 {
        color: #666687;
      }

      .c13[aria-disabled='true']:active svg > g,
      .c13[aria-disabled='true']:active svg path {
        fill: #666687;
      }

      .c13:hover {
        border: 1px solid #7b79ff;
        background: #7b79ff;
      }

      .c13:active {
        border: 1px solid #4945ff;
        background: #4945ff;
      }

      .c13 svg > g,
      .c13 svg path {
        fill: #ffffff;
      }

      .c21 {
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
        padding: 8px 16px;
        background: #4945ff;
        border: 1px solid #4945ff;
        border: 1px solid #dcdce4;
        background: #ffffff;
      }

      .c21 .sc-gJbFto {
        display: -webkit-box;
        display: -webkit-flex;
        display: -ms-flexbox;
        display: flex;
        -webkit-align-items: center;
        -webkit-box-align: center;
        -ms-flex-align: center;
        align-items: center;
      }

      .c21 .c14 {
        color: #ffffff;
      }

      .c21[aria-disabled='true'] {
        border: 1px solid #dcdce4;
        background: #eaeaef;
      }

      .c21[aria-disabled='true'] .c14 {
        color: #666687;
      }

      .c21[aria-disabled='true'] svg > g,
      .c21[aria-disabled='true'] svg path {
        fill: #666687;
      }

      .c21[aria-disabled='true']:active {
        border: 1px solid #dcdce4;
        background: #eaeaef;
      }

      .c21[aria-disabled='true']:active .c14 {
        color: #666687;
      }

      .c21[aria-disabled='true']:active svg > g,
      .c21[aria-disabled='true']:active svg path {
        fill: #666687;
      }

      .c21:hover {
        background-color: #f6f6f9;
      }

      .c21:active {
        background-color: #eaeaef;
      }

      .c21 .c14 {
        color: #32324d;
      }

      .c21 svg > g,
      .c21 svg path {
        fill: #32324d;
      }

      .c16 {
        background: #f6f6f9;
        padding-top: 16px;
        padding-right: 20px;
        padding-bottom: 16px;
        padding-left: 20px;
      }

      .c18 {
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
        -webkit-box-pack: justify;
        -webkit-justify-content: space-between;
        -ms-flex-pack: justify;
        justify-content: space-between;
      }

      .c19 {
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
        border-radius: 0 0 4px 4px;
        border-top: 1px solid #eaeaef;
      }

      .c20 > * + * {
        margin-left: 8px;
      }

      .c5 {
        -webkit-flex-direction: column;
        -ms-flex-direction: column;
        flex-direction: column;
      }

      .c6 {
        font-size: 3.75rem;
      }

      .c6 svg path {
        fill: #4945ff;
      }

      .c2 {
        border-style: dashed;
      }

      .c10 {
        opacity: 0;
        cursor: pointer;
      }

      <div>
        <form>
          <div
            class="c0"
          >
            <label>
              <div
                class="c1 c2"
              >
                <div
                  class="c3"
                >
                  <div
                    class="c4 c5"
                  >
                    <div
                      class="c6"
                    >
                      <svg
                        aria-hidden="true"
                        fill="none"
                        height="1em"
                        viewBox="0 0 24 20"
                        width="1em"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          d="M21.569 2.398H7.829v1.586h13.74c.47 0 .826.5.826 1.094v9.853l-2.791-3.17a2.13 2.13 0 00-.74-.55 2.214 2.214 0 00-.912-.196 2.215 2.215 0 00-.912.191 2.131 2.131 0 00-.74.546l-2.93 3.385-2.973-3.36a2.147 2.147 0 00-.741-.545 2.228 2.228 0 00-1.824.007c-.286.13-.538.319-.739.553l-2.931 3.432V7.653H2.51v9.894c.023.153.06.304.108.452v.127l.041.095c.057.142.126.28.207.412l.099.15c.074.107.157.207.247.302l.124.119c.13.118.275.222.43.309h.024c.36.214.775.327 1.198.325h16.515c.36-.004.716-.085 1.039-.24.323-.153.606-.375.827-.648a2.78 2.78 0 00.504-.888c.066-.217.108-.44.124-.666V5.078a2.497 2.497 0 00-.652-1.81 2.706 2.706 0 00-1.776-.87z"
                          fill="#32324D"
                        />
                        <path
                          d="M12.552 9.199c.912 0 1.651-.71 1.651-1.585 0-.876-.74-1.586-1.651-1.586-.912 0-1.652.71-1.652 1.586 0 .875.74 1.585 1.652 1.585zM3.303 6.408h.826V3.997h2.477v-.793-.793H4.129V0h-.826c-.219 0-.85.002-.826 0v2.411H0v1.586h2.477v2.41h.826z"
                          fill="#32324D"
                        />
                      </svg>
                    </div>
                    <div
                      class="c7"
                    >
                      <span
                        class="c8"
                      >
                        Drag & Drop here or
                      </span>
                    </div>
                    <input
                      class="c9 c10"
                      multiple=""
                      name="files"
                      tabindex="-1"
                      type="file"
                      width="100%"
                    />
                    <div
                      class="c11"
                    >
                      <button
                        aria-disabled="false"
                        class="c12 c13"
                        type="button"
                      >
                        <span
                          class="c14 c15"
                        >
                          Browse files
                        </span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </label>
          </div>
          <div
            class="c16 c17"
          >
            <div
              class="c18"
            >
              <div
                class="c19 c20"
              >
                <button
                  aria-disabled="false"
                  class="c12 c21"
                  type="button"
                >
                  <span
                    class="c14 c15"
                  >
                    App level translation
                  </span>
                </button>
              </div>
              <div
                class="c19 c20"
              />
            </div>
          </div>
        </form>
        <div
          class="c22"
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
