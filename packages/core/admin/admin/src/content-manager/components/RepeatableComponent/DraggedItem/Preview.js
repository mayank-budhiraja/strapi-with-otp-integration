import React from 'react';
import styled from 'styled-components';

const StyledSpan = styled.span`
  display: block;
  background-color: ${({ theme }) => theme.colors.primary100};
  outline: 1px dashed ${({ theme }) => theme.colors.primary500};
  outline-offset: -1px;
  padding: ${({ theme }) => theme.spaces[6]};
`;

const Preview = () => {
  return <StyledSpan padding={6} background="primary100" />;
};

export default Preview;
