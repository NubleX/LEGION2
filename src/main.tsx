// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
// @ts-ignore: side-effect import of CSS without type declarations
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);