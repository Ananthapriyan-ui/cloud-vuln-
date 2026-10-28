import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import { ErrorBoundary } from './components/ui/ErrorBoundary';
import './index.css';

// Automatically handle Vite chunk loading errors on new deployments
window.addEventListener('vite:preloadError', (event) => {
  console.warn('Vite preload error detected, auto-recovering...', event);
  const reloaded = sessionStorage.getItem('cloudvuln_chunk_reloaded');
  if (!reloaded) {
    sessionStorage.setItem('cloudvuln_chunk_reloaded', '1');
    window.location.reload();
  }
});

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);

