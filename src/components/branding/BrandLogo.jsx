import React from 'react';

export const BrandLogo = ({ className = 'h-8 w-8' }) => (
  <img
    src="/assets/cloudvuln-logo.png"
    alt="CloudVuln cloud, shield, and padlock logo"
    className={`object-contain ${className}`}
    decoding="async"
  />
);
