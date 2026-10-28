import React from 'react';
import { BrandLogo } from '../branding/BrandLogo';

export const Footer = () => {
  return (
    <footer className="mt-12 py-6 px-6 border-t border-slate-800/80 bg-[#070a12] text-xs text-slate-400">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 max-w-7xl mx-auto">
        <div className="flex items-center gap-2 font-mono">
          <BrandLogo className="w-5 h-5" />
          <span>CloudVuln Platform v1.0.0</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400 flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" /> Security Engine Active
          </span>
        </div>
        <div className="text-slate-500 font-mono text-[11px]">
          © 2026 CloudVuln Security Inc. All rights reserved.
        </div>
      </div>
    </footer>
  );
};
