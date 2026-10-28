import React from 'react';
import { BrandLogo } from '../components/branding/BrandLogo';
import { Loader } from '../components/ui/Loader';

export const LoadingScreen = ({ message = 'Initializing Cloud Security Engine...' }) => {
  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col items-center justify-center p-6 cyber-bg-grid relative overflow-hidden">
      <div className="absolute w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 flex flex-col items-center justify-center space-y-6 text-center">
        <div className="p-4 rounded-2xl bg-slate-900 border border-cyan-500/40 shadow-[0_0_30px_rgba(0,243,255,0.3)] text-cyan-400">
          <BrandLogo className="w-14 h-14 animate-cyber-pulse" />
        </div>

        <div>
          <h1 className="text-2xl font-black tracking-wider text-slate-100">
            CLOUD<span className="text-cyan-400">VULN</span>
          </h1>
          <p className="text-xs font-mono tracking-widest text-slate-400 uppercase mt-1">
            SecOps Control Platform
          </p>
        </div>

        <Loader size="lg" text={message} />
      </div>
    </div>
  );
};
