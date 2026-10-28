import React from 'react';
import { AlertTriangle, RefreshCw, LogIn, Terminal } from 'lucide-react';
import { Button } from './Button';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    // If it's a dynamic import / chunk load failure from a new deployment, auto-recover by reloading
    const msg = error?.message || '';
    const isChunkFailure =
      msg.includes('Failed to fetch dynamically imported module') ||
      msg.includes('Importing a module script failed') ||
      msg.includes('Loading chunk') ||
      msg.includes('error loading dynamically imported module');

    if (isChunkFailure) {
      const hasReloaded = sessionStorage.getItem('cloudvuln_chunk_reloaded');
      if (!hasReloaded) {
        sessionStorage.setItem('cloudvuln_chunk_reloaded', '1');
        window.location.reload();
        return { hasError: false, error: null };
      }
    }

    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught an unhandled exception:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReload = () => {
    sessionStorage.removeItem('cloudvuln_chunk_reloaded');
    window.location.reload();
  };

  handleResetSession = () => {
    try {
      localStorage.removeItem('cloudvuln_access_token');
      localStorage.removeItem('cloudvuln_refresh_token');
      localStorage.removeItem('cloudvuln_demo');
      sessionStorage.clear();
    } catch {
      // ignore
    }
    window.location.href = '/login';
  };

  render() {
    if (this.state.hasError) {
      const errorMessage =
        this.state.error?.message || 'An unexpected runtime error caused the UI to unmount.';

      return (
        <div className="min-h-screen bg-[#090d16] text-slate-100 flex items-center justify-center p-6 cyber-bg-grid relative overflow-hidden">
          <div className="w-full max-w-lg p-8 rounded-2xl bg-[#0b101d] border border-rose-500/40 shadow-[0_0_50px_rgba(244,63,94,0.15)] space-y-6 relative z-10">
            <div className="flex items-center gap-3 pb-4 border-b border-slate-800">
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400">
                <AlertTriangle className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">Application Error Intercepted</h1>
                <p className="text-xs font-mono text-slate-400">SecOps Runtime Fault Protection</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              The application encountered an unexpected runtime state. Your session security tokens have been preserved. You can refresh the view or reset your session cache below.
            </p>

            <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 text-[11px] font-mono text-rose-300 break-all space-y-1">
              <div className="flex items-center gap-1.5 text-slate-500 font-semibold uppercase text-[10px]">
                <Terminal className="w-3.5 h-3.5" /> Exception Trace
              </div>
              <p>{errorMessage}</p>
            </div>

            <div className="flex flex-col sm:flex-row gap-3 pt-2">
              <Button
                variant="primary"
                icon={RefreshCw}
                className="flex-1 py-2.5"
                onClick={this.handleReload}
              >
                Reload Platform
              </Button>
              <Button
                variant="secondary"
                icon={LogIn}
                className="flex-1 py-2.5"
                onClick={this.handleResetSession}
              >
                Clear Cache &amp; Sign In
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
