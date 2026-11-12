import React, { useState, useCallback } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { Mail, Key, ArrowRight, ShieldCheck, Lock } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Card, CardContent } from '../components/ui/Card';
import { GoogleIcon } from '../components/ui/GoogleIcon';
import { BrandLogo } from '../components/branding/BrandLogo';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../components/ui/Toast';

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export const LoginPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, loginWithGoogle } = useAuth();
  const { addToast } = useToast();

  const from = location.state?.from?.pathname || '/';

  const [form, setForm] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [serverError, setServerError] = useState('');

  const validate = useCallback(() => {
    const e = {};
    if (!form.email) e.email = 'Email is required';
    else if (!validateEmail(form.email)) e.email = 'Enter a valid email address';
    if (!form.password) e.password = 'Password is required';
    else if (form.password.length < 3) e.password = 'Password too short';
    return e;
  }, [form]);

  const handleChange = (field) => (e) => {
    setForm((prev) => ({ ...prev, [field]: e.target.value }));
    setErrors((prev) => ({ ...prev, [field]: '' }));
    setServerError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationErrors = validate();
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    setIsLoading(true);
    setServerError('');

    const result = await login(form.email, form.password);
    setIsLoading(false);

    if (result.success) {
      addToast(`Welcome back, ${result.user.full_name}`, 'success', { title: 'Authentication Successful' });
      navigate(from, { replace: true });
    } else {
      setServerError(result.error);
      addToast(result.error, 'error', { title: 'Login Failed' });
    }
  };

  const handleGoogleLogin = async () => {
    setIsGoogleLoading(true);
    setServerError('');
    const result = await loginWithGoogle();
    if (!result.success) {
      setIsGoogleLoading(false);
      setServerError(result.error);
      addToast(result.error, 'error', { title: 'Google Login Failed' });
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex items-center justify-center p-4 cyber-bg-grid relative overflow-hidden">
      {/* Background orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/8 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/8 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* Brand */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-slate-900 border border-cyan-500/40 shadow-[0_0_25px_rgba(0,243,255,0.25)] text-cyan-400">
            <BrandLogo className="w-12 h-12 animate-cyber-pulse" />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-wider text-slate-100">
              CLOUD<span className="text-cyan-400">VULN</span>
            </h1>
            <p className="text-xs font-mono tracking-widest text-slate-400 uppercase mt-1">
              CLOUD VULNERABILITY SCANNER &amp; REPORT GENERATOR
            </p>
          </div>
        </div>

        {/* Card */}
        <Card className="border-cyan-500/30 shadow-[0_0_50px_rgba(0,243,255,0.08)]">
          <CardContent className="p-8 space-y-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-cyan-400" /> LOGIN Authentication
              </span>
              <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" /> Secured
              </span>
            </div>

            {/* Server error */}
            {serverError && (
              <div
                role="alert"
                className="p-3 bg-rose-950/60 border border-rose-500/40 rounded-xl text-xs text-rose-300 flex items-center gap-2"
              >
                <span>⚠️</span> {serverError}
              </div>
            )}

            {/* Google OAuth Button */}
            <Button
              id="google-login-btn"
              type="button"
              variant="secondary"
              icon={GoogleIcon}
              className="w-full py-3 rounded-full bg-slate-800/80 hover:bg-slate-700/80 border-slate-700 text-slate-200"
              onClick={handleGoogleLogin}
              isLoading={isGoogleLoading}
            >
              Continue with Google
            </Button>

            <div className="relative flex items-center justify-center my-2">
              <div className="border-t border-slate-800 w-full"></div>
              <span className="bg-slate-900/90 px-3 text-[11px] font-mono text-slate-400 uppercase tracking-wider absolute">
                Or Continue With Email
              </span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              <Input
                id="login-email"
                label="Email Address"
                type="email"
                placeholder="operator@cloudvuln.io"
                icon={Mail}
                value={form.email}
                onChange={handleChange('email')}
                error={errors.email}
                required
                autoComplete="email"
              />

              <Input
                id="login-password"
                label="Password"
                type="password"
                placeholder="Enter your password"
                icon={Key}
                value={form.password}
                onChange={handleChange('password')}
                error={errors.password}
                required
                autoComplete="current-password"
              />

              <Button
                id="login-submit"
                type="submit"
                variant="primary"
                className="w-full py-3"
                isLoading={isLoading}
                iconRight={ArrowRight}
              >
                {isLoading ? 'Authenticating…' : 'Sign In'}
              </Button>
            </form>

            <div className="text-center pt-2 border-t border-slate-800 text-xs">
              <span className="text-slate-400">Need an account? </span>
              <Link to="/register" className="text-cyan-400 font-semibold hover:underline">
                Register
              </Link>
            </div>
          </CardContent>
        </Card>

        <p className="text-center text-[11px] text-slate-500 font-mono">
          Authorized personnel only. All access attempts are logged.
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
