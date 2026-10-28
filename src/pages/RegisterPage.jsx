import React, { useState, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, Mail, User, ShieldCheck, UserPlus } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Card, CardContent } from '../components/ui/Card';
import { GoogleIcon } from '../components/ui/GoogleIcon';
import { BrandLogo } from '../components/branding/BrandLogo';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../components/ui/Toast';

const PASSWORD_RULES = [
  { test: (p) => p.length >= 8,          label: 'At least 8 characters' },
  { test: (p) => /[A-Z]/.test(p),        label: 'One uppercase letter' },
  { test: (p) => /[0-9]/.test(p),        label: 'One number' },
];

function PasswordStrength({ password }) {
  if (!password) return null;
  const passed = PASSWORD_RULES.filter((r) => r.test(password)).length;
  const colors = ['bg-rose-500', 'bg-amber-500', 'bg-emerald-500'];
  const labels = ['Weak', 'Fair', 'Strong'];
  return (
    <div className="mt-1.5 space-y-1.5">
      <div className="flex gap-1">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full transition-colors duration-300 ${
              i < passed ? colors[passed - 1] : 'bg-slate-700'
            }`}
          />
        ))}
      </div>
      <div className="flex items-center justify-between">
        {passed > 0 && (
          <span className={`text-[10px] font-mono ${colors[passed - 1].replace('bg-', 'text-')}`}>
            {labels[passed - 1]}
          </span>
        )}
        <div className="flex gap-3">
          {PASSWORD_RULES.map((rule) => (
            <span
              key={rule.label}
              className={`text-[10px] font-mono flex items-center gap-1 ${
                rule.test(password) ? 'text-emerald-400' : 'text-slate-500'
              }`}
            >
              {rule.test(password) ? '✓' : '○'} {rule.label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

export const RegisterPage = () => {
  const navigate = useNavigate();
  const { register, loginWithGoogle } = useAuth();
  const { addToast } = useToast();

  const [form, setForm] = useState({
    fullName: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [serverError, setServerError] = useState('');

  const handleChange = (field) => (e) => {
    setForm((prev) => ({ ...prev, [field]: e.target.value }));
    setErrors((prev) => ({ ...prev, [field]: '' }));
    setServerError('');
  };

  const validate = useCallback(() => {
    const e = {};
    if (!form.fullName.trim()) e.fullName = 'Full name is required';
    else if (form.fullName.trim().length < 2) e.fullName = 'Name must be at least 2 characters';

    if (!form.email) e.email = 'Email is required';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = 'Enter a valid email';

    if (!form.password) e.password = 'Password is required';
    else {
      const failedRule = PASSWORD_RULES.find((r) => !r.test(form.password));
      if (failedRule) e.password = failedRule.label + ' required';
    }

    if (!form.confirmPassword) e.confirmPassword = 'Please confirm your password';
    else if (form.password !== form.confirmPassword) e.confirmPassword = 'Passwords do not match';

    return e;
  }, [form]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationErrors = validate();
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    setIsLoading(true);
    const result = await register(form.email, form.password, form.fullName);
    setIsLoading(false);

    if (result.success) {
      addToast(`Welcome, ${result.user.full_name}!`, 'success', { title: 'Account Created' });
      navigate('/');
    } else {
      setServerError(result.error);
      addToast(result.error, 'error', { title: 'Registration Failed' });
    }
  };

  const handleGoogleLogin = async () => {
    setIsGoogleLoading(true);
    setServerError('');
    const result = await loginWithGoogle();
    if (!result.success) {
      setIsGoogleLoading(false);
      setServerError(result.error);
      addToast(result.error, 'error', { title: 'Google Sign-Up Failed' });
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex items-center justify-center p-4 cyber-bg-grid relative overflow-hidden">
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/8 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/8 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-6 my-8">
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

        <Card className="border-cyan-500/30 shadow-[0_0_50px_rgba(0,243,255,0.08)]">
          <CardContent className="p-8 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <UserPlus className="w-3.5 h-3.5 text-cyan-400" /> Create Account
              </span>
              <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" /> Secured
              </span>
            </div>

            {serverError && (
              <div role="alert" className="p-3 bg-rose-950/60 border border-rose-500/40 rounded-xl text-xs text-rose-300">
                ⚠️ {serverError}
              </div>
            )}

            {/* Google OAuth Button */}
            <Button
              id="google-register-btn"
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
                Or Register With Email
              </span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3.5" noValidate>
              <Input
                id="reg-name"
                label="Full Name"
                type="text"
                placeholder="SecOps Operator"
                icon={User}
                value={form.fullName}
                onChange={handleChange('fullName')}
                error={errors.fullName}
                required
                autoComplete="name"
              />

              <Input
                id="reg-email"
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

              <div>
                <Input
                  id="reg-password"
                  label="Password"
                  type="password"
                  placeholder="Min 8 chars, 1 uppercase, 1 number"
                  icon={Lock}
                  value={form.password}
                  onChange={handleChange('password')}
                  error={errors.password}
                  required
                  autoComplete="new-password"
                />
                <PasswordStrength password={form.password} />
              </div>

              <Input
                id="reg-confirm"
                label="Confirm Password"
                type="password"
                placeholder="Re-enter password"
                icon={Lock}
                value={form.confirmPassword}
                onChange={handleChange('confirmPassword')}
                error={errors.confirmPassword}
                success={
                  form.confirmPassword &&
                  form.password === form.confirmPassword &&
                  form.password.length >= 8
                }
                required
                autoComplete="new-password"
              />

              <Button
                id="register-submit"
                type="submit"
                variant="primary"
                className="w-full py-3 mt-2"
                isLoading={isLoading}
                icon={UserPlus}
              >
                {isLoading ? 'Creating Account…' : 'Create Account'}
              </Button>
            </form>

            <div className="text-center pt-2 border-t border-slate-800 text-xs">
              <span className="text-slate-400">Already have an account? </span>
              <Link to="/login" className="text-cyan-400 font-semibold hover:underline">
                Sign In
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
