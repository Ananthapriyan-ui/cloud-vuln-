/**
 * AuthContext — Flask JWT Authentication
 *
 * Auth flow:
 *   Register  → POST /api/auth/register → stores access_token + refresh_token in localStorage
 *   Login     → POST /api/auth/login    → stores access_token + refresh_token in localStorage
 *   Restore   → GET  /api/auth/me       → restores session on page reload using stored token
 *   Logout    → POST /api/auth/logout   → clears localStorage tokens
 *
 * Token keys in localStorage:
 *   cloudvuln_access_token
 *   cloudvuln_refresh_token
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { supabase, getSupabase } from '../lib/supabase';

const AuthContext = createContext(null);

const BASE_URL = import.meta.env.VITE_API_URL || '/api';

// ─── Token helpers ────────────────────────────────────────────────
export const TOKEN_KEY = 'cloudvuln_access_token';
export const REFRESH_KEY = 'cloudvuln_refresh_token';

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredRefreshToken() {
  return localStorage.getItem(REFRESH_KEY);
}

function storeTokens(access_token, refresh_token) {
  if (access_token) localStorage.setItem(TOKEN_KEY, access_token);
  if (refresh_token) localStorage.setItem(REFRESH_KEY, refresh_token);
}

function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem('cloudvuln_demo');
}

// ─── Raw fetch helpers (used before api.js is initialized) ────────
async function authFetch(endpoint, body) {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

async function authGetMe(token) {
  const res = await fetch(`${BASE_URL}/auth/me`, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) return null;
  return res.json().catch(() => null);
}

// ─── Normalise user object ──────────────────────────────────
function buildUser(userData) {
  return {
    id: userData.id,
    email: userData.email,
    full_name: userData.full_name || userData.user_metadata?.full_name || userData.email?.split('@')[0] || 'User',
    is_active: userData.is_active ?? true,
    created_at: userData.created_at,
  };
}


export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // ─── Restore session on mount & Listen to Supabase Auth ──────────────────
  useEffect(() => {
    let mounted = true;

    async function restoreSession() {
      // 1. Check Flask JWT local token first
      const token = getStoredToken();
      if (token) {
        try {
          const userData = await authGetMe(token);
          if (mounted && userData) {
            setUser(buildUser(userData));
            setLoading(false);
            return;
          }
        } catch (err) {
          console.error('Session restore error:', err);
        }
      }

      // 2. Check Supabase session (e.g. after Google OAuth redirect)
      const client = getSupabase() || supabase;
      if (client) {
        try {
          const { data: { session } } = await client.auth.getSession();
          if (mounted && session?.user) {
            setUser(buildUser(session.user));
            setLoading(false);
            return;
          }
        } catch (err) {
          console.error('Supabase session check error:', err);
        }
      }

      if (mounted) setLoading(false);
    }

    restoreSession();

    // Listen for Supabase auth changes (OAuth callbacks)
    let authListener = null;
    const client = getSupabase() || supabase;
    if (client) {
      const { data } = client.auth.onAuthStateChange((event, session) => {
        if (session?.user) {
          setUser(buildUser(session.user));
        } else if (event === 'SIGNED_OUT') {
          setUser(null);
        }
      });
      authListener = data?.subscription;
    }

    return () => {
      mounted = false;
      if (authListener) authListener.unsubscribe();
    };
  }, []);


  // ─── Login ────────────────────────────────────────────────────────
  const login = useCallback(async (email, password) => {
    try {
      const { ok, data } = await authFetch('/auth/login', { email, password });

      if (!ok) {
        return { success: false, error: data.message || data.detail || 'Invalid email or password' };
      }

      storeTokens(data.access_token, data.refresh_token);
      const appUser = buildUser(data.user);
      setUser(appUser);
      return { success: true, user: appUser };
    } catch (err) {
      return { success: false, error: err.message || 'Network error. Check if the backend is running.' };
    }
  }, []);

  // ─── Google OAuth Login via Supabase ─────────────────────────────
  const loginWithGoogle = useCallback(async () => {
    const client = getSupabase() || supabase;
    if (!client) {
      return {
        success: false,
        error: 'Supabase client is not configured. Please add VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY to your .env file and restart Vite.',
      };
    }

    try {
      const { error } = await client.auth.signInWithOAuth({
        provider: 'google',
        options: {
          redirectTo: window.location.origin,
        },
      });

      if (error) throw error;
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message || 'Google OAuth sign-in failed.' };
    }
  }, []);

  // ─── Register ────────────────────────────────────────────────────
  const register = useCallback(async (email, password, fullName) => {
    try {
      const { ok, data } = await authFetch('/auth/register', {
        email,
        password,
        full_name: fullName,
      });

      if (!ok) {
        return { success: false, error: data.message || data.detail || 'Registration failed' };
      }

      storeTokens(data.access_token, data.refresh_token);
      const appUser = buildUser(data.user);
      setUser(appUser);
      return { success: true, user: appUser };
    } catch (err) {
      return { success: false, error: err.message || 'Network error. Check if the backend is running.' };
    }
  }, []);


  // ─── Logout ───────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    const token = getStoredToken();
    if (token) {
      fetch(`${BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
    const client = getSupabase() || supabase;
    if (client) {
      client.auth.signOut().catch(() => {});
    }
    clearTokens();
    setUser(null);
  }, []);


  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        loading,
        login,
        loginWithGoogle,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};
