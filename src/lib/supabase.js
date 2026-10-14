/**
 * Supabase Client (optional — not required for auth flow)
 * Auth is now handled directly by the Flask/FastAPI backend via JWT.
 * This file is kept for potential future Supabase integrations only.
 * It will NOT crash the app if Supabase env vars are not configured.
 */

import { createClient } from '@supabase/supabase-js';

let supabase = null;

export function getSupabase() {
  if (supabase) return supabase;

  let supabaseUrl = (import.meta.env.VITE_SUPABASE_URL || '').trim();
  const supabaseAnonKey = (import.meta.env.VITE_SUPABASE_ANON_KEY || '').trim();

  if (supabaseUrl) {
    if (supabaseUrl.endsWith('/rest/v1/')) {
      supabaseUrl = supabaseUrl.slice(0, -9);
    } else if (supabaseUrl.endsWith('/rest/v1')) {
      supabaseUrl = supabaseUrl.slice(0, -8);
    }
    supabaseUrl = supabaseUrl.replace(/\/+$/, '');
  }

  if (supabaseUrl && supabaseAnonKey) {
    try {
      supabase = createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
        },
      });
    } catch (e) {
      console.warn('Supabase client init failed:', e.message);
    }
  }
  return supabase;
}

// Initialise eagerly
getSupabase();

export { supabase };
export default supabase;

