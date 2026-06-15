import { useEffect, useState } from 'react';
import { supabase } from '../lib/supabase';
import type { User } from '@supabase/supabase-js';

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const isDemo = localStorage.getItem('demo_user') === 'true';
    if (isDemo) {
      setUser({ id: 'demo-123', email: 'demo@codeshield.dev' } as User);
      setLoading(false);
      return;
    }

    // get initial session
    supabase.auth.getSession().then(({ data }) => {
      setUser(data.session?.user ?? null);
      setLoading(false);
    }).catch(() => setLoading(false));

    // listen for auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => subscription.unsubscribe();
  }, []);

  const signInAsDemo = () => {
    localStorage.setItem('demo_user', 'true');
    setUser({ id: 'demo-123', email: 'demo@codeshield.dev' } as User);
  };

  const signInWithGoogle = () =>
    supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: `${window.location.origin}/dashboard` },
    });

  const signInWithEmail = (email: string, password: string) =>
    supabase.auth.signInWithPassword({ email, password });

  const signUpWithEmail = (email: string, password: string, fullName: string) =>
    supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
        },
      },
    });

  const signOut = () => {
    localStorage.removeItem('demo_user');
    setUser(null);
    return supabase.auth.signOut();
  };

  return { user, loading, signInAsDemo, signInWithGoogle, signInWithEmail, signUpWithEmail, signOut };
}
