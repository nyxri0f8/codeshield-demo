import { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';

const DEMO_USER_ID = 'demo-123';
const DEMO_GEMINI_KEY_STORAGE = 'demo_gemini_key';

export function useGeminiKey(userId: string | undefined) {
  const [geminiKey, setGeminiKey] = useState<string>(() => import.meta.env.VITE_GEMINI_API_KEY || '');
  const [saving, setSaving] = useState(false);

  const isDemo = userId === DEMO_USER_ID;

  // fetch key on mount
  useEffect(() => {
    if (!userId) {
      const envKey = import.meta.env.VITE_GEMINI_API_KEY || '';
      if (envKey) setGeminiKey(envKey);
      return;
    }

    // Demo mode: load from localStorage, never touch Supabase
    if (isDemo) {
      const stored = localStorage.getItem(DEMO_GEMINI_KEY_STORAGE) || import.meta.env.VITE_GEMINI_API_KEY || '';
      setGeminiKey(stored);
      return;
    }

    supabase
      .from('profiles')
      .select('gemini_api_key')
      .eq('id', userId)
      .single()
      .then(({ data }) => {
        if (data?.gemini_api_key) {
          setGeminiKey(data.gemini_api_key);
        } else {
          const envKey = import.meta.env.VITE_GEMINI_API_KEY || '';
          if (envKey) setGeminiKey(envKey);
        }
      });
  }, [userId]);

  // save key — localStorage for demo, Supabase for real users
  const saveKey = async (key: string) => {
    if (!userId) return;
    setSaving(true);

    if (isDemo) {
      localStorage.setItem(DEMO_GEMINI_KEY_STORAGE, key);
      setGeminiKey(key);
      setSaving(false);
      return;
    }

    await supabase
      .from('profiles')
      .update({ gemini_api_key: key })
      .eq('id', userId);
    setGeminiKey(key);
    setSaving(false);
  };

  return { geminiKey, saveKey, saving };
}
