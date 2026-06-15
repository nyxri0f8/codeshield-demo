import { create } from 'zustand';
import type { User } from '@supabase/supabase-js';

interface AppState {
  user: User | null;
  setUser: (user: User | null) => void;
  geminiKey: string;
  setGeminiKey: (key: string) => void;
  currentScan: any | null; // scan details
  setCurrentScan: (scan: any | null) => void;
}

export const useAppStore = create<AppState>((set) => ({
  user: null,
  setUser: (user) => set({ user }),
  geminiKey: '',
  setGeminiKey: (key) => set({ geminiKey: key }),
  currentScan: null,
  setCurrentScan: (scan) => set({ currentScan: scan }),
}));
