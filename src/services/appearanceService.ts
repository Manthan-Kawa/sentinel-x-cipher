/**
 * Appearance Service
 * Manages theme presets ('Dark Cyber' | 'Obsidian Black' | 'Cyberpunk Teal' | 'Crimson Red'),
 * animation toggles, and neon  effects for both User and Analyst portals.
 */

export type ThemePreset = 'Dark Cyber' | 'Obsidian Black' | 'Cyberpunk Teal' | 'Crimson Red';

export interface AppearancePreferences {
  themePreset: ThemePreset;
  animationsEnabled: boolean;
  glowEffects: boolean;
}

const KEY_THEME = 'sentinel_appearance_theme';
const KEY_ANIMATIONS = 'sentinel_appearance_animations';
const KEY_GLOW = 'sentinel_appearance_glow';

export const THEME_PALETTES: Record<
  ThemePreset,
  {
    name: ThemePreset;
    color: string;
    bg: string;
    cardBg: string;
    border: string;
  }
> = {
  'Dark Cyber': {
    name: 'Dark Cyber',
    color: '#8b5cf6',
    bg: '#08090e',
    cardBg: '#0c0e18',
    border: 'rgba(139, 92, 246, 0.25)',
  },
  'Obsidian Black': {
    name: 'Obsidian Black',
    color: '#3b82f6',
    bg: '#030508',
    cardBg: '#070b12',
    border: 'rgba(59, 130, 246, 0.25)',
  },
  'Cyberpunk Teal': {
    name: 'Cyberpunk Teal',
    color: '#14b8a6',
    bg: '#030c10',
    cardBg: '#051419',
    border: 'rgba(20, 184, 166, 0.25)',
  },
  'Crimson Red': {
    name: 'Crimson Red',
    color: '#ef4444',
    bg: '#0a0406',
    cardBg: '#13060a',
    border: 'rgba(239, 68, 68, 0.25)',
  },
};

export class AppearanceService {
  /**
   * Retrieves active appearance preferences for the user/analyst.
   */
  static getPreferences(userEmail?: string): AppearancePreferences {
    let themePreset: ThemePreset = 'Dark Cyber';
    let animationsEnabled = true;
    let glowEffects = false;

    try {
      const cleanEmail = (userEmail || '').trim().toLowerCase();
      if (cleanEmail) {
        const userSettingsRaw = localStorage.getItem(`sentinel_user_settings_${cleanEmail}`);
        if (userSettingsRaw) {
          const parsed = JSON.parse(userSettingsRaw);
          if (parsed.themePreset && THEME_PALETTES[parsed.themePreset as ThemePreset]) {
            themePreset = parsed.themePreset;
          }
          if (parsed.animationsEnabled !== undefined) {
            animationsEnabled = Boolean(parsed.animationsEnabled);
          }
        }
      }

      // Fallback to global keys
      const savedTheme = localStorage.getItem(KEY_THEME) as ThemePreset;
      if (savedTheme && THEME_PALETTES[savedTheme]) {
        themePreset = savedTheme;
      }

      const savedAnim = localStorage.getItem(KEY_ANIMATIONS);
      if (savedAnim !== null) {
        animationsEnabled = savedAnim === 'true';
      }
    } catch {
      // ignore
    }

    return { themePreset, animationsEnabled, glowEffects: false };
  }

  /**
   * Applies appearance settings to the DOM (<html> attributes, CSS custom properties)
   * and saves them to localStorage.
   */
  static applyPreferences(prefs: Partial<AppearancePreferences>, userEmail?: string): AppearancePreferences {
    const current = this.getPreferences(userEmail);
    const updated: AppearancePreferences = {
      themePreset: prefs.themePreset ?? current.themePreset,
      animationsEnabled: prefs.animationsEnabled ?? current.animationsEnabled,
      glowEffects: false,
    };

    try {
      localStorage.setItem(KEY_THEME, updated.themePreset);
      localStorage.setItem(KEY_ANIMATIONS, String(updated.animationsEnabled));
      localStorage.setItem(KEY_GLOW, 'false');

      const cleanEmail = (userEmail || '').trim().toLowerCase();
      if (cleanEmail) {
        const userSettingsRaw = localStorage.getItem(`sentinel_user_settings_${cleanEmail}`);
        const parsed = userSettingsRaw ? JSON.parse(userSettingsRaw) : {};
        localStorage.setItem(
          `sentinel_user_settings_${cleanEmail}`,
          JSON.stringify({
            ...parsed,
            themePreset: updated.themePreset,
            animationsEnabled: updated.animationsEnabled,
            glowEffects: false,
          })
        );
      }
    } catch (e) {
      console.warn('Failed to save appearance preferences:', e);
    }

    // Set DOM attributes
    if (typeof document !== 'undefined') {
      const root = document.documentElement;
      root.setAttribute('data-theme', updated.themePreset);
      root.setAttribute('data-animations', String(updated.animationsEnabled));

      const palette = THEME_PALETTES[updated.themePreset] || THEME_PALETTES['Dark Cyber'];
      root.style.setProperty('--theme-primary', palette.color);
      root.style.setProperty('--theme-bg', palette.bg);
      root.style.setProperty('--theme-card-bg', palette.cardBg);
      root.style.setProperty('--theme-card-border', palette.border);
      root.style.setProperty('--theme-glow', 'none');
    }

    // Broadcast event
    try {
      window.dispatchEvent(new CustomEvent('sentinel_appearance_changed', { detail: updated }));
    } catch {
      // ignore
    }

    return updated;
  }

  static isAnimationsEnabled(userEmail?: string): boolean {
    return this.getPreferences(userEmail).animationsEnabled;
  }

  static isGlowEnabled(userEmail?: string): boolean {
    return this.getPreferences(userEmail).glowEffects;
  }

  static getTheme(userEmail?: string): ThemePreset {
    return this.getPreferences(userEmail).themePreset;
  }

  static init(): void {
    const user = typeof localStorage !== 'undefined' ? localStorage.getItem('sentinel_user') || '' : '';
    const prefs = this.getPreferences(user);
    this.applyPreferences(prefs, user);
  }
}
