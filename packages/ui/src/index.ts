/**
 * NIZ Design System Tokens
 * Strict adherence to charcoal/deep navy background, emerald green accents,
 * soft neutrals, and WCAG AA contrast.
 */

export const NizTokens = {
  colors: {
    // Backgrounds & Canvas
    canvas: '#090D14', // Deepest charcoal / dark navy
    surface: '#111827', // Card & elevated surface
    surfaceHover: '#1F2937', // Hover state
    surfaceActive: '#283344', // Active / pressed state
    border: '#232D3F', // Subtle border for separation

    // Accents (Emerald Green)
    primary: '#10B981', // Vibrant emerald
    primaryHover: '#059669', // Darker emerald hover
    primaryFocus: '#34D399', // Focus outline ring
    primaryMuted: 'rgba(16, 185, 129, 0.12)', // Subtle green tint

    // Status & Feedback
    success: '#10B981',
    warning: '#F59E0B',
    danger: '#EF4444',
    info: '#3B82F6',

    // Typography
    textPrimary: '#F9FAFB', // Pure/soft white for high readability
    textSecondary: '#9CA3AF', // Cool gray for metadata
    textMuted: '#6B7280', // Inactive labels
    textInverse: '#090D14', // Text on bright emerald buttons
  },
  radii: {
    sm: '6px',
    md: '10px',
    lg: '16px',
    full: '9999px',
  },
  typography: {
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
    monoFamily:
      'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
  },
  shadows: {
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.5)',
    card: '0 4px 12px 0 rgba(0, 0, 0, 0.35)',
    modal: '0 20px 25px -5px rgba(0, 0, 0, 0.7), 0 10px 10px -5px rgba(0, 0, 0, 0.5)',
  },
} as const;

export type NizColorKeys = keyof typeof NizTokens.colors;
