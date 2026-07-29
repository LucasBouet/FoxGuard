import type { Config } from "tailwindcss";

/**
 * Same palette as the dashboard, same rule: peer states are drawn with the
 * reserved status colours, always as a coloured dot next to a written label,
 * with the label in normal ink. Colour never carries the meaning by itself.
 */
export default {
  content: ["./src/**/*.{ts,tsx}"],
  darkMode: ["class", ':root[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        surface: "var(--surface-1)",
        page: "var(--page)",
        ink: {
          DEFAULT: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        },
        hairline: "var(--border)",
        status: {
          good: "var(--status-good)",
          warning: "var(--status-warning)",
          serious: "var(--status-serious)",
          critical: "var(--status-critical)",
          info: "var(--status-info)",
          neutral: "var(--text-muted)",
        },
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", "Segoe UI", "sans-serif"],
      },
    },
  },
  plugins: [],
} satisfies Config;
