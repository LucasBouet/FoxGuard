import type { Config } from "tailwindcss";

/**
 * Colours live as CSS custom properties in `globals.css` so light and dark swap
 * in one place; Tailwind only names them.
 *
 * Peer states and ACL actions use the reserved **status** palette, never the
 * categorical one — they are states, not series. Two consequences are load
 * bearing:
 *
 *  - a status colour never carries meaning alone. Every badge pairs a coloured
 *    dot with a written label.
 *  - the label itself is drawn in normal ink, never in the status colour, so
 *    readability never depends on the hue. (`warning` is deliberately below 3:1
 *    on the light surface; the label is the mitigation.)
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
        grid: "var(--gridline)",
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
