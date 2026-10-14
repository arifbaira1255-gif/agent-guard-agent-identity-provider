import type { Config } from "tailwindcss";

const config: Config = {
  // Theme is toggled by adding/removing the `dark` class on <html>.
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#eef4ff",
          100: "#d9e6ff",
          200: "#bcd3ff",
          300: "#8fb4ff",
          400: "#5b8bfb",
          500: "#3b6ef6",
          600: "#2b57d6",
          700: "#1f43ab",
          800: "#1a3788",
          900: "#12245c",
        },
      },
      boxShadow: {
        soft: "0 1px 2px rgba(16,24,40,0.04), 0 8px 24px -12px rgba(16,24,40,0.18)",
        card: "0 1px 3px rgba(16,24,40,0.06), 0 12px 32px -16px rgba(16,24,40,0.22)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgba(59,110,246,0.45)" },
          "70%": { boxShadow: "0 0 0 8px rgba(59,110,246,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(59,110,246,0)" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.25s ease-out both",
        "pulse-ring": "pulse-ring 1.8s cubic-bezier(0.4,0,0.6,1) infinite",
        shimmer: "shimmer 1.6s infinite",
      },
    },
  },
  plugins: [],
};

export default config;
