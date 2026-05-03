/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', "monospace"],
        display: ['"Major Mono Display"', '"JetBrains Mono"', "monospace"],
      },
      colors: {
        bg: "#0a0e0a",
        panel: "#0f150f",
        panel2: "#131c13",
        border: "#1a2a1a",
        ink: "#c8e6c8",
        dim: "#6a8a6a",
        phosphor: "#5fff8a",
        amber: "#ffb454",
        crimson: "#ff5f6d",
        violet: "#a78bfa",
      },
      animation: {
        blink: "blink 1.1s steps(2) infinite",
        scan: "scan 6s linear infinite",
        "fade-in": "fade-in 0.4s ease-out",
        "slide-up": "slide-up 0.3s ease-out",
      },
      keyframes: {
        blink: { "50%": { opacity: "0" } },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(400%)" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "slide-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
