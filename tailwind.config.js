/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#0b1020",
          raised: "#151b30",
          border: "#232b45",
        },
        accent: {
          DEFAULT: "#5b8cff",
          muted: "#3a5bbf",
        },
      },
    },
  },
  plugins: [],
};