/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",               // 루트 index.html
    "./src/**/*.{js,ts,jsx,tsx}" // src 폴더 아래 모든 JS/TS/JSX/TSX 파일
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}