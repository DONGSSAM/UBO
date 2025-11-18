import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './input.css'   // ★ Tailwind CSS 적용

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)