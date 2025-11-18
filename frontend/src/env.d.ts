interface ImportMetaEnv {
  readonly VITE_API_URL: string
  // 필요한 환경 변수 추가
  // readonly VITE_SOME_KEY: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}