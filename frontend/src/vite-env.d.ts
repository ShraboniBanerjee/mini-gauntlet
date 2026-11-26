/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Optional API origin. Empty means the dashboard's own origin (nginx or the Vite proxy). */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
