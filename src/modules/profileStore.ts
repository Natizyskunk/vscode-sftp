import app from '../app';

// Persists the active profile per context (keyed by its base dir) so a chosen
// profile survives window reloads. Backed by VS Code's per-workspace storage.
const KEY_PREFIX = 'sftp.profile:';

// undefined -> never chosen for this context (fall back to defaultProfile)
// null      -> explicitly UNSET by the user
export function getStoredProfile(baseDir: string): string | null | undefined {
  if (!app.workspaceState) {
    return undefined;
  }
  return app.workspaceState.get<string | null>(KEY_PREFIX + baseDir);
}

export function storeProfile(baseDir: string, profile: string | null) {
  if (!app.workspaceState) {
    return;
  }
  app.workspaceState.update(KEY_PREFIX + baseDir, profile);
}
