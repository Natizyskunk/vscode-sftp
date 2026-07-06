import * as vscode from 'vscode';

// A context is "protected" when its active profile is listed in
// `protectedProfiles` (e.g. ["prod"]). While protected, the status bar turns red
// and uploads ask for confirmation, to avoid accidental production deploys.
export function isProtected(fileService: any, config: any): boolean {
  const profile = fileService.getActiveProfile();
  return !!profile && (config.protectedProfiles || []).indexOf(profile) !== -1;
}

// Returns false to abort the upload.
export async function confirmProtectedUpload(ctx: any): Promise<boolean> {
  if (!isProtected(ctx.fileService, ctx.config)) {
    return true;
  }
  const profile = ctx.fileService.getActiveProfile();
  const choice = await vscode.window.showWarningMessage(
    `You are about to upload to the protected profile "${profile}" (${ctx.config.host}). Continue?`,
    { modal: true },
    'Upload to ' + profile
  );
  return choice !== undefined;
}
