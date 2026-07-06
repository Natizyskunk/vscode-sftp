import * as vscode from 'vscode';
import { COMMAND_SET_PROFILE, SET_PROFILE_ACTIVE_CONTEXT } from '../constants';
import { showInformationMessage } from '../host';
import app from '../app';
import logger from '../logger';
import { getAllFileService, getFileService } from '../modules/serviceManager';
import { storeProfile } from '../modules/profileStore';
import { FileService } from '../core';
import { checkCommand } from './abstract/createCommand';

const ALL = '__all__';

export default checkCommand({
  id: COMMAND_SET_PROFILE,

  async handleCommand(arg) {
    const servicesWithProfiles = getAllFileService().filter(
      service => service.getAvailableProfiles().length > 0
    );

    if (servicesWithProfiles.length <= 0) {
      showInformationMessage('No Available Profile.');
      return;
    }

    // status-bar shortcut: jump straight to the active editor's context
    if (arg === SET_PROFILE_ACTIVE_CONTEXT) {
      const editor = vscode.window.activeTextEditor;
      const svc = editor ? getFileService(editor.document.uri) : undefined;
      if (svc && svc.getAvailableProfiles().length > 0) {
        await pickProfileFor([svc]);
        return;
      }
      // no active context with profiles -> fall through to the normal picker
      arg = undefined;
    }

    // programmatic call: apply to every context that has the profile (back-compat)
    if (arg !== undefined) {
      applyProfile(servicesWithProfiles, arg);
      return;
    }

    // step 1: pick the context (skip when there is only one)
    let targets: FileService[];
    if (servicesWithProfiles.length === 1) {
      targets = servicesWithProfiles;
    } else {
      const contextItems: Array<
        vscode.QuickPickItem & { value: FileService | typeof ALL }
      > = servicesWithProfiles.map(service => ({
        label: service.name || '(unnamed)',
        description: service.getActiveProfile()
          ? `active: ${service.getActiveProfile()}`
          : '',
        value: service,
      }));
      contextItems.unshift({ label: 'All contexts', value: ALL });

      const pickedContext = await vscode.window.showQuickPick(contextItems, {
        placeHolder: 'select a context',
      });
      if (pickedContext === undefined) return;
      targets =
        pickedContext.value === ALL
          ? servicesWithProfiles
          : [pickedContext.value];
    }

    await pickProfileFor(targets);
  },
});

// step 2: pick the profile (union of profiles available across targets) + UNSET
async function pickProfileFor(targets: FileService[]) {
  const available = Array.from(
    new Set(
      targets.reduce<string[]>(
        (acc, service) => acc.concat(service.getAvailableProfiles()),
        []
      )
    )
  );
  const profileItems: Array<vscode.QuickPickItem & { value: string | null }> = [
    { label: 'UNSET', value: null },
    ...available.map(profile => ({ label: profile, value: profile })),
  ];

  const picked = await vscode.window.showQuickPick(profileItems, {
    placeHolder: 'select a profile',
  });
  if (picked === undefined) return;

  applyProfile(targets, picked.value);
}

function applyProfile(services: FileService[], profile: string | null) {
  services.forEach(service => {
    if (profile === null || service.getAvailableProfiles().indexOf(profile) !== -1) {
      service.setActiveProfile(profile);
      storeProfile(service.baseDir, profile); // persist across reloads
    } else {
      logger.warn(`profile "${profile}" not found for context "${service.name}"`);
    }
  });
  app.state.notify();
}
