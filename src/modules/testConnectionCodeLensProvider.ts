import * as vscode from 'vscode';
import { COMMAND_TEST_CONNECTION } from '../constants';

export default class TestConnectionCodeLensProvider implements vscode.CodeLensProvider {
  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const range = new vscode.Range(0, 0, 0, 0);
    return [
      new vscode.CodeLens(range, {
        title: '$(plug) Test Connection',
        command: COMMAND_TEST_CONNECTION,
        arguments: [document.uri],
      }),
    ];
  }
}
