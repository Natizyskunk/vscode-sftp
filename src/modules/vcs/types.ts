import { Uri } from 'vscode';

export type VcsKind = 'git' | 'svn';

export type ChangeKind = 'added' | 'modified' | 'deleted' | 'renamed' | 'untracked' | 'conflict';

export interface VcsChange {
  vcs: VcsKind;
  kind: ChangeKind;
  // local file or folder the change refers to (for renames: the new path)
  uri: Uri;
  // only set for renames: the path before the rename
  originalUri?: Uri;
  // root directory of the repository / working copy
  repositoryRoot: string;
}
