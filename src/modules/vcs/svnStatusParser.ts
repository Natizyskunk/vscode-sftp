// Parser for the output of `svn status --xml`.
// Free of any vscode dependency so it can be unit tested.

export interface SvnStatusEntry {
  path: string;
  item: string;
  props: string;
  treeConflicted: boolean;
  movedFrom?: string;
  movedTo?: string;
}

export type SvnChangeKind = 'added' | 'modified' | 'deleted' | 'renamed' | 'untracked' | 'conflict';

export interface SvnChange {
  kind: SvnChangeKind;
  path: string;
  // only set for renames: the path before the move
  originalPath?: string;
}

function unescapeXml(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, code) => String.fromCharCode(parseInt(code, 16)))
    .replace(/&amp;/g, '&');
}

function parseAttributes(raw: string): { [name: string]: string } {
  const attributes: { [name: string]: string } = {};
  const attributeRegex = /([\w:-]+)\s*=\s*"([^"]*)"/g;
  let match = attributeRegex.exec(raw);
  while (match !== null) {
    attributes[match[1]] = unescapeXml(match[2]);
    match = attributeRegex.exec(raw);
  }
  return attributes;
}

export function parseSvnStatusXml(xml: string): SvnStatusEntry[] {
  const entries: SvnStatusEntry[] = [];
  // attributes may span several lines; a ">" inside a value is escaped by svn
  const entryRegex = /<entry\b([^>]*)>([\s\S]*?)<\/entry>/g;
  const statusRegex = /<wc-status\b([^>]*?)\/?>/;

  let match = entryRegex.exec(xml);
  while (match !== null) {
    const entryAttributes = parseAttributes(match[1]);
    const statusMatch = statusRegex.exec(match[2]);
    if (entryAttributes.path !== undefined && statusMatch) {
      const status = parseAttributes(statusMatch[1]);
      entries.push({
        path: entryAttributes.path,
        item: status.item || 'none',
        props: status.props || 'none',
        treeConflicted: status['tree-conflicted'] === 'true',
        movedFrom: status['moved-from'],
        movedTo: status['moved-to'],
      });
    }
    match = entryRegex.exec(xml);
  }

  return entries;
}

export function toSvnChanges(entries: SvnStatusEntry[]): SvnChange[] {
  // sources of moves that are reported as "renamed" through their destination entry
  const renameSources: { [path: string]: boolean } = {};
  for (const entry of entries) {
    if (entry.movedFrom && (entry.item === 'added' || entry.item === 'replaced')) {
      renameSources[entry.movedFrom] = true;
    }
  }

  const changes: SvnChange[] = [];
  for (const entry of entries) {
    if (entry.treeConflicted) {
      changes.push({ kind: 'conflict', path: entry.path });
      continue;
    }

    switch (entry.item) {
      case 'added':
      case 'replaced':
        if (entry.movedFrom) {
          changes.push({ kind: 'renamed', path: entry.path, originalPath: entry.movedFrom });
        } else {
          changes.push({ kind: entry.item === 'added' ? 'added' : 'modified', path: entry.path });
        }
        break;
      case 'modified':
      case 'merged':
        changes.push({ kind: 'modified', path: entry.path });
        break;
      case 'deleted':
      case 'missing':
        if (entry.movedTo && renameSources[entry.path]) {
          // covered by the "renamed" change of the destination
          break;
        }
        changes.push({ kind: 'deleted', path: entry.path });
        break;
      case 'unversioned':
        changes.push({ kind: 'untracked', path: entry.path });
        break;
      case 'conflicted':
        changes.push({ kind: 'conflict', path: entry.path });
        break;
      default:
        // normal (includes property-only changes), ignored, external, none, incomplete, obstructed
        break;
    }
  }

  return changes;
}
