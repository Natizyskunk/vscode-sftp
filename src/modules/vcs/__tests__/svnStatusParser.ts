import { parseSvnStatusXml, toSvnChanges, SvnChange } from '../svnStatusParser';

// trimmed real output of `svn status --xml C:\wc` (svn 1.14)
const FIXTURE = String.raw`<?xml version="1.0" encoding="UTF-8"?>
<status>
<target
   path="C:\wc">
<entry
   path="C:\wc\a.txt">
<wc-status
   item="modified"
   revision="1"
   props="none">
<commit
   revision="1">
<author>jonas</author>
<date>2026-09-02T04:16:49.576853Z</date>
</commit>
</wc-status>
</entry>
<entry
   path="C:\wc\added.txt">
<wc-status
   item="added"
   revision="-1"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\del.txt">
<wc-status
   item="deleted"
   revision="1"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\dir\b.txt">
<wc-status
   moved-to="C:\wc\dir\c.txt"
   item="deleted"
   revision="1"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\dir\c.txt">
<wc-status
   moved-from="C:\wc\dir\b.txt"
   item="added"
   props="none"
   copied="true">
</wc-status>
</entry>
<entry
   path="C:\wc\miss.txt">
<wc-status
   item="missing"
   revision="1"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\new.txt">
<wc-status item="unversioned" props="none"/>
</entry>
<entry
   path="C:\wc\newdir">
<wc-status
   item="unversioned"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\prop.txt">
<wc-status
   item="normal"
   revision="1"
   props="modified">
</wc-status>
</entry>
<entry
   path="C:\wc\sp ace &amp; &quot;amp&quot;.txt">
<wc-status
   item="modified"
   revision="1"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\conflict.txt">
<wc-status
   item="conflicted"
   revision="1"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\tree.txt">
<wc-status
   item="normal"
   revision="1"
   props="none"
   tree-conflicted="true">
</wc-status>
</entry>
<entry
   path="C:\wc\ignored.log">
<wc-status
   item="ignored"
   props="none">
</wc-status>
</entry>
<entry
   path="C:\wc\gone.txt">
<wc-status
   moved-to="C:\elsewhere\gone.txt"
   item="deleted"
   revision="1"
   props="none">
</wc-status>
</entry>
</target>
</status>
`;

// "C:\wc\<relative path with forward slashes>"
function wc(relativePath: string): string {
  return 'C:\\wc\\' + relativePath.replace(/\//g, '\\');
}

function byPath(changes: SvnChange[], filePath: string): SvnChange | undefined {
  return changes.find(change => change.path === filePath);
}

describe('parseSvnStatusXml', () => {
  const entries = parseSvnStatusXml(FIXTURE);

  test('reads every entry', () => {
    expect(entries.map(entry => entry.path)).toEqual([
      wc('a.txt'),
      wc('added.txt'),
      wc('del.txt'),
      wc('dir/b.txt'),
      wc('dir/c.txt'),
      wc('miss.txt'),
      wc('new.txt'),
      wc('newdir'),
      wc('prop.txt'),
      wc('sp ace & "amp".txt'),
      wc('conflict.txt'),
      wc('tree.txt'),
      wc('ignored.log'),
      wc('gone.txt'),
    ]);
  });

  test('reads multi-line and self-closing wc-status elements', () => {
    expect(entries[0]).toEqual({
      path: wc('a.txt'),
      item: 'modified',
      props: 'none',
      treeConflicted: false,
      movedFrom: undefined,
      movedTo: undefined,
    });
    expect(entries[6].item).toBe('unversioned');
  });

  test('reads move information', () => {
    expect(entries[3].movedTo).toBe(wc('dir/c.txt'));
    expect(entries[4].movedFrom).toBe(wc('dir/b.txt'));
  });

  test('reads tree conflicts', () => {
    expect(entries[11].treeConflicted).toBe(true);
  });

  test('handles empty output', () => {
    expect(parseSvnStatusXml('')).toEqual([]);
    expect(parseSvnStatusXml('<status><target path="x"></target></status>')).toEqual([]);
  });
});

describe('toSvnChanges', () => {
  const changes = toSvnChanges(parseSvnStatusXml(FIXTURE));

  test('maps content changes', () => {
    expect(byPath(changes, wc('a.txt'))).toEqual({ kind: 'modified', path: wc('a.txt') });
    expect(byPath(changes, wc('added.txt'))).toEqual({ kind: 'added', path: wc('added.txt') });
    expect(byPath(changes, wc('sp ace & "amp".txt'))!.kind).toBe('modified');
  });

  test('maps deleted and missing files', () => {
    expect(byPath(changes, wc('del.txt'))!.kind).toBe('deleted');
    expect(byPath(changes, wc('miss.txt'))!.kind).toBe('deleted');
  });

  test('maps unversioned files and folders', () => {
    expect(byPath(changes, wc('new.txt'))!.kind).toBe('untracked');
    expect(byPath(changes, wc('newdir'))!.kind).toBe('untracked');
  });

  test('turns moves into a single rename', () => {
    expect(byPath(changes, wc('dir/c.txt'))).toEqual({
      kind: 'renamed',
      path: wc('dir/c.txt'),
      originalPath: wc('dir/b.txt'),
    });
    expect(byPath(changes, wc('dir/b.txt'))).toBeUndefined();
  });

  test('keeps a deletion whose move target is outside the status range', () => {
    expect(byPath(changes, wc('gone.txt'))!.kind).toBe('deleted');
  });

  test('maps conflicts', () => {
    expect(byPath(changes, wc('conflict.txt'))!.kind).toBe('conflict');
    expect(byPath(changes, wc('tree.txt'))!.kind).toBe('conflict');
  });

  test('skips property-only changes and ignored files', () => {
    expect(byPath(changes, wc('prop.txt'))).toBeUndefined();
    expect(byPath(changes, wc('ignored.log'))).toBeUndefined();
  });
});
