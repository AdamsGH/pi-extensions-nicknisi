import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { discoverRelaySessions, DISCOVERY_OUTPUT_MAX_BYTES, type RelayDiscoveryInput } from './discovery.js';
import { deriveAddr, writeRecord, type SessionRecord } from './registry.js';
import { resolveReplyTarget, resolveSessionTarget } from './routing.js';

const fixtures: string[] = [];
afterEach(() => {
  for (const root of fixtures.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});
function fixture(): string {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'relay-discovery-')));
  fixtures.push(root);
  return root;
}
function record(id: string, over: Partial<SessionRecord> = {}): SessionRecord {
  return {
    addr: deriveAddr('/work', id),
    sessionId: id,
    name: id,
    cwd: '/work',
    pid: process.pid,
    startedAt: 100,
    lastSeenAt: Date.now(),
    status: 'idle',
    ...over,
  };
}
function input(root: string, over: Partial<RelayDiscoveryInput> = {}): RelayDiscoveryInput {
  return { action: 'list-cwd', root, selfAddress: deriveAddr('/work', 'self'), activeCwd: '/work', ...over };
}

it('defaults to online neighbors, includes descendants, and supports exact offline/self lookups', () => {
  const root = fixture();
  for (const r of [
    record('self'),
    record('live'),
    record('child', { cwd: '/work/child' }),
    record('outside', { cwd: '/workspace' }),
    record('offline', { offline: true }),
  ])
    writeRecord(root, r);
  const online = discoverRelaySessions(input(root));
  expect(online.details.sessions.map((r) => r.sessionId)).toEqual(['child', 'live']);
  expect(online.text).toContain('presence=all');
  expect(
    discoverRelaySessions(input(root, { includeSubdirectories: false })).details.sessions.map((r) => r.sessionId),
  ).toEqual(['live']);
  const exact = discoverRelaySessions(input(root, { sessionIds: ['offline', 'self', 'outside', 'unknown'] }));
  expect(exact.details.sessions.map((r) => r.sessionId)).toEqual(['offline', 'self']);
  expect(exact.details.notRegisteredSessionIds).toEqual(['unknown']);
  expect(exact.details.excludedSessionIds).toEqual([{ sessionId: 'outside', reasons: ['cwd'] }]);
  expect(
    discoverRelaySessions(input(root, { sessionIds: ['offline'], presence: 'online' })).details.excludedSessionIds,
  ).toEqual([{ sessionId: 'offline', reasons: ['presence'] }]);
});

it('paginates by stable keys despite heartbeats and rejects foreign or malformed cursors', () => {
  const root = fixture();
  for (let i = 0; i < 25; i++) writeRecord(root, record(`session-${String(i).padStart(2, '0')}`));
  const first = discoverRelaySessions(input(root));
  expect(first.details.returned).toBe(20);
  expect(first.details.total).toBe(25);
  expect(first.text).toContain(first.details.sessions[0]!.address);
  writeRecord(root, record('session-00', { lastSeenAt: Date.now() + 1000 }));
  const next = discoverRelaySessions(input(root, first.details.nextArguments!));
  expect(next.details.sessions.map((r) => r.sessionId)).toEqual([
    'session-20',
    'session-21',
    'session-22',
    'session-23',
    'session-24',
  ]);
  expect(next.details.hasMore).toBe(false);
  expect(() => discoverRelaySessions(input(root, { cursor: first.details.nextCursor!, presence: 'all' }))).toThrow(
    /does not match/,
  );
  expect(() => discoverRelaySessions(input(root, { cursor: 'garbage' }))).toThrow(/Restart/);
  expect(discoverRelaySessions(input(root)).details.returned).toBe(20);
});

it('measures the complete escaped UTF-8 envelope and returns advancing byte-limited pages', () => {
  const root = fixture();
  for (let i = 0; i < 100; i++)
    writeRecord(
      root,
      record(`id-${String(i).padStart(3, '0')}-${'界'.repeat(240)}`, {
        name: '\u001b[31m' + '界'.repeat(150),
        cwd: '/work/' + '界'.repeat(150),
      }),
    );
  let args = input(root, { limit: 100 });
  const seen: string[] = [];
  for (let page = 0; page < 100; page++) {
    const result = discoverRelaySessions(args);
    expect(result.details.outputBytes).toBe(
      Buffer.byteLength(JSON.stringify({ content: [{ type: 'text', text: result.text }], details: result.details })),
    );
    expect(result.details.outputBytes).toBeLessThanOrEqual(DISCOVERY_OUTPUT_MAX_BYTES);
    expect(result.details.returned).toBeGreaterThan(0);
    expect(result.text).not.toContain('\u001b');
    seen.push(...result.details.sessions.map((r) => r.sessionId));
    if (!result.details.hasMore) break;
    args = input(root, result.details.nextArguments!);
  }
  expect(seen).toHaveLength(100);
  expect(new Set(seen).size).toBe(100);
});

it('validates discovery before touching the root and refuses oversized exact identities', () => {
  expect(() => discoverRelaySessions(input('/definitely/absent', { limit: 0 }))).toThrow(/limit/);
  expect(() => discoverRelaySessions(input('/definitely/absent', { sessionIds: ['same', 'same'] }))).toThrow(/unique/);
  const root = fixture();
  writeRecord(root, record('x'.repeat(50000)));
  expect(() => discoverRelaySessions(input(root))).toThrow(/budget|continuation/);
});

it('routes exact session IDs case-sensitively and refuses collisions instead of guessing', () => {
  const peer = record('Exact-ID', { name: 'Human title' });
  expect(resolveSessionTarget(peer.sessionId, [peer], 'self').record).toEqual(peer);
  expect(resolveSessionTarget('exact-id', [peer], 'self').error).toBeDefined();
  expect(
    resolveSessionTarget(peer.sessionId, [peer, record('other', { name: peer.sessionId })], 'self').error,
  ).toContain('ambiguous');
  expect(
    resolveSessionTarget(peer.sessionId, [peer, { ...peer, addr: deriveAddr('/other', peer.sessionId) }], 'self').error,
  ).toContain('ambiguous');
  expect(resolveSessionTarget(peer.sessionId, [peer], peer.addr).error).toBeDefined();
});

it('resolves ordinary replies from only the active branch and rejects conflicting senders and watcher entries', () => {
  const id = 'ordinary-message';
  const peer = record('peer');
  const entry = {
    type: 'custom_message',
    customType: 'relay:delivery',
    details: { id, kind: 'message', from: { addr: peer.addr } },
  };
  expect(resolveReplyTarget(id, [], [entry]).target).toEqual({ id, addr: peer.addr, ask: false });
  expect(resolveReplyTarget(id, [], []).error).toContain('active conversation');
  expect(resolveReplyTarget(id, [], [{ ...entry, details: { ...entry.details, kind: 'cancel' } }]).error).toBeDefined();
  expect(
    resolveReplyTarget(
      id,
      [],
      [entry, { ...entry, details: { ...entry.details, from: { addr: record('other').addr } } }],
    ).error,
  ).toContain('ambiguous');
  expect(resolveReplyTarget(id, [], [entry, entry]).target?.addr).toBe(peer.addr);
  expect(
    resolveReplyTarget(id, [], [entry, { ...entry, details: { ...entry.details, id: `${id}-longer` } }]).target?.id,
  ).toBe(id);
});
