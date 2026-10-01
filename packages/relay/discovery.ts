import { createHash } from 'node:crypto';
import * as path from 'node:path';
import { listRecords, presenceOf } from './core.js';
import type { SessionRecord as RelaySessionRecord, Presence as SessionPresence } from './registry.js';

export interface RelayDiscoveryArguments {
  action: 'list' | 'list-cwd';
  cwd?: string;
  includeSubdirectories?: boolean;
  sessionIds?: string[];
  presence?: 'all' | 'online' | 'live' | 'stalled' | 'offline';
  limit?: number;
  cursor?: string;
}

export const DISCOVERY_DEFAULT_LIMIT = 20;
export const DISCOVERY_MAX_LIMIT = 100;
export const DISCOVERY_MAX_SESSION_IDS = 64;
export const DISCOVERY_OUTPUT_MAX_BYTES = 48 * 1024;

type DiscoveryPresenceFilter = NonNullable<RelayDiscoveryArguments['presence']>;
type CursorKey = readonly [registeredAt: number, sessionId: string, address: string];

export interface RelayDiscoverySession {
  readonly sessionId: string;
  readonly address: string;
  readonly name: string;
  readonly cwd: string;
  readonly nameTruncated: boolean;
  readonly cwdTruncated: boolean;
  readonly presence: SessionPresence;
  readonly activity: RelaySessionRecord['status'];
  readonly sampledAt: number;
}

export interface RelayDiscoveryExcluded {
  readonly sessionId: string;
  readonly reasons: readonly ('cwd' | 'presence')[];
}

export interface RelayDiscoveryDetails {
  readonly outcome: 'success';
  readonly action: 'list' | 'list-cwd';
  readonly count: number;
  readonly total: number;
  readonly returned: number;
  readonly sampledAt: number;
  readonly sessions: readonly RelayDiscoverySession[];
  readonly notRegisteredSessionIds: readonly string[];
  readonly excludedSessionIds: readonly RelayDiscoveryExcluded[];
  readonly excludedCount: number;
  readonly hasMore: boolean;
  readonly nextCursor?: string;
  readonly nextArguments?: Record<string, unknown>;
  readonly outputBytes: number;
  readonly outputTruncated: boolean;
}

export interface RelayDiscoveryResult {
  readonly text: string;
  readonly details: RelayDiscoveryDetails;
}

export type RelayDiscoveryInput = RelayDiscoveryArguments & {
  readonly selfAddress: string;
  readonly activeCwd: string;
  readonly root: string;
  readonly now?: number;
};

interface CursorPayload {
  readonly version: 1;
  readonly queryHash: string;
  readonly after: CursorKey;
}

interface PreparedRecord {
  readonly record: RelaySessionRecord;
  readonly presence: SessionPresence;
  readonly key: CursorKey;
}

const CONTROL_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
const ANSI_PATTERN = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const DISPLAY_MAX_CHARS = 96;
const CURSOR_HASH_PATTERN = /^[a-f0-9]{64}$/;

function sanitizeDisplay(value: string): { readonly value: string; readonly truncated: boolean } {
  const cleaned = value.replace(ANSI_PATTERN, '').replace(CONTROL_PATTERN, '').replace(/\s+/g, ' ').trim();
  if (cleaned.length <= DISPLAY_MAX_CHARS) return { value: cleaned, truncated: false };
  return {
    value: `${cleaned.slice(0, DISPLAY_MAX_CHARS - 14)} [truncated]`,
    truncated: true,
  };
}

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function recordKey(record: RelaySessionRecord): CursorKey {
  return [record.startedAt, record.sessionId, record.addr];
}

function compareKey(left: CursorKey, right: CursorKey): number {
  return left[0] - right[0] || compareString(left[1], right[1]) || compareString(left[2], right[2]);
}

function isCursorKey(value: unknown): value is CursorKey {
  return (
    Array.isArray(value) &&
    value.length === 3 &&
    Number.isSafeInteger(value[0]) &&
    value[0] >= 0 &&
    typeof value[1] === 'string' &&
    value[1].length > 0 &&
    typeof value[2] === 'string' &&
    value[2].length > 0
  );
}

function encodeCursor(payload: CursorPayload): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

function decodeCursor(value: string): CursorPayload {
  try {
    const raw = Buffer.from(value, 'base64url').toString('utf8');
    const decoded: unknown = JSON.parse(raw);
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) throw new Error('invalid shape');
    const candidate = decoded as Record<string, unknown>;
    if (
      Object.keys(candidate).length !== 3 ||
      candidate.version !== 1 ||
      typeof candidate.queryHash !== 'string' ||
      !CURSOR_HASH_PATTERN.test(candidate.queryHash) ||
      !isCursorKey(candidate.after) ||
      Buffer.from(raw, 'utf8').toString('base64url') !== value
    )
      throw new Error('invalid cursor');
    return { version: 1, queryHash: candidate.queryHash, after: candidate.after };
  } catch {
    throw new Error('Invalid relay discovery cursor. Restart discovery without cursor.');
  }
}

function filterMatches(presence: SessionPresence, filter: DiscoveryPresenceFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'online') return presence === 'live' || presence === 'stalled';
  return presence === filter;
}

function effectivePresence(input: RelayDiscoveryInput): DiscoveryPresenceFilter {
  return input.presence ?? (input.sessionIds === undefined ? 'online' : 'all');
}

function queryHash(
  input: RelayDiscoveryInput,
  cwd: string | undefined,
  includeSubdirectories: boolean,
  limit: number,
  presence: DiscoveryPresenceFilter,
): string {
  const canonical = JSON.stringify({
    version: 1,
    action: input.action,
    cwd: cwd ?? null,
    presence,
    includeSubdirectories,
    limit,
    sessionIds: input.sessionIds === undefined ? null : [...input.sessionIds].sort(compareString),
    selfAddress: input.selfAddress,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function continuationArguments(
  input: RelayDiscoveryInput,
  cursor: string,
  limit: number,
  cwd: string | undefined,
  includeSubdirectories: boolean,
): Record<string, unknown> {
  const args: Record<string, unknown> = { action: input.action, limit, cursor };
  if (input.cwd !== undefined) args.cwd = input.cwd;
  if (input.sessionIds !== undefined) args.sessionIds = [...input.sessionIds];
  if (input.presence !== undefined) args.presence = input.presence;
  if (cwd !== undefined) args.includeSubdirectories = includeSubdirectories;
  return args;
}

function statusLine(label: string, ids: readonly string[]): string {
  return ids.length === 0 ? '' : `${label}: ${ids.map((id) => JSON.stringify(id)).join(', ')}`;
}

function rowText(row: RelayDiscoverySession, commonCwd: string | undefined): string {
  const cwd = commonCwd === undefined || row.cwd !== commonCwd ? ` cwd=${JSON.stringify(row.cwd)}` : '';
  return `sessionId=${JSON.stringify(row.sessionId)} address=${JSON.stringify(row.address)} presence=${row.presence} activity=${row.activity} name=${JSON.stringify(row.name)}${cwd}${row.nameTruncated || row.cwdTruncated ? ' [display truncated]' : ''}`;
}

type DetailsBase = Omit<RelayDiscoveryDetails, 'outputBytes' | 'outputTruncated'>;

function measuredResult(text: string, base: DetailsBase, truncated: boolean): RelayDiscoveryResult {
  let outputBytes = 0;
  let details: RelayDiscoveryDetails;
  for (let attempt = 0; attempt < 4; attempt++) {
    details = { ...base, outputBytes, outputTruncated: truncated };
    const measured = Buffer.byteLength(JSON.stringify({ content: [{ type: 'text', text }], details }), 'utf8');
    if (measured === outputBytes) return { text, details };
    outputBytes = measured;
  }
  details = { ...base, outputBytes, outputTruncated: truncated };
  return { text, details };
}

function assertWithinBudget(result: RelayDiscoveryResult, subject: string): void {
  if (result.details.outputBytes > DISCOVERY_OUTPUT_MAX_BYTES)
    throw new Error(
      `Relay discovery cannot fit ${subject} within the ${DISCOVERY_OUTPUT_MAX_BYTES}-byte content/details budget. Narrow sessionIds or filters.`,
    );
}

export function discoverRelaySessions(input: RelayDiscoveryInput): RelayDiscoveryResult {
  validateDiscovery(input);
  const sampledAt = input.now ?? Date.now();
  const limit = input.limit ?? DISCOVERY_DEFAULT_LIMIT;
  const requestedIds = input.sessionIds;
  const cwd = input.action === 'list-cwd' ? (input.cwd ?? input.activeCwd) : input.cwd;
  const filter = effectivePresence(input);
  const includeSubdirectories = cwd !== undefined && input.includeSubdirectories !== false;
  const fingerprint = queryHash(input, cwd, includeSubdirectories, limit, filter);
  const records = listRecords(input.root);
  const prepared = records
    .map((record): PreparedRecord => ({
      record,
      presence: presenceOf(record, sampledAt),
      key: recordKey(record),
    }))
    .sort((left, right) => compareKey(left.key, right.key));
  const requestedSet = requestedIds === undefined ? undefined : new Set(requestedIds);
  const registered =
    requestedSet === undefined
      ? prepared.filter(({ record }) => record.addr !== input.selfAddress)
      : prepared.filter(({ record }) => requestedSet.has(record.sessionId));
  const notRegisteredSessionIds =
    requestedIds === undefined
      ? []
      : requestedIds.filter((id) => !prepared.some(({ record }) => record.sessionId === id));
  const cwdMatches = registered.filter(({ record }) => {
    if (cwd === undefined) return true;
    if (!includeSubdirectories) return record.cwd === cwd;
    const relative = path.relative(path.resolve(cwd), path.resolve(record.cwd));
    return (
      relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
    );
  });
  const selected = cwdMatches.filter(({ presence }) => filterMatches(presence, filter));
  const selectedAddresses = new Set(selected.map(({ record }) => record.addr));
  const excludedSessionIds: RelayDiscoveryExcluded[] = [];
  if (requestedIds !== undefined) {
    for (const sessionId of requestedIds) {
      const matches = registered.filter(({ record }) => record.sessionId === sessionId);
      if (matches.length === 0 || matches.some(({ record }) => selectedAddresses.has(record.addr))) continue;
      const reasons = new Set<'cwd' | 'presence'>();
      for (const match of matches) {
        if (cwd !== undefined && !cwdMatches.includes(match)) reasons.add('cwd');
        else if (!filterMatches(match.presence, filter)) reasons.add('presence');
      }
      if (reasons.size > 0) excludedSessionIds.push({ sessionId, reasons: [...reasons] });
    }
  }

  const cursor = input.cursor === undefined ? undefined : decodeCursor(input.cursor);
  if (cursor !== undefined && cursor.queryHash !== fingerprint)
    throw new Error('Relay discovery cursor does not match these filters. Restart discovery without cursor.');
  const pageCandidates = selected.filter(({ key }) => cursor === undefined || compareKey(key, cursor.after) > 0);
  let rows: RelayDiscoverySession[] = [];
  let lastKey: CursorKey | undefined;
  let byteLimited = false;

  const build = (
    nextRows: readonly RelayDiscoverySession[],
    hasMore: boolean,
    nextKey: CursorKey | undefined,
    truncated: boolean,
  ): RelayDiscoveryResult => {
    const nextCursor =
      hasMore && nextKey !== undefined
        ? encodeCursor({ version: 1, queryHash: fingerprint, after: nextKey })
        : undefined;
    if (nextCursor !== undefined && nextCursor.length > 4096)
      throw new Error(
        "Relay discovery cannot encode this record's identity in a valid continuation cursor. Narrow sessionIds or filters to a single page.",
      );
    const base: DetailsBase = {
      outcome: 'success',
      action: input.action,
      count: selected.length,
      total: selected.length,
      returned: nextRows.length,
      sampledAt,
      sessions: nextRows,
      notRegisteredSessionIds,
      excludedSessionIds,
      excludedCount: excludedSessionIds.length,
      hasMore,
      ...(nextCursor === undefined
        ? {}
        : {
            nextCursor,
            nextArguments: continuationArguments(input, nextCursor, limit, cwd, includeSubdirectories),
          }),
    };
    const lines = [
      `Relay discovery ${input.action}: ${nextRows.length} returned, ${selected.length} matching, sampledAt=${sampledAt}${cwd === undefined ? '' : `, ${includeSubdirectories ? 'cwd subtree' : 'cwd'}=${JSON.stringify(sanitizeDisplay(cwd).value)}`}.`,
      ...nextRows.map((row) => rowText(row, cwd === undefined ? undefined : sanitizeDisplay(cwd).value)),
      ...(filter === 'online' && input.presence === undefined && requestedIds === undefined
        ? ['Use presence=all or presence=offline to find archived sessions, or sessionIds for an exact lookup.']
        : []),
      statusLine('Not registered sessionIds', notRegisteredSessionIds),
      statusLine(
        'Registered but excluded sessionIds',
        excludedSessionIds.map(({ sessionId }) => sessionId),
      ),
    ].filter(Boolean);
    if (nextCursor !== undefined)
      lines.push(
        `More sessions available. Continue with ${JSON.stringify(continuationArguments(input, nextCursor, limit, cwd, includeSubdirectories))}.`,
      );
    if (nextRows.length === 0 && notRegisteredSessionIds.length === 0 && excludedSessionIds.length === 0)
      lines.push('No sessions match this discovery scope.');
    return measuredResult(lines.join('\n'), base, truncated);
  };

  for (const candidate of pageCandidates.slice(0, limit)) {
    const name = sanitizeDisplay(candidate.record.name);
    const displayCwd = sanitizeDisplay(candidate.record.cwd);
    const row: RelayDiscoverySession = {
      sessionId: candidate.record.sessionId,
      address: candidate.record.addr,
      name: name.value,
      cwd: displayCwd.value,
      nameTruncated: name.truncated,
      cwdTruncated: displayCwd.truncated,
      presence: candidate.presence,
      activity: candidate.record.status,
      sampledAt,
    };
    const nextRows = [...rows, row];
    const hasMore = pageCandidates.length > nextRows.length;
    const proposed = build(nextRows, hasMore, candidate.key, false);
    if (proposed.details.outputBytes > DISCOVERY_OUTPUT_MAX_BYTES) {
      if (rows.length === 0) assertWithinBudget(proposed, 'the first exact session identity');
      byteLimited = true;
      break;
    }
    rows = nextRows;
    lastKey = candidate.key;
  }

  const result = build(rows, pageCandidates.length > rows.length, lastKey, byteLimited);
  assertWithinBudget(result, rows.length === 0 ? 'required discovery metadata' : 'this discovery page');
  if (pageCandidates.length > 0 && rows.length === 0)
    throw new Error(
      'Relay discovery could not emit a row or an advancing cursor within the output budget. Narrow the filters.',
    );
  return result;
}

/** Validate direct calls too, before reading any registry state. */
export function validateDiscovery(input: RelayDiscoveryArguments): void {
  if (input.action !== 'list' && input.action !== 'list-cwd') throw new Error('Discovery requires list or list-cwd.');
  if (input.limit !== undefined && (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100))
    throw new Error('limit must be an integer from 1 to 100.');
  if (input.cwd !== undefined && (typeof input.cwd !== 'string' || !input.cwd.trim() || input.cwd.length > 4096))
    throw new Error('cwd must be a nonempty path of at most 4096 characters.');
  if (input.includeSubdirectories !== undefined && typeof input.includeSubdirectories !== 'boolean')
    throw new Error('includeSubdirectories must be boolean.');
  if (input.presence !== undefined && !['all', 'online', 'live', 'stalled', 'offline'].includes(input.presence))
    throw new Error('presence must be all, online, live, stalled, or offline.');
  if (
    input.sessionIds !== undefined &&
    (!Array.isArray(input.sessionIds) ||
      input.sessionIds.length < 1 ||
      input.sessionIds.length > 64 ||
      input.sessionIds.some((id) => typeof id !== 'string' || !id.trim() || id !== id.trim() || id.length > 256) ||
      new Set(input.sessionIds).size !== input.sessionIds.length)
  )
    throw new Error('sessionIds must contain 1 to 64 unique, exact, nonempty IDs of at most 256 characters.');
  if (input.cursor !== undefined && (typeof input.cursor !== 'string' || !input.cursor || input.cursor.length > 4096))
    throw new Error('Invalid relay discovery cursor. Restart discovery without cursor.');
}
