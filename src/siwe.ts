import { getAddress, recoverMessageAddress } from 'viem';
import {
  ExpiredSignatureError,
  FutureSignatureError,
  InvalidSignatureError,
  MissingAuthError,
  ReplayedNonceError,
} from './errors.js';
import type { NonceStore, ParsedSiwe, SiweEnvelope } from './types.js';

const SIGNATURE_PAST_MS = 5 * 60 * 1000;
const SIGNATURE_FUTURE_SKEW_MS = 10 * 1000;
const NONCE_RECORD_TTL_MS = 10 * 60 * 1000;

// Size limits, checked before anything is parsed. A sign-in message with a statement and a few
// resources is well under 4 KB; the header carries it base64-encoded inside JSON with a signature.
export const MAX_SIWE_MESSAGE_LENGTH = 4096;
export const MAX_AUTHORIZATION_HEADER_LENGTH = 8192;

export function extractEnvelope(authorizationHeader: string | undefined): SiweEnvelope {
  if (!authorizationHeader) throw new MissingAuthError();
  if (authorizationHeader.length > MAX_AUTHORIZATION_HEADER_LENGTH) {
    throw new InvalidSignatureError('authorization header is too long');
  }
  if (authorizationHeader.slice(0, 7).toLowerCase() !== 'wallet ') throw new MissingAuthError();
  const encoded = authorizationHeader.slice(7).trim();
  if (!encoded) throw new MissingAuthError();
  let decoded: string;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf-8');
  } catch {
    throw new InvalidSignatureError('envelope is not valid base64');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    throw new InvalidSignatureError('envelope is not valid JSON');
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    typeof (parsed as Record<string, unknown>).message !== 'string' ||
    typeof (parsed as Record<string, unknown>).signature !== 'string'
  ) {
    throw new InvalidSignatureError('envelope must contain string message and signature');
  }
  return parsed as SiweEnvelope;
}

const HEADER_SUFFIX = ' wants you to sign in with your Ethereum account:';
const FIELD_ORDER = ['URI', 'Version', 'Chain ID', 'Nonce', 'Issued At', 'Expiration Time', 'Not Before', 'Request ID'] as const;
const REQUIRED_FIELDS = ['URI', 'Version', 'Chain ID', 'Nonce', 'Issued At'] as const;

/**
 * Parse an EIP-4361 (Sign-In with Ethereum) message, strictly and in one pass over its lines.
 * Every check is a fixed-shape comparison per line, so the cost is linear in the message length.
 * Refuses: a message over {@link MAX_SIWE_MESSAGE_LENGTH}, a domain with whitespace, an address
 * that is not EIP-55 checksummed, a Version other than 1, fields out of order or repeated,
 * unknown lines, and timestamps that do not parse.
 */
export function parseSiweMessage(message: string): ParsedSiwe {
  if (typeof message !== 'string' || message.length > MAX_SIWE_MESSAGE_LENGTH) {
    throw new InvalidSignatureError('message is too long');
  }
  const lines = message.split('\n');
  const bad = (why: string): never => {
    throw new InvalidSignatureError(why);
  };

  // Line 1: "<domain> wants you to sign in with your Ethereum account:"
  const head = lines[0] ?? '';
  if (!head.endsWith(HEADER_SUFFIX)) bad('message missing EIP-4361 header');
  const domain = head.slice(0, head.length - HEADER_SUFFIX.length);
  if (!domain || /\s/.test(domain)) bad('message missing EIP-4361 header');

  // Line 2: the address, EIP-55 checksummed.
  const address = lines[1] ?? '';
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) bad('message missing EIP-4361 header');
  let checksummed: string;
  try {
    checksummed = getAddress(address);
  } catch {
    return bad('address is not valid');
  }
  if (checksummed !== address) bad('address is not EIP-55 checksummed');

  // Line 3 blank, then an optional statement followed by a blank line.
  if (lines[2] !== '') bad('message is not EIP-4361 formatted');
  let i = 3;
  let statement: string | undefined;
  if (lines[i] !== undefined && !lines[i].startsWith('URI: ')) {
    statement = lines[i];
    if (statement === '') bad('message is not EIP-4361 formatted');
    if (lines[i + 1] !== '') bad('message is not EIP-4361 formatted');
    i += 2;
  }

  // Fields, each at most once and in the order EIP-4361 gives them.
  const fields: Partial<Record<(typeof FIELD_ORDER)[number], string>> = {};
  let next = 0;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line === 'Resources:') {
      for (i++; i < lines.length; i++) {
        if (!lines[i].startsWith('- ') || lines[i].length < 3) bad('message has a malformed resource');
      }
      break;
    }
    const colon = line.indexOf(': ');
    if (colon < 1) bad('message has an unexpected line');
    const label = line.slice(0, colon);
    const value = line.slice(colon + 2);
    const at = FIELD_ORDER.indexOf(label as (typeof FIELD_ORDER)[number]);
    if (at < next) bad(at < 0 ? 'message has an unexpected line' : 'message fields are out of order or repeated');
    if (!value || value !== value.trim()) bad(`message field ${label} is empty or padded`);
    fields[label as (typeof FIELD_ORDER)[number]] = value;
    next = at + 1;
  }

  for (const f of REQUIRED_FIELDS) {
    if (fields[f] === undefined) bad('message missing required EIP-4361 fields');
  }
  if (fields.Version !== '1') bad('message Version must be 1');
  if (!/^[0-9]{1,15}$/.test(fields['Chain ID']!)) bad('chain id is not numeric');
  if (!/^[a-zA-Z0-9]{8,}$/.test(fields.Nonce!)) bad('nonce must be at least 8 letters or digits');
  for (const f of ['Issued At', 'Expiration Time', 'Not Before'] as const) {
    if (fields[f] !== undefined && !Number.isFinite(Date.parse(fields[f]!))) {
      bad(`${f} is not a valid ISO 8601 timestamp`);
    }
  }

  return {
    domain,
    address,
    uri: fields.URI!,
    version: fields.Version!,
    chainId: Number(fields['Chain ID']),
    nonce: fields.Nonce!,
    issuedAt: fields['Issued At']!,
    expirationTime: fields['Expiration Time'],
    notBefore: fields['Not Before'],
    requestId: fields['Request ID'],
    statement,
  };
}

export async function verifySiwe(
  envelope: SiweEnvelope,
  options: {
    nonceStore: NonceStore;
    siweDomain: string;
    now?: () => number;
  },
): Promise<{ wallet: string; parsed: ParsedSiwe }> {
  const parsed = parseSiweMessage(envelope.message);

  const now = options.now ? options.now() : Date.now();
  const issuedAtMs = Date.parse(parsed.issuedAt);
  if (!Number.isFinite(issuedAtMs)) {
    throw new InvalidSignatureError('issuedAt is not a valid ISO 8601 timestamp');
  }
  if (issuedAtMs > now + SIGNATURE_FUTURE_SKEW_MS) throw new FutureSignatureError();
  if (now - issuedAtMs > SIGNATURE_PAST_MS) throw new ExpiredSignatureError();
  // The signer's own limits, when given, are honoured on top of the SDK's window.
  if (parsed.expirationTime !== undefined && now >= Date.parse(parsed.expirationTime)) {
    throw new ExpiredSignatureError();
  }
  if (parsed.notBefore !== undefined && Date.parse(parsed.notBefore) > now + SIGNATURE_FUTURE_SKEW_MS) {
    throw new FutureSignatureError();
  }

  if (parsed.domain !== options.siweDomain) {
    throw new InvalidSignatureError(
      `domain mismatch: signed for '${parsed.domain}', expected '${options.siweDomain}'`,
    );
  }

  let recovered: string;
  try {
    recovered = await recoverMessageAddress({
      message: envelope.message,
      signature: envelope.signature as `0x${string}`,
    });
  } catch (err) {
    throw new InvalidSignatureError(
      err instanceof Error ? err.message : 'signature recovery failed',
    );
  }

  if (recovered.toLowerCase() !== parsed.address.toLowerCase()) {
    throw new InvalidSignatureError('recovered address does not match address in message');
  }

  const accepted = await options.nonceStore.setIfAbsent(parsed.nonce, NONCE_RECORD_TTL_MS);
  if (!accepted) throw new ReplayedNonceError();

  return { wallet: recovered, parsed };
}
