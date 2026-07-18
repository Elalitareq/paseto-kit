import { b64uDecode } from './b64.js';
import { FormatError } from '../errors.js';

export interface SplitToken {
  header: string;
  purpose: 'local' | 'public';
  body: Uint8Array;
  footer: Uint8Array;
}

export function splitToken(token: string): SplitToken {
  const parts = token.split('.');
  if (parts.length !== 3 && parts.length !== 4) throw new FormatError('invalid token structure');
  const version = parts[0];
  const purpose = parts[1];
  if (version !== 'v4') throw new FormatError('unsupported version');
  if (purpose !== 'local' && purpose !== 'public') throw new FormatError('unsupported purpose');
  return {
    header: `${version}.${purpose}.`,
    purpose,
    body: b64uDecode(parts[2]!),
    footer: parts[3] !== undefined ? b64uDecode(parts[3]) : new Uint8Array(),
  };
}
