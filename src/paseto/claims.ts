import { ClaimError } from '../errors.js';

export interface Validate {
  /** Reject if `exp` is in the past. */
  exp?: boolean;
  /** Reject if `nbf` is in the future. */
  nbf?: boolean;
  /** Require `iss` to equal this value. */
  iss?: string;
  /** Require `aud` to equal this value. */
  aud?: string;
  /** Require `sub` to equal this value. */
  sub?: string;
  /** Allowed clock skew in seconds for exp/nbf (default 0). */
  clockToleranceSec?: number;
}

// Validates registered claims on a decoded object payload. Times are ISO-8601
// strings per the PASETO registered-claims convention.
export function validateClaims(
  payload: Record<string, unknown>,
  v: Validate,
  now: number = Date.now(),
): void {
  const tol = (v.clockToleranceSec ?? 0) * 1000;
  if (v.exp && typeof payload.exp === 'string') {
    if (now - tol > Date.parse(payload.exp)) throw new ClaimError('exp', 'token expired');
  }
  if (v.nbf && typeof payload.nbf === 'string') {
    if (now + tol < Date.parse(payload.nbf)) throw new ClaimError('nbf', 'token not yet valid');
  }
  for (const c of ['iss', 'aud', 'sub'] as const) {
    if (v[c] !== undefined && payload[c] !== v[c]) throw new ClaimError(c, `${c} mismatch`);
  }
}
