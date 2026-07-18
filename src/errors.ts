export class PasetoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}
export class FormatError extends PasetoError {}
export class DecryptError extends PasetoError {}
export class VerifyError extends PasetoError {}
export class PaserkError extends PasetoError {}
export class ClaimError extends PasetoError {
  constructor(
    public readonly claim: string,
    message: string,
  ) {
    super(message);
  }
}
