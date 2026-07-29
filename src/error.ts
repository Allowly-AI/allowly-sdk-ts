import type { AllowlyError } from "./types.js";

export class AllowlyAPIError extends Error {
  readonly status: number;
  readonly code: string;
  readonly fields?: AllowlyError["fields"];
  /** Parsed Retry-After response header in seconds, when the API sent one
   * (rate limits, contended idempotent replays). Honor it before retrying. */
  readonly retryAfterSeconds?: number;

  constructor(status: number, error: AllowlyError, retryAfterSeconds?: number) {
    super(error.message);
    this.name = "AllowlyAPIError";
    this.status = status;
    this.code = error.code;
    this.fields = error.fields;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class AllowlyProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AllowlyProtocolError";
  }
}
