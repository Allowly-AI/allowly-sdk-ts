import type { AllowlyError } from "./types.js";

export class AllowlyAPIError extends Error {
  readonly status: number;
  readonly code: string;
  readonly fields?: AllowlyError["fields"];

  constructor(status: number, error: AllowlyError) {
    super(error.message);
    this.name = "AllowlyAPIError";
    this.status = status;
    this.code = error.code;
    this.fields = error.fields;
  }
}

export class AllowlyProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AllowlyProtocolError";
  }
}
