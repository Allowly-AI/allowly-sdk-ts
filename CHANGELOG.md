# Changelog

## 0.9.0

- Submit captured action reports with `observe.submit` and read their status
  with `observe.get`. Observe reports do not authorize or block actions.
- Retain and validate approved policy evidence requirements in the definition
  digest. Normalize malformed native credential import errors.

## 0.8.0

- Use verifier 5.0.0 and receipt wire 5 only, preserving the original signed
  JWS envelope for verification. This breaking rebuild removes wire-4 parsing.
- Create grants from exact immutable policy editions. Support action choices,
  decision precedence, OR conditions and list operators in the typed policy API.
- Continue native Execute reviews using the original operation and saved request;
  status and verified resolution webhooks wake saved jobs but do not authorize
  or dispatch an action. Pending or rejected reviews never send.
- Use the published verifier 5.0.0 with a registry-backed lock. SDK 0.7.0
  remains the earlier wire-4 release; this breaking rebuild uses the next minor.
  The publish workflow checks the public verifier release before publication.

## 0.6.1

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require `@allowly/verifier ^4.3.0` from npm for the new
  `confirmation.resolve` event on receipt wire format 4.
