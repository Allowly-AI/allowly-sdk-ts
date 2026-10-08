# Changelog

## 0.6.1

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require `@allowly/verifier ^4.3.0` from npm for the new
  `confirmation.resolve` event on receipt wire format 4.
