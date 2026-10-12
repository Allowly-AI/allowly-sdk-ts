# Changelog

## 0.7.0 (local, unpublished)

- Use verifier 5.0.0 and receipt wire 5 only, preserving the original signed
  JWS envelope for verification. This breaking rebuild removes wire-4 parsing.
- Create grants from exact immutable policy editions. Support action choices,
  decision precedence, OR conditions and list operators in the typed policy API.
- Continue native Execute reviews using the original operation and saved request;
  status and verified resolution webhooks wake saved jobs but do not authorize
  or dispatch an action. Pending or rejected reviews never send.
- Keep the sibling-source verifier dependency for local testing. Publication
  requires verifier 5.0.0 on npm, then regenerated registry-backed dependencies
  and locks; the publish workflow derives the checked release from the manifest.

## 0.6.1

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require `@allowly/verifier ^4.3.0` from npm for the new
  `confirmation.resolve` event on receipt wire format 4.
