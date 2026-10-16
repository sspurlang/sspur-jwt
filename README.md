# jwt

JSON Web Tokens (RFC 7519) as compact JWS (RFC 7515), signed and verified with HS256, HS384, HS512 (RFC 7518) or EdDSA over Ed25519 (RFC 8037), with JWK and JWK set support (RFC 7517, RFC 7638 thumbprints). It follows the JWT best current practices of RFC 8725:

- Keys are typed and bound to one algorithm. The `alg` in a token's header only chooses among the keys and the algorithms you allow; it is never trusted on its own, so an HMAC key can't verify an EdDSA token and a public key can't be used as an HMAC secret (algorithm confusion).
- `none` (in any case) and unimplemented algorithms are refused, as are unknown `crit` extensions, unencoded payloads (`b64: false`), JWE, non-canonical base64url (padding, stray characters, nonzero trailing bits), headers and payloads that aren't JSON objects, duplicate member names, and tokens over a size limit (8192 characters by default).
- HMAC keys must be at least as long as the hash (RFC 7518 section 3.2), checked when the key is made and again when it is used.
- Claims (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, `typ`) are checked against a time you pass in, with a leeway, a maximum age, accepted issuers and audiences, a pinned subject and required claims. `verify_now` reads the clock.

## Install

```console
$ sspur add jwt
```

## Example

```sspur
type Access = {sub: Str, scope: Str}

fn main() -> Unit ! log, rand
= do
  issuer = jwt.with_kid(jwt.generate_ed25519_key(), "2026-10")
  now = 1760000000
  c = jwt.claims() with iss := some("https://auth.example.com"), sub := some("user-42"), aud := ["api"], iat := some(now), exp := some(now + 900)
  token = jwt.sign(issuer, c, [("scope", jwt.jstr("notes:read notes:write"))]).or("")
  log("token has {token.split(".").len} parts, header {jwt.decode_unverified(token, 8192).map(j => jwt.json_text(j.header))}")
  published = jwt.public_jwks([issuer])
  log(published.take(60) + "...")
  keys = jwt.parse_jwks(published).or([])
  p = jwt.policy([jwt.EdDSA]) with issuers := ["https://auth.example.com"], audiences := ["api"], leeway := 30
  match jwt.verify(token, keys, p, now + 60)
  | ok(t) => log("verified {t.claims.sub}, scopes {jwt.claim_strs(t, "scope")}, typed {json.decode[Access](t.text)}")
  | err(e) => log("refused: {e}")
  log("later: {jwt.verify(token, keys, p, now + 2000).map(t => t.claims.sub)}")
  log("other audience: {jwt.verify(token, keys, p with audiences := ["billing"], now).map(t => t.claims.sub)}")
  forged = "eyJhbGciOiJub25lIn0." + token.split(".")[1] + "."
  log("alg none: {jwt.verify(forged, keys, p, now).map(t => t.claims.sub)}")
  hs = jwt.hmac_key(jwt.HS384, secret(crypto.random(48)))
  log("HS384: {hs.map(k => jwt.sign(k, c, []).map(t => jwt.verify(t, [k], jwt.policy([jwt.HS384]), now).is_ok))}")
  log("short key: {jwt.hmac_key(jwt.HS256, secret("too short".to_bytes)).map(k => jwt.key_alg(k))}")
```

```console
$ sspur run main.ssp
token has 3 parts, header ok("{\"alg\":\"EdDSA\",\"kid\":\"2026-10\",\"typ\":\"JWT\"}")
{"keys":[{"kty":"OKP","crv":"Ed25519","x":"4hSmEzGPbFSEvATPR...
verified some("user-42"), scopes some(["notes:read", "notes:write"]), typed ok(Access{sub: "user-42", scope: "notes:read notes:write"})
later: err(Expired{exp: 1760000900, now: 1760002000})
other audience: err(WrongAudience{aud: ["api"]})
alg none: err(UnsupportedAlg{alg: "none"})
HS384: ok(ok(true))
short key: err(InvalidKey{why: "an HS256 key must be at least 32 bytes"})
```

(`sspur` also prints one `audit A_DECLASSIFY` line for jwt's HMAC-SHA-384, the one place the package declassifies a value: the HMAC tag it computes from a secret key.)

In an `http.serve` handler: `jwt.bearer_token(req)` reads `Authorization: Bearer`, then `jwt.verify_now(token, keys, policy)`. Decode your own claims with `json.decode[MyClaims](t.text)`.

## API

### Keys

| Definition | What it is |
|---|---|
| `Alg` | `HS256`, `HS384`, `HS512`, `EdDSA` |
| `alg_name(a)`, `alg_of(name)`, `all_algs()` | Header names (case-sensitive; `none` is not an algorithm) |
| `Key` | `HmacKey`, `EdSigningKey` or `EdVerifyingKey`, each bound to one algorithm, with an optional `kid` (holds secrets, so no `Eq`/`Show`) |
| `hmac_key(alg, secret)` | Checks the length: 32, 48 or 64 bytes at least |
| `ed25519_signing_key(seed)`, `ed25519_verifying_key(x)` | From the 32-byte seed (JWK `d`) or public key (JWK `x`) |
| `generate_hmac_key(alg)`, `generate_ed25519_key()` | Random keys (`! rand`) |
| `with_kid(k, kid)`, `key_id(k)`, `key_alg(k)`, `can_sign(k)` | Key ids and properties |
| `verifying_key(k)`, `public_bytes(k)` | The shareable half of an Ed25519 key (none for HMAC) |
| `select_keys(keys, kid, alg)` | The keys a token with that `alg` and `kid` may be verified with |

### Verifying

| Definition | What it is |
|---|---|
| `Policy`, `policy(algs)` | Allowed algorithms, `leeway`, `max_age`, `issuers`, `audiences`, `subject`, `typ`, `required` claims, understood `critical` extensions, `max_len` |
| `verify(token, keys, p, now)` | Signature, then payload, then claims; gives a `Token` |
| `verify_now(token, keys, p)` | The same at the current time (`! time`) |
| `check_claims(t, p, now)` | The claim checks alone, for a decoded token |
| `Token` | `header`, `claims`, `payload` (parsed), `text` (the payload as signed), `alg`, `kid`, `typ` |
| `Claims`, `claims()` | The registered claims; `aud` is always a list |
| `claim(t, n)`, `claim_str`, `claim_int`, `claim_bool`, `claim_strs` | Custom claims; `claim_strs` reads a string or an array, and splits `scope` on spaces |
| `claims_of(json)` | The registered claims of a payload, type-checked |
| `decode_jwt_unverified(token, max_len)` | Decodes without checking anything; never trust it |
| `bearer_token(req)` | The token of `Authorization: Bearer` (RFC 6750) |

### Signing

| Definition | What it is |
|---|---|
| `sign(k, c, extra)` | A JWT with header `alg`, `typ: JWT` and `kid`; payload `c` plus your claims |
| `sign_payload(k, json)` | A JWT whose payload is your own JSON text, such as `json.encode(MyClaims{...})` |
| `claims_json(c, extra)` | The payload `sign` would write |

### JWS (any payload)

| Definition | What it is |
|---|---|
| `jws_sign(k, extra_headers, payload)` | A compact JWS of any text |
| `jws_verify(token, keys, p)` | Verifies a compact JWS with the policy's `algs`, `critical` and `max_len` |
| `sign_compact(k, header, payload)` | Signs with exact header text, for reproducing tokens byte for byte |
| `decode_unverified(token, max_len)` | The header and payload, unchecked |
| `Jws` | `header`, `payload`, `alg`, `kid` |
| `b64url(b)`, `from_b64url(s)` | Unpadded base64url; decoding accepts only the canonical form |

### JWK

| Definition | What it is |
|---|---|
| `parse_jwks(text)` | The verifying keys of a public set; skips RSA, EC, X25519 and keys not for signatures; refuses sets with private material |
| `parse_private_jwks(text)` | Signing keys too: Ed25519 with `d` (checked against `x`) and `oct` keys with their `alg` |
| `parse_jwk(text)` | One key, private parts allowed |
| `public_jwk(k)`, `public_jwks(keys)` | Publish your verifying keys |
| `thumbprint(k)` | RFC 7638 thumbprint of an Ed25519 key |

### Supporting functions

| Definition | What it is |
|---|---|
| `JwtErr` | Every reason a token, key or set was refused: `Malformed`, `TooLarge`, `UnsupportedAlg`, `AlgNotAllowed`, `UnknownCritical`, `NoKey`, `BadSignature`, `Expired`, `NotYetValid`, `IssuedInFuture`, `IssuedTooLongAgo`, `WrongIssuer`, `WrongAudience`, `WrongSubject`, `WrongType`, `MissingClaim`, `BadClaim`, `InvalidKey`, `BadJwks` |
| `JsonValue`, `parse_json(s)`, `json_text(v)`, `member(v, n)`, `json_int(v)`, `jint(n)`, `jstr(s)` | The strict JSON reader the tokens are parsed with (one value, no duplicate members, no lone surrogates, 32 levels) and its writer |
| `sha384(data)`, `hmac_sha384(key, data)` | SHA-384 and HMAC-SHA-384, which HS384 needs and the standard library lacks |

## Security notes

- Always pass the algorithms you expect to `policy`. The header's `alg` must be in that list and match the key's.
- With a `kid` in the header only keys with that id are tried; without one, every key of the token's algorithm is.
- `exp` must be strictly after `now - leeway`; `nbf` at most `now + leeway`; an `iat` in the future (beyond the leeway) is refused.
- `jku`, `x5u` and `jwk` headers are never followed: keys come only from you.
- Test vectors: RFC 7515 A.1 (the exact HS256 token, also RFC 7519 section 3.1), RFC 8037 A.1, A.3 and A.4 (the Ed25519 key, its thumbprint and the exact EdDSA token), FIPS 180-4 SHA-384, RFC 4231 HMAC-SHA-256, -384 and -512 cases. The SHA-384 code is the SHA-512 algorithm, checked against `crypto.sha512` on inputs across every padding boundary, and its constants are recomputed in the tests from the cube and square roots of the primes.

## Out of scope

- RS256/384/512, PS256/384/512 and ES256/384/512: the standard library has no RSA or ECDSA, and this package doesn't implement public-key cryptography of its own. Tokens with these algorithms are refused as `UnsupportedAlg`, and RSA and EC keys in a JWK set are skipped.
- JWE (encrypted tokens), unencoded payloads (RFC 7797), and the JSON (non-compact) serializations.
- Fetching JWK sets over HTTP and caching them: fetch with `http.fetch`, then `parse_jwks`.

## License

MIT. See LICENSE.
