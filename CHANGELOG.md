# CHANGELOG

## Unreleased (v5.0.0)

### Breaking changes

* Dropped support for Node.js versions older than `^20.15.0 || >=22.2.0`
* Dropped callback support in async API:s, only supporting promises going forward.
* Converted to ESM with `SecurePassword` as a named export
* `SecurePassword` now needs to be created with `new`, eg `new SecurePassword()`
* Constants are their own named exports rather than static properties

### Changes

* Added type declarations
* Upgraded to `sodium-native` v5.x
* Dropped `nanoassert`

### Internal changes

* Swapped `tape` for `node:test`
* Added more tests
* Mapped the boilerplate setup to that of [voxpelli/node-module-template](https://github.com/voxpelli/node-module-template)

## v4.0.0

* Dropped support for Node.js versions older than 10
* Upgraded to `sodium-native` v3.x

## v3.0.0

* `libsodium` has changed the default algorithm from `argon2i` to the safer
  `argon2id`. This also means the parameter constants will have changed since
  they now are in adjusted to `argon2id`. Upgrading will still verify passwords
  for `argon2i`, but returns `VALID_NEEDS_REHASH`
* The enums `INVALID_UNRECOGNIZED_HASH`, `INVALID`, `VALID` and
  `VALID_NEEDS_REHASH` are now `Symbol`s to avoid bugs stemming form invalid
  checks.
