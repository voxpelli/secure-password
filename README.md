# `secure-password`

> Making Password storage safer for all

## Breaking changes in v5

- Only supports Node.js `^20.15.0 || >=22.2.0` and later.
- Only supports ESM (`import { SecurePassword } from 'secure-password'`).
- All async APIs are now Promise-only (no callback support).
- `SecurePassword` must be constructed with `new`.
- Constants are named exports, not static properties.

## Features

- State of the art password hashing algorithm (Argon2id, via sodium-native)
- Safe, modern defaults for most applications
- Future-proof: easily upgrade work factors and algorithms
- `Buffer`-only API for safe memory handling
- 100% code and type coverage, robust error handling

## Install

```sh
npm install secure-password
```

## Usage

```js
import {
  SecurePassword,
  INVALID_UNRECOGNIZED_HASH,
  INVALID,
  VALID_NEEDS_REHASH,
  VALID,
} from 'secure-password'

const pwd = new SecurePassword()
const userPassword = Buffer.from('my secret password')

// Generate user password hash and save somewhere
const hash = await pwd.hash(userPassword)

// ... later somewhere else in the code:

// Validate provided password against a hash
const result = await pwd.verify(userPassword, hash)

switch (result) {
  case INVALID_UNRECOGNIZED_HASH:
    throw new Error('This hash was not made with secure-password. Attempt legacy algorithm')
    break
  case INVALID:
    throw new Error('Invalid password')
    break
  case VALID:
    console.log('Authenticated')
    break
  case VALID_NEEDS_REHASH:
    console.log('Authenticated, but needs rehash')

    try {
    // We can only rehash when we have the userPassword at hands,
    // so we should seize the opportunity...
      const improvedHash = await pwd.hash(userPassword)
      // ...and replace the old hash with the improvedHash where its stored
    } catch (err) {
      console.error('You are authenticated, but we could not improve your safety this time around')
    }
    break
}
```


## Types

Type definitions are generated when published.
All result symbols and options are typed.


## API

### `new SecurePassword([opts])`

Make a new instance of `SecurePassword` which will contain your settings. You
can view this as a password policy for your application. `opts` takes the
following keys:

```js
// Initialise our password policy (these are the defaults)
const pwd = new SecurePassword({
  memlimit: MEMLIMIT_DEFAULT,
  opslimit: OPSLIMIT_DEFAULT,
})
```

- `memlimit` (number, default: `MEMLIMIT_DEFAULT`)
  - Memory limit for Argon2id in bytes. Higher is safer, but slower.
- `opslimit` (number, default: `OPSLIMIT_DEFAULT`)
  - Number of Argon2id iterations. Higher is safer, but slower.

They're both constrained by the constants `MEMLIMIT_MIN` to `MEMLIMIT_MAX` and
`OPSLIMIT_MIN` to `OPSLIMIT_MAX`. If not provided, they will be given the default
values `MEMLIMIT_DEFAULT` and `OPSLIMIT_DEFAULT` which should be fast enough for
a general purpose web server without your users noticing too much of a load time.

However, you should set these as high as possible to make any kind of cracking as
costly as possible. A load time of 1s seems reasonable for login, so test various
settings in your production environment.

The settings can be easily increased at a later time as hardware most likely
improves (Moore's law) and adversaries therefore get more powerful.

If a hash is attempted verified with weaker parameters than your current settings,
you get a special return code signalling that you need to rehash the plaintext
password according to the updated policy.

In contrast to other modules, this module will not increase these settings
automatically as this can have ill effects on services that are not carefully
monitored.

### `await pwd.hash(passwordBuf)`

Takes Buffer `passwordBuf` and hashes it. Returns a Buffer with the hash.
The hashing is done by a seperate worker as to not block the event loop,
so normal execution and I/O can continue. The callback is invoked with a
potential error, or the Buffer `hash`.

- `passwordBuf` must be a Buffer of length between `PASSWORD_BYTES_MIN` and
  `PASSWORD_BYTES_MAX`.
- Returns a Buffer of length `HASH_BYTES`.
- Throws if input is invalid or hashing encounters an error.

### `pwd.hashSync(passwordBuf)`

Same as `pwd.hash()`, but the hashing is done on the same thread as
the event loop, therefore normal execution and I/O will be blocked.

### `await pwd.verify(passwordBuf, hashBuf)`


Takes `passwordBuf`, hashes it and then safely compares it to the `hashBuf`.
The hashing is done by a seperate worker as to not block the event loop, so
normal execution and I/O can continue.

Returns one of the symbols `INVALID`, `VALID`, `VALID_NEEDS_REHASH` or `INVALID_UNRECOGNIZED_HASH`.

If `VALID_NEEDS_REHASH` is returned you should call `pwd.hash(passwordBuf)` to
generate a new hash and replace the old hash with the new one in your persistent
storage.

> [!TIP]
> Be careful not to introduce a bug where a user trying to login multiple times,
> successfully, in quick succession, makes your server do unnecessary work.

- `passwordBuf` must be a Buffer of length between `PASSWORD_BYTES_MIN` and
  `PASSWORD_BYTES_MAX`.
- `hashBuf` must be a Buffer of length `HASH_BYTES`.
- Throws if input is invalid or verification encounters an error.

### `pwd.verifySync(passwordBuf, hashBuf)`

Same as `pwd.verify()`, but the verification is done on the same thread as
the event loop, therefore normal execution and I/O will be blocked.

### Constants

All constants are named exports:
- `HASH_BYTES`, `PASSWORD_BYTES_MIN`, `PASSWORD_BYTES_MAX`,
  `MEMLIMIT_MIN`, `MEMLIMIT_MAX`, `OPSLIMIT_MIN`, `OPSLIMIT_MAX`,
  `MEMLIMIT_DEFAULT`, `OPSLIMIT_DEFAULT`

### Verification result symbols

- `VALID`: Password is correct
- `VALID_NEEDS_REHASH`: Password is correct, but hash should be upgraded
- `INVALID`: Password is incorrect
- `INVALID_UNRECOGNIZED_HASH`: Hash is not recognized as secure-password

### `VALID`

The password was verified and is valid

### `INVALID`

The password was invalid

### `VALID_NEEDS_REHASH`

The password was verified and is valid, but needs to be rehashed with new
parameters

### `INVALID_UNRECOGNIZED_HASH`

The hash was unrecognized and therefore could not be verified.
As an implementation detail it is currently very cheap to attempt verifying
unrecognized hashes, since this only requires some lightweight pattern matching.

### `HASH_BYTES`

Size of the `hash` Buffer returned by `hash` and `hashSync` and used by `verify`
and `verifySync`.

### `PASSWORD_BYTES_MIN`

Minimum length of the `password` Buffer.

### `PASSWORD_BYTES_MAX`

Maximum length of the `password` Buffer.

### `MEMLIMIT_MIN`

Minimum value for the `opts.memlimit` option.

### `MEMLIMIT_MAX`

Maximum value for the `opts.memlimit` option.

### `OPSLIMIT_MIN`

Minimum value for the `opts.opslimit` option.

### `OPSLIMIT_MAX`

Maximum value for the `opts.opslimit` option.

### `MEMLIMIT_DEFAULT`

Default value for the `opts.memlimit` option.

### `OPSLIMIT_DEFAULT`

Minimum value for the `opts.opslimit` option.

## Credits

I want to thank [Tom Streller](https://github.com/scan) for donating the package
name on npm. The `<1.0.0` versions that he had written and published to npm can
still be downloaded and the source is available in his [`scan/secure-password` repository](https://github.com/scan/secure-password)

## License

[ISC](LICENSE.md)
