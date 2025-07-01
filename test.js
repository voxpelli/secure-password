/* eslint-disable n/no-sync */

import test from 'node:test'
import { SecurePassword } from './index.js'

/** @import { TestContext } from 'node:test' */

test('Can hash password sync', /** @param {TestContext} t */ (t) => {
  const pwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')
  const passwordHash = pwd.hashSync(userPassword)

  t.assert.ok(!userPassword.equals(passwordHash))
})

test('Can hash password using promises', /** @param {TestContext} t */ async (t) => {
  const pwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')
  const passwordHash = await pwd.hash(userPassword)

  t.assert.ok(!userPassword.equals(passwordHash))
})

test('Can hash password async simultaneous', /** @param {TestContext} t */ async (t) => {
  t.plan(4)
  const pwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')
  const [hash1, hash2] = await Promise.all([
    pwd.hash(userPassword),
    pwd.hash(userPassword),
  ])

  t.assert.ok(!userPassword.equals(hash1))
  t.assert.ok(!userPassword.equals(hash2))
  t.assert.ok(Buffer.isBuffer(hash1))
  t.assert.ok(Buffer.isBuffer(hash2))
})

test('Can verify password (identity) sync', /** @param {TestContext} t */ (t) => {
  const pwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')
  const passwordHash = pwd.hashSync(userPassword)

  t.assert.strictEqual(pwd.verifySync(userPassword, passwordHash), SecurePassword.VALID)
})

test('Can verify password (identity) using promises', /** @param {TestContext} t */ async (t) => {
  const pwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')
  const passwordHash = await pwd.hash(userPassword)
  const bool = await pwd.verify(userPassword, passwordHash)

  t.assert.strictEqual(bool, SecurePassword.VALID)
})

test('Needs rehash sync', /** @param {TestContext} t */ (t) => {
  const weakPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')
  const wrongPassword = Buffer.from('my secret 2')
  const pass = Buffer.from('hello world')
  const empty = Buffer.from('')
  const argon2ipass = Buffer.from('JGFyZ29uMmkkdj0xOSRtPTMyNzY4LHQ9NCxwPTEkYnB2R2dVNjR1Q3h4TlF2aWYrd2Z3QSR3cXlWL1EvWi9UaDhVNUlaeEFBN0RWYjJVMWtLSG01VHhLOWE2QVlkOUlVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')
  const argon2ipassempty = Buffer.from('JGFyZ29uMmkkdj0xOSRtPTMyNzY4LHQ9NCxwPTEkN3dZV0EvbjBHQjRpa3lwSWN5UVh6USRCbjd6TnNrcW03aWNwVGNjNGl6WC9xa0liNUZBQnZVNGw2MUVCaTVtaWFZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')
  const weakHash = weakPwd.hashSync(userPassword)
  const weakValid = weakPwd.verifySync(userPassword, weakHash)

  t.assert.strictEqual(weakValid, SecurePassword.VALID)
  t.assert.notStrictEqual(weakValid, SecurePassword.INVALID)
  t.assert.notStrictEqual(weakValid, SecurePassword.VALID_NEEDS_REHASH)

  const weakInvalid = weakPwd.verifySync(wrongPassword, weakHash)

  t.assert.notStrictEqual(weakInvalid, SecurePassword.VALID)
  t.assert.strictEqual(weakInvalid, SecurePassword.INVALID)
  t.assert.notStrictEqual(weakInvalid, SecurePassword.VALID_NEEDS_REHASH)

  const betterPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT + 1024,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT + 1,
  })

  const rehashValid = betterPwd.verifySync(userPassword, weakHash)

  t.assert.notStrictEqual(rehashValid, SecurePassword.VALID)
  t.assert.notStrictEqual(rehashValid, SecurePassword.INVALID)
  t.assert.strictEqual(rehashValid, SecurePassword.VALID_NEEDS_REHASH)

  const rehashValidAlgo = betterPwd.verifySync(pass, argon2ipass)

  t.assert.notStrictEqual(rehashValidAlgo, SecurePassword.VALID)
  t.assert.notStrictEqual(rehashValidAlgo, SecurePassword.INVALID)
  t.assert.strictEqual(rehashValidAlgo, SecurePassword.VALID_NEEDS_REHASH)

  const rehashValidAlgoEmpty = betterPwd.verifySync(empty, argon2ipassempty)

  t.assert.notStrictEqual(rehashValidAlgoEmpty, SecurePassword.VALID)
  t.assert.notStrictEqual(rehashValidAlgoEmpty, SecurePassword.INVALID)
  t.assert.strictEqual(rehashValidAlgoEmpty, SecurePassword.VALID_NEEDS_REHASH)

  const betterHash = betterPwd.hashSync(userPassword)
  const betterValid = betterPwd.verifySync(userPassword, betterHash)

  t.assert.strictEqual(betterValid, SecurePassword.VALID)
  t.assert.notStrictEqual(betterValid, SecurePassword.INVALID)
  t.assert.notStrictEqual(betterValid, SecurePassword.VALID_NEEDS_REHASH)

  const betterInvalid = betterPwd.verifySync(wrongPassword, betterHash)

  t.assert.notStrictEqual(betterInvalid, SecurePassword.VALID)
  t.assert.strictEqual(betterInvalid, SecurePassword.INVALID)
  t.assert.notStrictEqual(betterInvalid, SecurePassword.VALID_NEEDS_REHASH)
})

test('Can handle invalid hash sync', /** @param {TestContext} t */ (t) => {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

  const unrecognizedHash = pwd.verifySync(userPassword, invalidHash)

  t.assert.strictEqual(unrecognizedHash, SecurePassword.INVALID_UNRECOGNIZED_HASH)
  t.assert.notStrictEqual(unrecognizedHash, SecurePassword.INVALID)
  t.assert.notStrictEqual(unrecognizedHash, SecurePassword.VALID)
  t.assert.notStrictEqual(unrecognizedHash, SecurePassword.VALID_NEEDS_REHASH)
})

test('Can handle invalid hash async', /** @param {TestContext} t */ async (t) => {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

  const unrecognizedHash = await pwd.verify(userPassword, invalidHash)

  t.assert.strictEqual(unrecognizedHash, SecurePassword.INVALID_UNRECOGNIZED_HASH)
  t.assert.notStrictEqual(unrecognizedHash, SecurePassword.INVALID)
  t.assert.notStrictEqual(unrecognizedHash, SecurePassword.VALID)
  t.assert.notStrictEqual(unrecognizedHash, SecurePassword.VALID_NEEDS_REHASH)
})

test('Verify async returns INVALID if password is wrong', /** @param {TestContext} t */ async (t) => {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const wrongPassword = Buffer.from('not the secret')

  const passwordHash = await pwd.hash(userPassword)
  const result = await pwd.verify(wrongPassword, passwordHash)

  t.assert.strictEqual(result, SecurePassword.INVALID)
})

test('Verify async returns VALID_NEEDS_REHASH if hash needs rehash', /** @param {TestContext} t */ async (t) => {
  // Create a hash with intentionally lower (weak) parameters...
  const weakPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_MIN, // intentionally as low as allowed
    opslimit: SecurePassword.OPSLIMIT_MIN, // intentionally as low as allowed
  })

  const userPassword = Buffer.from('my secret')
  const weakHash = await weakPwd.hash(userPassword)

  // ...then verify with stricter (stronger) params
  const betterPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT + 1024, // higher than default
    opslimit: SecurePassword.OPSLIMIT_DEFAULT + 1,    // higher than default
  })

  const result = await betterPwd.verify(userPassword, weakHash)

  t.assert.strictEqual(result, SecurePassword.VALID_NEEDS_REHASH)
})

// *** Assert tests ***

test('Verify async throws if passwordBuf is not a Buffer', async (t) => {
  const pwd = new SecurePassword()
  await t.assert.rejects(
    // @ts-expect-error: Intentionally passing a string to test runtime assertion for non-Buffer input
    () => pwd.verify('not-a-buffer', Buffer.alloc(SecurePassword.HASH_BYTES)),
    /passwordBuf must be Buffer/
  )
})

test('Verify async throws if passwordBuf is too short', async (t) => {
  const min = Math.max(0, SecurePassword.PASSWORD_BYTES_MIN - 1)
  if (min > 0) {
    const pwd = new SecurePassword()
    await t.assert.rejects(
      () => pwd.verify(Buffer.alloc(min), Buffer.alloc(SecurePassword.HASH_BYTES)),
      /passwordBuf must be at least PASSWORD_BYTES_MIN/
    )
  }
})

test('Verify async throws if passwordBuf is too long', async (t) => {
  const pwd = new SecurePassword()
  await t.assert.rejects(
    () => pwd.verify(Buffer.alloc(SecurePassword.PASSWORD_BYTES_MAX + 1), Buffer.alloc(SecurePassword.HASH_BYTES)),
    /passwordBuf must be shorter than PASSWORD_BYTES_MAX/
  )
})

test('Verify async throws if hashBuf is not a Buffer', async (t) => {
  const pwd = new SecurePassword()
  await t.assert.rejects(
    // @ts-expect-error: Intentionally passing a string as hashBuf to test runtime assertion for non-Buffer input
    () => pwd.verify(Buffer.alloc(SecurePassword.PASSWORD_BYTES_MIN), 'not-a-buffer'),
    /hashBuf must be Buffer/
  )
})

test('Verify async throws if hashBuf is wrong length', async (t) => {
  const pwd = new SecurePassword()
  await t.assert.rejects(
    () => pwd.verify(Buffer.alloc(SecurePassword.PASSWORD_BYTES_MIN), Buffer.alloc(1)),
    /hashBuf must be HASH_BYTES/
  )
})
