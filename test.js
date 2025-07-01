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

  t.assert.ok(pwd.verifySync(userPassword, passwordHash) === SecurePassword.VALID)
})

test('Can verify password (identity) using promises', /** @param {TestContext} t */ async (t) => {
  const pwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')
  const passwordHash = await pwd.hash(userPassword)
  const bool = await pwd.verify(userPassword, passwordHash)

  t.assert.ok(bool === SecurePassword.VALID)
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

  t.assert.ok(weakValid === SecurePassword.VALID)
  t.assert.ok(weakValid !== SecurePassword.INVALID)
  t.assert.ok(weakValid !== SecurePassword.VALID_NEEDS_REHASH)

  const weakInvalid = weakPwd.verifySync(wrongPassword, weakHash)

  t.assert.ok(weakInvalid !== SecurePassword.VALID)
  t.assert.ok(weakInvalid === SecurePassword.INVALID)
  t.assert.ok(weakInvalid !== SecurePassword.VALID_NEEDS_REHASH)

  const betterPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT + 1024,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT + 1,
  })

  const rehashValid = betterPwd.verifySync(userPassword, weakHash)

  t.assert.ok(rehashValid !== SecurePassword.VALID)
  t.assert.ok(rehashValid !== SecurePassword.INVALID)
  t.assert.ok(rehashValid === SecurePassword.VALID_NEEDS_REHASH)

  const rehashValidAlgo = betterPwd.verifySync(pass, argon2ipass)

  t.assert.ok(rehashValidAlgo !== SecurePassword.VALID)
  t.assert.ok(rehashValidAlgo !== SecurePassword.INVALID)
  t.assert.ok(rehashValidAlgo === SecurePassword.VALID_NEEDS_REHASH)

  const rehashValidAlgoEmpty = betterPwd.verifySync(empty, argon2ipassempty)

  t.assert.ok(rehashValidAlgoEmpty !== SecurePassword.VALID)
  t.assert.ok(rehashValidAlgoEmpty !== SecurePassword.INVALID)
  t.assert.ok(rehashValidAlgoEmpty === SecurePassword.VALID_NEEDS_REHASH)

  const betterHash = betterPwd.hashSync(userPassword)
  const betterValid = betterPwd.verifySync(userPassword, betterHash)

  t.assert.ok(betterValid === SecurePassword.VALID)
  t.assert.ok(betterValid !== SecurePassword.INVALID)
  t.assert.ok(betterValid !== SecurePassword.VALID_NEEDS_REHASH)

  const betterInvalid = betterPwd.verifySync(wrongPassword, betterHash)

  t.assert.ok(betterInvalid !== SecurePassword.VALID)
  t.assert.ok(betterInvalid === SecurePassword.INVALID)
  t.assert.ok(betterInvalid !== SecurePassword.VALID_NEEDS_REHASH)
})

test('Can handle invalid hash sync', /** @param {TestContext} t */ (t) => {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

  const unrecognizedHash = pwd.verifySync(userPassword, invalidHash)

  t.assert.ok(unrecognizedHash === SecurePassword.INVALID_UNRECOGNIZED_HASH)
  t.assert.ok(unrecognizedHash !== SecurePassword.INVALID)
  t.assert.ok(unrecognizedHash !== SecurePassword.VALID)
  t.assert.ok(unrecognizedHash !== SecurePassword.VALID_NEEDS_REHASH)
})

test('Can handle invalid hash async', /** @param {TestContext} t */ async (t) => {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

  const unrecognizedHash = await pwd.verify(userPassword, invalidHash)

  t.assert.ok(unrecognizedHash === SecurePassword.INVALID_UNRECOGNIZED_HASH)
  t.assert.ok(unrecognizedHash !== SecurePassword.INVALID)
  t.assert.ok(unrecognizedHash !== SecurePassword.VALID)
  t.assert.ok(unrecognizedHash !== SecurePassword.VALID_NEEDS_REHASH)
})
