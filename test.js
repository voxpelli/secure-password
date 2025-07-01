import test from 'tape'
import { SecurePassword } from './index.js'

test('Can hash password sync', function (assert) {
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')

  const passwordHash = pwd.hashSync(userPassword)
  assert.notOk(userPassword.equals(passwordHash))
  assert.end()
})

test('Can hash password async', function (assert) {
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')

  pwd.hash(userPassword, function (err, passwordHash) {
    assert.error(err)
    assert.notOk(userPassword.equals(passwordHash))
    assert.end()
  })
})

test('Can hash password using promises', function (assert) {
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')

  pwd.hash(userPassword).then(function (passwordHash) {
    assert.notOk(userPassword.equals(passwordHash))
    assert.end()
  }, assert.error)
})

test('Can hash password async simultanious', function (assert) {
  assert.plan(4)
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secrets')

  pwd.hash(userPassword, function (err, passwordHash) {
    assert.error(err)
    assert.notOk(userPassword.equals(passwordHash))
  })

  pwd.hash(userPassword, function (err, passwordHash) {
    assert.error(err)
    assert.notOk(userPassword.equals(passwordHash))
  })
})

test('Can verify password (identity) sync', function (assert) {
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')

  const passwordHash = pwd.hashSync(userPassword)

  assert.ok(pwd.verifySync(userPassword, passwordHash) === SecurePassword.VALID)
  assert.end()
})

test('Can verify password (identity) async', function (assert) {
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')

  pwd.hash(userPassword, function (err, passwordHash) {
    assert.error(err)
    pwd.verify(userPassword, passwordHash, function (err, bool) {
      assert.error(err)
      assert.ok(bool === SecurePassword.VALID)
      assert.end()
    })
  })
})

test('Can verify password (identity) using promises', function (assert) {
  const pwd = new SecurePassword({
    version: 0,
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const userPassword = Buffer.from('my secret')

  pwd
    .hash(userPassword)
    .then(function (passwordHash) {
      return pwd.verify(userPassword, passwordHash)
    })
    .then(function (bool) {
      assert.ok(bool === SecurePassword.VALID)
      assert.end()
    })
    .catch(assert.error)
})

test('Needs rehash sync', function (assert) {
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
  assert.ok(weakValid === SecurePassword.VALID)
  assert.notOk(weakValid === SecurePassword.INVALID)
  assert.notOk(weakValid === SecurePassword.VALID_NEEDS_REHASH)

  const weakInvalid = weakPwd.verifySync(wrongPassword, weakHash)
  assert.notOk(weakInvalid === SecurePassword.VALID)
  assert.ok(weakInvalid === SecurePassword.INVALID)
  assert.notOk(weakInvalid === SecurePassword.VALID_NEEDS_REHASH)

  const betterPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT + 1024,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT + 1,
  })

  const rehashValid = betterPwd.verifySync(userPassword, weakHash)

  assert.notOk(rehashValid === SecurePassword.VALID)
  assert.notOk(rehashValid === SecurePassword.INVALID)
  assert.ok(rehashValid === SecurePassword.VALID_NEEDS_REHASH)

  const rehashValidAlgo = betterPwd.verifySync(pass, argon2ipass)

  assert.notOk(rehashValidAlgo === SecurePassword.VALID)
  assert.notOk(rehashValidAlgo === SecurePassword.INVALID)
  assert.ok(rehashValidAlgo === SecurePassword.VALID_NEEDS_REHASH)

  const rehashValidAlgoEmpty = betterPwd.verifySync(empty, argon2ipassempty)

  assert.notOk(rehashValidAlgoEmpty === SecurePassword.VALID)
  assert.notOk(rehashValidAlgoEmpty === SecurePassword.INVALID)
  assert.ok(rehashValidAlgoEmpty === SecurePassword.VALID_NEEDS_REHASH)

  const betterHash = betterPwd.hashSync(userPassword)
  const betterValid = betterPwd.verifySync(userPassword, betterHash)
  assert.ok(betterValid === SecurePassword.VALID)
  assert.notOk(betterValid === SecurePassword.INVALID)
  assert.notOk(betterValid === SecurePassword.VALID_NEEDS_REHASH)

  const betterInvalid = betterPwd.verifySync(wrongPassword, betterHash)
  assert.notOk(betterInvalid === SecurePassword.VALID)
  assert.ok(betterInvalid === SecurePassword.INVALID)
  assert.notOk(betterInvalid === SecurePassword.VALID_NEEDS_REHASH)
  assert.end()
})

test('Needs rehash async', function (assert) {
  assert.plan(37)
  const weakPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT,
  })

  const betterPwd = new SecurePassword({
    memlimit: SecurePassword.MEMLIMIT_DEFAULT + 1024,
    opslimit: SecurePassword.OPSLIMIT_DEFAULT + 1,
  })

  const userPassword = Buffer.from('my secret')
  const wrongPassword = Buffer.from('my secret 2')
  const pass = Buffer.from('hello world')
  const empty = Buffer.from('')
  const argon2ipass = Buffer.from('JGFyZ29uMmkkdj0xOSRtPTMyNzY4LHQ9NCxwPTEkYnB2R2dVNjR1Q3h4TlF2aWYrd2Z3QSR3cXlWL1EvWi9UaDhVNUlaeEFBN0RWYjJVMWtLSG01VHhLOWE2QVlkOUlVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')
  const argon2ipassempty = Buffer.from('JGFyZ29uMmkkdj0xOSRtPTMyNzY4LHQ9NCxwPTEkN3dZV0EvbjBHQjRpa3lwSWN5UVh6USRCbjd6TnNrcW03aWNwVGNjNGl6WC9xa0liNUZBQnZVNGw2MUVCaTVtaWFZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'base64')

  weakPwd.hash(userPassword, function (err, weakHash) {
    assert.error(err, 'hash not error')
    weakPwd.verify(userPassword, weakHash, function (err, res) {
      assert.error(err, 'weak right verify not error')
      assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH, 'weak not right unrecognized')
      assert.ok(res === SecurePassword.VALID, 'weak right valid')
      assert.notOk(res === SecurePassword.INVALID, 'weak right not invalid')
      assert.notOk(res === SecurePassword.VALID_NEEDS_REHASH, 'weak right not rehash')
    })

    weakPwd.verify(wrongPassword, weakHash, function (err, res) {
      assert.error(err, 'weak wrong verify not valid')
      assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH, 'weak not right unrecognized')
      assert.notOk(res === SecurePassword.VALID, 'weak wrong not valid')
      assert.ok(res === SecurePassword.INVALID, 'weak wrong invalid')
      assert.notOk(res === SecurePassword.VALID_NEEDS_REHASH, 'weak wrong not rehash')
    })

    betterPwd.verify(userPassword, weakHash, function (err, res) {
      assert.error(err, 'weak right not error')
      assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH, 'weak not right unrecognized')
      assert.notOk(res === SecurePassword.VALID, 'weak right not valid')
      assert.notOk(res === SecurePassword.INVALID, 'weak right not invald')
      assert.ok(res === SecurePassword.VALID_NEEDS_REHASH, 'weak right rehash')
    })

    weakPwd.verify(pass, argon2ipass, function (err, res) {
      assert.error(err, 'weak right not error')
      assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH, 'weak not right unrecognized')
      assert.notOk(res === SecurePassword.VALID, 'weak right not valid')
      assert.notOk(res === SecurePassword.INVALID, 'weak right not invald')
      assert.ok(res === SecurePassword.VALID_NEEDS_REHASH, 'weak right rehash')
    })

    weakPwd.verify(empty, argon2ipassempty, function (err, res) {
      assert.error(err, 'weak right not error')
      assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH, 'weak not right unrecognized')
      assert.notOk(res === SecurePassword.VALID, 'weak right not valid')
      assert.notOk(res === SecurePassword.INVALID, 'weak right not invald')
      assert.ok(res === SecurePassword.VALID_NEEDS_REHASH, 'weak right rehash')
    })

    betterPwd.hash(userPassword, function (err, betterHash) {
      assert.error(err)

      betterPwd.verify(userPassword, betterHash, function (err, res) {
        assert.error(err)
        assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH)
        assert.ok(res === SecurePassword.VALID)
        assert.notOk(res === SecurePassword.INVALID)
        assert.notOk(res === SecurePassword.VALID_NEEDS_REHASH)
      })

      betterPwd.verify(wrongPassword, betterHash, function (err, res) {
        assert.error(err)
        assert.notOk(res === SecurePassword.INVALID_UNRECOGNIZED_HASH)
        assert.notOk(res === SecurePassword.VALID)
        assert.ok(res === SecurePassword.INVALID)
        assert.notOk(res === SecurePassword.VALID_NEEDS_REHASH)
      })
    })
  })
})

test('Can handle invalid hash sync', function (assert) {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

  const unrecognizedHash = pwd.verifySync(userPassword, invalidHash)
  assert.ok(unrecognizedHash === SecurePassword.INVALID_UNRECOGNIZED_HASH)
  assert.notOk(unrecognizedHash === SecurePassword.INVALID)
  assert.notOk(unrecognizedHash === SecurePassword.VALID)
  assert.notOk(unrecognizedHash === SecurePassword.VALID_NEEDS_REHASH)
  assert.end()
})

test('Can handle invalid hash async', function (assert) {
  const pwd = new SecurePassword()

  const userPassword = Buffer.from('my secret')
  const invalidHash = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

  pwd.verify(userPassword, invalidHash, function (err, unrecognizedHash) {
    assert.error(err)
    assert.ok(unrecognizedHash === SecurePassword.INVALID_UNRECOGNIZED_HASH)
    assert.notOk(unrecognizedHash === SecurePassword.INVALID)
    assert.notOk(unrecognizedHash === SecurePassword.VALID)
    assert.notOk(unrecognizedHash === SecurePassword.VALID_NEEDS_REHASH)
    assert.end()
  })
})
