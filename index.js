import { promisify } from 'node:util'

import sodium from 'sodium-native'
import assert from 'nanoassert'

const cryptoPwhashStrAsync = promisify(sodium.crypto_pwhash_str_async)
const cryptoPwhashStrVerifyAsync = promisify(sodium.crypto_pwhash_str_verify_async)
const cryptoPwhashStrNeedsRehash = sodium.crypto_pwhash_str_needs_rehash

/**
 * Checks if a hash buffer uses a recognized Argon2 algorithm.
 *
 * @param {Buffer} hashBuf
 * @returns {boolean}
 */
function recognizedAlgorithm (hashBuf) {
  return hashBuf.includes('$argon2i$') || hashBuf.includes('$argon2id$')
}

/**
 * @typedef SecurePasswordOptions
 * @property {number} [memlimit] - Memory limit for hashing (default: SecurePassword.MEMLIMIT_DEFAULT)
 * @property {number} [opslimit] - Operations limit for hashing (default: SecurePassword.OPSLIMIT_DEFAULT)
 */

/**
 * Argon2 password hashing and verification utility using sodium-native.
 *
 * @class
 */
export class SecurePassword {
  /**
   * @param {SecurePasswordOptions} [opts]
   */
  constructor (opts = {}) {
    const {
      memlimit = SecurePassword.MEMLIMIT_DEFAULT,
      opslimit = SecurePassword.OPSLIMIT_DEFAULT,
    } = opts

    assert(memlimit >= SecurePassword.MEMLIMIT_MIN, 'opts.memlimit must be at least MEMLIMIT_MIN (' + SecurePassword.MEMLIMIT_MIN + ')')
    assert(memlimit <= SecurePassword.MEMLIMIT_MAX, 'opts.memlimit must be at most MEMLIMIT_MAX (' + SecurePassword.MEMLIMIT_MAX + ')')

    assert(opslimit >= SecurePassword.OPSLIMIT_MIN, 'opts.opslimit must be at least OPSLIMIT_MIN (' + SecurePassword.OPSLIMIT_MIN + ')')
    assert(opslimit <= SecurePassword.OPSLIMIT_MAX, 'opts.memlimit must be at most OPSLIMIT_MAX (' + SecurePassword.OPSLIMIT_MAX + ')')

    this.memlimit = memlimit
    this.opslimit = opslimit
  }

  /**
   * Hash a password buffer synchronously.
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @returns {Buffer} The resulting hash Buffer.
   */
  hashSync (passwordBuf) {
    assert(Buffer.isBuffer(passwordBuf), 'passwordBuf must be Buffer')
    assert(passwordBuf.length >= SecurePassword.PASSWORD_BYTES_MIN, 'passwordBuf must be at least PASSWORD_BYTES_MIN (' + SecurePassword.PASSWORD_BYTES_MIN + ')')
    assert(passwordBuf.length < SecurePassword.PASSWORD_BYTES_MAX, 'passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + SecurePassword.PASSWORD_BYTES_MAX + ')')

    // Unsafe is okay here since sodium will overwrite all bytes
    const hashBuf = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)
    sodium.crypto_pwhash_str(hashBuf, passwordBuf, this.opslimit, this.memlimit)

    // Note that this buffer may have trailing NULL bytes, which is by design
    // (of libsodium). The trailing NULL bytes can be safely trimmed if need
    // be per libsodium docs. This is a TODO as we currently don't handle this case
    return hashBuf
  }

  /**
   * Hash a password buffer asynchronously (Promise or callback).
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @returns {Promise<Buffer>} Promise if no callback is given.
   */
  async hash (passwordBuf) {
    assert(Buffer.isBuffer(passwordBuf), 'passwordBuf must be Buffer')
    assert(passwordBuf.length >= SecurePassword.PASSWORD_BYTES_MIN, 'passwordBuf must be at least PASSWORD_BYTES_MIN (' + SecurePassword.PASSWORD_BYTES_MIN + ')')
    assert(passwordBuf.length < SecurePassword.PASSWORD_BYTES_MAX, 'passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + SecurePassword.PASSWORD_BYTES_MAX + ')')

    // Unsafe is okay here since sodium will overwrite all bytes
    const hashBuf = Buffer.allocUnsafe(SecurePassword.HASH_BYTES)

    await cryptoPwhashStrAsync(hashBuf, passwordBuf, this.opslimit, this.memlimit)

    return hashBuf
  }

  /**
   * Verify a password against a hash synchronously.
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @param {Buffer} hashBuf - The hash as a Buffer.
   * @returns {symbol} One of SecurePassword.INVALID, VALID, VALID_NEEDS_REHASH, or INVALID_UNRECOGNIZED_HASH.
   */
  verifySync (passwordBuf, hashBuf) {
    assert(Buffer.isBuffer(passwordBuf), 'passwordBuf must be Buffer')
    assert(passwordBuf.length >= SecurePassword.PASSWORD_BYTES_MIN, 'passwordBuf must be at least PASSWORD_BYTES_MIN (' + SecurePassword.PASSWORD_BYTES_MIN + ')')
    assert(passwordBuf.length < SecurePassword.PASSWORD_BYTES_MAX, 'passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + SecurePassword.PASSWORD_BYTES_MAX + ')')

    assert(Buffer.isBuffer(hashBuf), 'hashBuf must be Buffer')
    assert(hashBuf.length === SecurePassword.HASH_BYTES, 'hashBuf must be HASH_BYTES (' + SecurePassword.HASH_BYTES + ')')

    if (recognizedAlgorithm(hashBuf) === false) return SecurePassword.INVALID_UNRECOGNIZED_HASH

    if (sodium.crypto_pwhash_str_verify(hashBuf, passwordBuf) === false) {
      return SecurePassword.INVALID
    }

    if (sodium.crypto_pwhash_str_needs_rehash(hashBuf, this.opslimit, this.memlimit)) {
      return SecurePassword.VALID_NEEDS_REHASH
    }

    return SecurePassword.VALID
  }

  /**
   * Verify a password against a hash asynchronously (Promise or callback).
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @param {Buffer} hashBuf - The hash as a Buffer.
   * @returns {Promise<symbol>} Promise if no callback is given.
   */
  async verify (passwordBuf, hashBuf) {
    assert(Buffer.isBuffer(passwordBuf), 'passwordBuf must be Buffer')
    assert(passwordBuf.length >= SecurePassword.PASSWORD_BYTES_MIN, 'passwordBuf must be at least PASSWORD_BYTES_MIN (' + SecurePassword.PASSWORD_BYTES_MIN + ')')
    assert(passwordBuf.length < SecurePassword.PASSWORD_BYTES_MAX, 'passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + SecurePassword.PASSWORD_BYTES_MAX + ')')

    assert(Buffer.isBuffer(hashBuf), 'hashBuf must be Buffer')
    assert(hashBuf.length === SecurePassword.HASH_BYTES, 'hashBuf must be HASH_BYTES (' + SecurePassword.HASH_BYTES + ')')

    if (recognizedAlgorithm(hashBuf) === false) {
      return SecurePassword.INVALID_UNRECOGNIZED_HASH
    }

    const bool = await cryptoPwhashStrVerifyAsync(hashBuf, passwordBuf)

    if (bool === false) {
      return SecurePassword.INVALID
    }
    if (cryptoPwhashStrNeedsRehash(hashBuf, this.opslimit, this.memlimit)) {
      return SecurePassword.VALID_NEEDS_REHASH
    }

    return SecurePassword.VALID
  }

  /** @type {number} */
  static HASH_BYTES = sodium.crypto_pwhash_STRBYTES
  /** @type {number} */
  static PASSWORD_BYTES_MIN = sodium.crypto_pwhash_PASSWD_MIN
  /** @type {number} */
  static PASSWORD_BYTES_MAX = sodium.crypto_pwhash_PASSWD_MAX
  /** @type {number} */
  static MEMLIMIT_MIN = sodium.crypto_pwhash_MEMLIMIT_MIN
  /** @type {number} */
  static MEMLIMIT_MAX = sodium.crypto_pwhash_MEMLIMIT_MAX
  /** @type {number} */
  static OPSLIMIT_MIN = sodium.crypto_pwhash_OPSLIMIT_MIN
  /** @type {number} */
  static OPSLIMIT_MAX = sodium.crypto_pwhash_OPSLIMIT_MAX
  /** @type {number} */
  static MEMLIMIT_DEFAULT = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  /** @type {number} */
  static OPSLIMIT_DEFAULT = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  /** @type {symbol} */
  static INVALID_UNRECOGNIZED_HASH = Symbol('INVALID_UNRECOGNIZED_HASH')
  /** @type {symbol} */
  static INVALID = Symbol('INVALID')
  /** @type {symbol} */
  static VALID = Symbol('VALID')
  /** @type {symbol} */
  static VALID_NEEDS_REHASH = Symbol('VALID_NEEDS_REHASH')
}
