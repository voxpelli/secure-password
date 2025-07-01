import { promisify } from 'node:util'

import sodium from 'sodium-native'

const cryptoPwhashStrAsync = promisify(sodium.crypto_pwhash_str_async)
const cryptoPwhashStrVerifyAsync = promisify(sodium.crypto_pwhash_str_verify_async)
const cryptoPwhashStrNeedsRehash = sodium.crypto_pwhash_str_needs_rehash

// Sodium constants

export const HASH_BYTES = sodium.crypto_pwhash_STRBYTES
export const PASSWORD_BYTES_MIN = sodium.crypto_pwhash_PASSWD_MIN
export const PASSWORD_BYTES_MAX = sodium.crypto_pwhash_PASSWD_MAX
export const MEMLIMIT_MIN = sodium.crypto_pwhash_MEMLIMIT_MIN
export const MEMLIMIT_MAX = sodium.crypto_pwhash_MEMLIMIT_MAX
export const OPSLIMIT_MIN = sodium.crypto_pwhash_OPSLIMIT_MIN
export const OPSLIMIT_MAX = sodium.crypto_pwhash_OPSLIMIT_MAX
export const MEMLIMIT_DEFAULT = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
export const OPSLIMIT_DEFAULT = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE

// Symbols

export const INVALID = Symbol('INVALID')
export const INVALID_UNRECOGNIZED_HASH = Symbol('INVALID_UNRECOGNIZED_HASH')
export const VALID = Symbol('VALID')
export const VALID_NEEDS_REHASH = Symbol('VALID_NEEDS_REHASH')

/** @typedef {typeof INVALID | typeof INVALID_UNRECOGNIZED_HASH | typeof VALID | typeof VALID_NEEDS_REHASH} VerificationResult */

/**
 * Checks if a hash buffer uses a recognized Argon2 algorithm.
 *
 * @param {Buffer} hashBuf
 * @returns {boolean}
 */
const recognizedAlgorithm = hashBuf => hashBuf.includes('$argon2i$') || hashBuf.includes('$argon2id$')

/**
 * @typedef SecurePasswordOptions
 * @property {number} [memlimit] - Memory limit for hashing (default: MEMLIMIT_DEFAULT)
 * @property {number} [opslimit] - Operations limit for hashing (default: OPSLIMIT_DEFAULT)
 */

/**
 * Argon2 password hashing and verification utility using sodium-native.
 *
 * @class
 */
export class SecurePassword {
  #memlimit
  #opslimit

  /**
   * @param {SecurePasswordOptions} [opts]
   */
  constructor (opts = {}) {
    const {
      memlimit = MEMLIMIT_DEFAULT,
      opslimit = OPSLIMIT_DEFAULT,
    } = opts

    if (memlimit < MEMLIMIT_MIN) throw new Error('opts.memlimit must be at least MEMLIMIT_MIN (' + MEMLIMIT_MIN + ')')
    if (memlimit > MEMLIMIT_MAX) throw new Error('opts.memlimit must be at most MEMLIMIT_MAX (' + MEMLIMIT_MAX + ')')

    if (opslimit < OPSLIMIT_MIN) throw new Error('opts.opslimit must be at least OPSLIMIT_MIN (' + OPSLIMIT_MIN + ')')
    if (opslimit > OPSLIMIT_MAX) throw new Error('opts.opslimit must be at most OPSLIMIT_MAX (' + OPSLIMIT_MAX + ')')

    this.#memlimit = memlimit
    this.#opslimit = opslimit
  }

  /**
   * Hash a password buffer synchronously.
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @returns {Buffer} The resulting hash Buffer.
   */
  hashSync (passwordBuf) {
    if (!Buffer.isBuffer(passwordBuf)) throw new TypeError('passwordBuf must be Buffer')
    if (passwordBuf.length < PASSWORD_BYTES_MIN) throw new Error('passwordBuf must be at least PASSWORD_BYTES_MIN (' + PASSWORD_BYTES_MIN + ')')
    if (passwordBuf.length >= PASSWORD_BYTES_MAX) throw new Error('passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + PASSWORD_BYTES_MAX + ')')

    // Unsafe is okay here since sodium will overwrite all bytes
    const hashBuf = Buffer.allocUnsafe(HASH_BYTES)
    sodium.crypto_pwhash_str(hashBuf, passwordBuf, this.#opslimit, this.#memlimit)

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
    if (!Buffer.isBuffer(passwordBuf)) throw new TypeError('passwordBuf must be Buffer')
    if (passwordBuf.length < PASSWORD_BYTES_MIN) throw new Error('passwordBuf must be at least PASSWORD_BYTES_MIN (' + PASSWORD_BYTES_MIN + ')')
    if (passwordBuf.length >= PASSWORD_BYTES_MAX) throw new Error('passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + PASSWORD_BYTES_MAX + ')')

    // Unsafe is okay here since sodium will overwrite all bytes
    const hashBuf = Buffer.allocUnsafe(HASH_BYTES)

    await cryptoPwhashStrAsync(hashBuf, passwordBuf, this.#opslimit, this.#memlimit)

    return hashBuf
  }

  /**
   * Verify a password against a hash synchronously.
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @param {Buffer} hashBuf - The hash as a Buffer.
   * @returns {VerificationResult} One of INVALID, VALID, VALID_NEEDS_REHASH, or INVALID_UNRECOGNIZED_HASH.
   */
  verifySync (passwordBuf, hashBuf) {
    if (!Buffer.isBuffer(passwordBuf)) throw new TypeError('passwordBuf must be Buffer')
    if (passwordBuf.length < PASSWORD_BYTES_MIN) throw new Error('passwordBuf must be at least PASSWORD_BYTES_MIN (' + PASSWORD_BYTES_MIN + ')')
    if (passwordBuf.length >= PASSWORD_BYTES_MAX) throw new Error('passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + PASSWORD_BYTES_MAX + ')')

    if (!Buffer.isBuffer(hashBuf)) throw new TypeError('hashBuf must be Buffer')
    if (hashBuf.length !== HASH_BYTES) throw new Error('hashBuf must be HASH_BYTES (' + HASH_BYTES + ')')

    if (recognizedAlgorithm(hashBuf) === false) {
      return INVALID_UNRECOGNIZED_HASH
    }

    if (sodium.crypto_pwhash_str_verify(hashBuf, passwordBuf) === false) {
      return INVALID
    }

    if (sodium.crypto_pwhash_str_needs_rehash(hashBuf, this.#opslimit, this.#memlimit)) {
      return VALID_NEEDS_REHASH
    }

    return VALID
  }

  /**
   * Verify a password against a hash asynchronously (Promise or callback).
   *
   * @param {Buffer} passwordBuf - The password as a Buffer.
   * @param {Buffer} hashBuf - The hash as a Buffer.
   * @returns {Promise<VerificationResult>} Promise if no callback is given.
   */
  async verify (passwordBuf, hashBuf) {
    if (!Buffer.isBuffer(passwordBuf)) throw new TypeError('passwordBuf must be Buffer')
    if (passwordBuf.length < PASSWORD_BYTES_MIN) throw new Error('passwordBuf must be at least PASSWORD_BYTES_MIN (' + PASSWORD_BYTES_MIN + ')')
    if (passwordBuf.length >= PASSWORD_BYTES_MAX) throw new Error('passwordBuf must be shorter than PASSWORD_BYTES_MAX (' + PASSWORD_BYTES_MAX + ')')

    if (!Buffer.isBuffer(hashBuf)) throw new TypeError('hashBuf must be Buffer')
    if (hashBuf.length !== HASH_BYTES) throw new Error('hashBuf must be HASH_BYTES (' + HASH_BYTES + ')')

    if (recognizedAlgorithm(hashBuf) === false) {
      return INVALID_UNRECOGNIZED_HASH
    }

    const bool = await cryptoPwhashStrVerifyAsync(hashBuf, passwordBuf)

    if (bool === false) {
      return INVALID
    }
    if (cryptoPwhashStrNeedsRehash(hashBuf, this.#opslimit, this.#memlimit)) {
      return VALID_NEEDS_REHASH
    }

    return VALID
  }
}
