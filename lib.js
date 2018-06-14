const unorm = require('unorm')
const pbkdf2 = require('pbkdf2')
const nacl = require('js-nacl')
const Blake2b = require('blakejs')
const blake2b = Blake2b.blake2b
const blake2bHex = Blake2b.blake2bHex
const sha256 = require('sha256')
const BN = require('bn.js')
const EdDSA = require('elliptic').eddsa

/* LIBS */

const iterations = 2048

const der_key_len = 64
const magicbyte = 434591
const magicprefix = '06a19f'
const code_string_base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function promisify (f) {
  return new Promise (function (resolve, reject) {
    f(function (args) {
      resolve.apply(null, arguments)
    })
  })
}

function mnemonic_to_seed (mnemonic, salt) {
  let salted_salt = 'mnemonic' + salt
  let derived_key = pbkdf2.pbkdf2Sync(mnemonic, salted_salt, iterations, der_key_len, 'sha512')

  return derived_key
}

/**
 * mod
 * @param n {Integer}
 * @param m {Integer}
 * @return {Integer}
 */

function mod (n, m) {
  return ((n % m) + m) % m
}

/**
 * bin_dbl_sha256
 * @param data {Buffer}
 * @return {Buffer}
 */

function bin_dbl_sha256 (data) {
  return Buffer.from(sha256.x2(data), 'hex')
}

/**
 * decode (from base 256)
 * @param data {Buffer}
 * @return {BN}
 */

function decode (data) {
  let len = data.length
  let result = new BN()
  let base = new BN(256)
  let counter = 0

  while (counter < len) {
    result.imul(base)
    result.iadd(new BN(data[counter]))
    counter += 1
  }

  return result
}

/**
 * encode (to base 58)
 * @param val {BN}
 * @return {String}
 */

function encode (val) {
  let result = ''
  let base = new BN(58)
  let m

  while (val > 0) {
    m = val.umod(base).toString(10)
    result = code_string_base58[m] + result
    val = val.div(base)
  }

  return result
}

/**
 * to_base58
 * @param digest {Buffer}
 * @return {String}
 */

function to_base58 (digest) {
  return encode(decode(digest))
}

/**
 * to_b58check
 * @param digest {Buffer}
 * @return {String}
 */

function to_b58check (digest) {
  let magic_buf = Buffer.from(magicprefix, 'hex')
  let magic_buf_len = magic_buf.length
  let checksum_len = 4
  let buf_len = magic_buf_len + digest.length + checksum_len
  let buf = Buffer.allocUnsafe(buf_len)
  let acc = 0
  let checksum_buf
  let checksum

  acc += magic_buf.copy(buf, 0)
  acc += digest.copy(buf, acc)
  checksum_buf = buf.slice(0, acc)
  checksum = bin_dbl_sha256(checksum_buf).slice(0, checksum_len)
  acc += checksum.copy(buf, acc)

  return to_base58(buf)
}

/**
 * tezos_pkh
 * @param digest {Buffer}
 * @return {String}
 */

function tezos_pkh (digest) {
  return to_b58check(digest)
}

function hash64 (msg, enc) {
  let buf = Buffer.from(msg, enc)

  return blake2bHex(buf, null, 64)
}

function sign (sk, msg, enc) {
  // Create and initialize EdDSA context
  let ec = new EdDSA('ed25519')

  // Create key pair from secret key
  let key01 = ec.keyFromSecret(sk) // string, array or Buffer

  // generate message hash
  let msgHash = Buffer.from(hash64(msg, enc), 'hex')

  // generate signature
  let signature = key01.sign(msgHash).toHex()

  return signature
}

function remove_0x (addr) {
  return addr.replace('0x', '')
}

function add_0x (addr) {
  if (addr.startsWith('0x')) {
    return addr
  }

  return '0x' + addr
}


/* END LIBS */

/**
 * _genrate_data
 *
 * @param params.TZ_addr {string}
 * @param params.mnemonic {string}
 * @param params.email {string}
 * @param params.password {string}
 * @param params.ETH_address {string}
 * @return {string}
 */

const _generate_data = async function ({TZ_addr, mnemonic, email, password, ETH_addr}) {
  ETH_addr = remove_0x(ETH_addr)
  let words = mnemonic.split(' ')
  let isValid = words.length === 15

  if (!isValid) { return 'Error: invalid number of words in mnemonic' }

  let mnemonic_sanit = words.join(' ').toLowerCase()
  let email_passwd = email + password
  let salt = unorm.nfkd(email_passwd)
  let seed = mnemonic_to_seed(mnemonic_sanit, salt)
  let crypto_sign_seed_keypair = (await promisify(nacl.instantiate)).crypto_sign_seed_keypair
  let sk = seed.slice(0, 32)
  let sk_pk = crypto_sign_seed_keypair(sk)
  let pk = Buffer.from(sk_pk.signPk)
  let TZL_pk = pk.toString('hex')
  let hashed_pk = blake2b(pk, null, 20)
  let pkh = Buffer.from(hashed_pk)
  let tz_pkh = tezos_pkh(pkh)

  isValid &= tz_pkh === TZ_addr

  if (!isValid) { return `Error: recovered Tz address (${tz_pkh}) does not match the provided one (${TZ_addr})` }

  let ETH_addr_signature = sign(sk, ETH_addr, 'hex')

  return {
    TZL_pkh: tz_pkh,
    ETH_addr,
    TZL_pk,
    ETH_addr_signature
  }
}

/**
 * generate_data
 *
 * @param params.TZ_addr {string}
 * @param params.mnemonic {string}
 * @param params.email {string}
 * @param params.password {string}
 * @param params.ETH_address {string}
 * @return {string}
 */

const generate_data = module.exports = async function (params) {
  let result = ''
  try {
    result = await _generate_data(params)
  } catch (e) {
    result = ''
  }

  return result
}
