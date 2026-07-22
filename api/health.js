'use strict';


/* source 3-3 */
const crypto = require('crypto');

/* source 4-1184 */
const DIRAC_RECOVERY_CRYPTO_V2 = (() => {
'use strict';

/*
 * Dirac Recovery Crypto V2 — narrow high-assurance recovery-only module.
 * No login, payment, email-template, MFA/A2F, or endpoint logic lives here.
 */

const crypto = require('crypto');

const VERSION = 'dirac-lost-passkey-vault-v2-max-2026';
const MANIFEST_SCHEMA = 'dirac-lost-passkey-signed-security-manifest-v2';
const SECURITY_CONTRACT = 'dirac-lost-passkey-security-contract-v2';
const ENVELOPE_VERSION = 'dirac-recovery-hybrid-envelope-v2';
const PLAINTEXT_VERSION = 'dirac-recovery-hybrid-plaintext-v2';
const RESPONSE_VERSION = 'dirac-recovery-hybrid-response-v2';
const PURPOSE = 'lost_passkey_recovery';
const HYBRID_SUITE = 'DHKEM-X25519-HKDF-SHA256+ML-KEM-1024+HKDF-SHA512+AES-256-GCM';
const PAYLOAD_CIPHER = 'AES-256-GCM';
const KEY_WRAP = 'A256KW';
const KDF = 'Argon2id+HKDF-SHA512';
const SIGNATURE_POLICY = 'Ed25519-AND-ML-DSA-87';
const RFC3394_IV = Buffer.from('a6a6a6a6a6a6a6a6', 'hex');
const MLDSA_CONTEXT = Buffer.from('dirac/recovery/v2/manifest', 'utf8');
const MAX_CLOCK_SKEW_MS = 30_000;
const MAX_ENVELOPE_LIFETIME_MS = 120_000;

function fail(code, message) {
  const error = new Error(message || code);
  error.code = code;
  return error;
}

function envText(name) {
  return String(process.env[String(name || '')] || '').trim();
}

function envTrue(name) {
  return /^(1|true|yes|on|enabled)$/i.test(envText(name));
}

function assertNoLoneSurrogates(text) {
  const value = String(text);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw fail('JCS_UNPAIRED_SURROGATE');
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw fail('JCS_UNPAIRED_SURROGATE');
    }
  }
}

/** RFC 8785-compatible canonicalization for JSON-compatible values. */
function jcs(value, seen = new Set()) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'string') {
    assertNoLoneSurrogates(value);
    return JSON.stringify(value);
  }
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) throw fail('JCS_NUMBER_INVALID');
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (type !== 'object') throw fail('JCS_TYPE_INVALID');
  if (seen.has(value)) throw fail('JCS_CYCLE_INVALID');
  seen.add(value);
  try {
    if (Array.isArray(value)) return '[' + value.map((item) => jcs(item, seen)).join(',') + ']';
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw fail('JCS_OBJECT_INVALID');
    const keys = Object.keys(value).sort();
    return '{' + keys.map((key) => {
      assertNoLoneSurrogates(key);
      if (value[key] === undefined || typeof value[key] === 'function' || typeof value[key] === 'symbol') {
        throw fail('JCS_MEMBER_INVALID');
      }
      return JSON.stringify(key) + ':' + jcs(value[key], seen);
    }).join(',') + '}';
  } finally {
    seen.delete(value);
  }
}

function b64u(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function decodeB64u(value, exactLength = null, maximumTextLength = 64 * 1024) {
  const clean = String(value || '').trim();
  if (!clean || clean.length > maximumTextLength || !/^[A-Za-z0-9_-]+$/.test(clean) || clean.length % 4 === 1) {
    throw fail('BASE64URL_INVALID');
  }
  const decoded = Buffer.from(clean, 'base64url');
  if (decoded.toString('base64url') !== clean) throw fail('BASE64URL_NON_CANONICAL');
  if (exactLength !== null && decoded.length !== exactLength) throw fail('BASE64URL_LENGTH_INVALID');
  return decoded;
}

function sha512B64u(value) {
  return crypto.createHash('sha512').update(Buffer.isBuffer(value) ? value : Buffer.from(value)).digest('base64url');
}

function sha512(value) {
  return crypto.createHash('sha512').update(Buffer.isBuffer(value) ? value : Buffer.from(value)).digest();
}

function hkdfSha512(ikm, salt, info, length) {
  if (!Number.isSafeInteger(length) || length < 1 || length > 255 * 64) throw fail('HKDF_LENGTH_INVALID');
  return Buffer.from(crypto.hkdfSync(
    'sha512',
    Buffer.from(ikm),
    Buffer.from(salt || Buffer.alloc(0)),
    Buffer.from(String(info || ''), 'utf8'),
    length
  ));
}

function aesKwWrap(kek, plaintext) {
  const key = Buffer.from(kek);
  const input = Buffer.from(plaintext);
  if (key.length !== 32 || input.length < 16 || input.length % 8 !== 0) throw fail('AES_KW_INPUT_INVALID');
  const cipher = crypto.createCipheriv('id-aes256-wrap', key, RFC3394_IV);
  const wrapped = Buffer.concat([cipher.update(input), cipher.final()]);
  if (wrapped.length !== input.length + 8) throw fail('AES_KW_OUTPUT_INVALID');
  return wrapped;
}

function aesKwUnwrap(kek, wrapped, expectedLength = null) {
  const key = Buffer.from(kek);
  const input = Buffer.from(wrapped);
  if (key.length !== 32 || input.length < 24 || input.length % 8 !== 0) throw fail('AES_KW_INPUT_INVALID');
  let output;
  try {
    const decipher = crypto.createDecipheriv('id-aes256-wrap', key, RFC3394_IV);
    output = Buffer.concat([decipher.update(input), decipher.final()]);
  } catch (_) {
    throw fail('AES_KW_INTEGRITY_FAILED');
  }
  if (expectedLength !== null && output.length !== expectedLength) {
    output.fill(0);
    throw fail('AES_KW_LENGTH_INVALID');
  }
  return output;
}

function aesGcmEncrypt(key, plaintext, aad, nonce = crypto.randomBytes(12)) {
  const realKey = Buffer.from(key);
  const realNonce = Buffer.from(nonce);
  if (realKey.length !== 32 || realNonce.length !== 12) throw fail('AES_GCM_INPUT_INVALID');
  const cipher = crypto.createCipheriv('aes-256-gcm', realKey, realNonce, { authTagLength: 16 });
  const realAad = Buffer.from(aad || Buffer.alloc(0));
  cipher.setAAD(realAad, { plaintextLength: Buffer.byteLength(plaintext) });
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { nonce: realNonce, ciphertext, tag };
}

function aesGcmDecrypt(key, nonce, ciphertext, tag, aad) {
  const realKey = Buffer.from(key);
  const realNonce = Buffer.from(nonce);
  const realCiphertext = Buffer.from(ciphertext);
  const realTag = Buffer.from(tag);
  const realAad = Buffer.from(aad || Buffer.alloc(0));
  if (realKey.length !== 32 || realNonce.length !== 12 || realTag.length !== 16) throw fail('AES_GCM_INPUT_INVALID');
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', realKey, realNonce, { authTagLength: 16 });
    decipher.setAAD(realAad, { plaintextLength: realCiphertext.length });
    decipher.setAuthTag(realTag);
    return Buffer.concat([decipher.update(realCiphertext), decipher.final()]);
  } catch (_) {
    throw fail('AES_GCM_AUTHENTICATION_FAILED');
  }
}

function parsePrivateKey(raw, expectedType) {
  const clean = String(raw || '').trim();
  if (!clean) throw fail('PRIVATE_KEY_MISSING');
  const material = clean.includes('-----BEGIN') ? clean.replace(/\\n/g, '\n') : Buffer.from(clean, 'base64');
  const key = crypto.createPrivateKey(material);
  if (expectedType && key.asymmetricKeyType !== expectedType) throw fail('PRIVATE_KEY_TYPE_INVALID');
  return key;
}

function parsePublicKey(raw, expectedType) {
  const clean = String(raw || '').trim();
  if (!clean) throw fail('PUBLIC_KEY_MISSING');
  const material = clean.includes('-----BEGIN') ? clean.replace(/\\n/g, '\n') : Buffer.from(clean, 'base64');
  const key = crypto.createPublicKey(material);
  if (expectedType && key.asymmetricKeyType !== expectedType) throw fail('PUBLIC_KEY_TYPE_INVALID');
  return key;
}

function assertPostQuantumRuntime() {
  if (typeof crypto.encapsulate !== 'function' || typeof crypto.decapsulate !== 'function') {
    throw fail('NODE_MLKEM_RUNTIME_UNAVAILABLE');
  }
}

function mlkemEncapsulate(publicKey = null) {
  assertPostQuantumRuntime();
  const key = publicKey || parsePublicKey(
    envText('DIRAC_RECOVERY_MLKEM1024_PUBLIC_KEY_PEM') || envText('DIRAC_RECOVERY_MLKEM1024_PUBLIC_KEY_DER_B64'),
    'ml-kem-1024'
  );
  const result = crypto.encapsulate(key);
  if (!result || !Buffer.isBuffer(result.sharedKey) || !Buffer.isBuffer(result.ciphertext) || result.sharedKey.length !== 32) {
    throw fail('MLKEM_ENCAPSULATION_INVALID');
  }
  return { sharedKey: Buffer.from(result.sharedKey), ciphertext: Buffer.from(result.ciphertext) };
}

function mlkemDecapsulate(ciphertext, privateKey = null) {
  assertPostQuantumRuntime();
  const key = privateKey || parsePrivateKey(
    envText('DIRAC_RECOVERY_MLKEM1024_PRIVATE_KEY_PEM') || envText('DIRAC_RECOVERY_MLKEM1024_PRIVATE_KEY_DER_B64'),
    'ml-kem-1024'
  );
  const sharedKey = crypto.decapsulate(key, Buffer.from(ciphertext));
  if (!Buffer.isBuffer(sharedKey) || sharedKey.length !== 32) throw fail('MLKEM_DECAPSULATION_INVALID');
  return Buffer.from(sharedKey);
}

function dualSignManifest(payload) {
  const message = Buffer.from(jcs(payload), 'utf8');
  const edPrivate = parsePrivateKey(
    envText('DIRAC_LOST_PASSKEY_ED25519_PRIVATE_KEY_PEM') || envText('DIRAC_LOST_PASSKEY_ED25519_PRIVATE_KEY'),
    'ed25519'
  );
  const mlPrivate = parsePrivateKey(
    envText('DIRAC_RECOVERY_MLDSA87_PRIVATE_KEY_PEM') || envText('DIRAC_RECOVERY_MLDSA87_PRIVATE_KEY_DER_B64'),
    'ml-dsa-87'
  );
  let edSignature;
  let mlSignature;
  try {
    edSignature = crypto.sign(null, message, edPrivate);
    mlSignature = crypto.sign(null, message, { key: mlPrivate, context: MLDSA_CONTEXT });
    if (edSignature.length !== 64 || mlSignature.length < 4000) throw fail('DUAL_SIGNATURE_OUTPUT_INVALID');
    return {
      policy: SIGNATURE_POLICY,
      ed25519: {
        key_id: envText('DIRAC_LOST_PASSKEY_ED25519_KEY_ID') || 'dirac-recovery-ed25519-2026-01',
        algorithm: 'Ed25519',
        signature_b64url: b64u(edSignature)
      },
      ml_dsa_87: {
        key_id: envText('DIRAC_RECOVERY_MLDSA87_KEY_ID') || 'dirac-recovery-ml-dsa-87-2026-01',
        algorithm: 'ML-DSA-87',
        context_b64url: b64u(MLDSA_CONTEXT),
        signature_b64url: b64u(mlSignature)
      }
    };
  } finally {
    message.fill(0);
    if (edSignature) edSignature.fill(0);
    if (mlSignature) mlSignature.fill(0);
  }
}

function verifyDualManifest(payload, signatures) {
  if (!signatures || typeof signatures !== 'object' || Array.isArray(signatures) || signatures.policy !== SIGNATURE_POLICY) throw fail('DUAL_SIGNATURE_POLICY_INVALID');
  const signatureKeys = Object.keys(signatures).sort();
  const expectedSignatureKeys = ['ed25519', 'ml_dsa_87', 'policy'];
  if (signatureKeys.length !== expectedSignatureKeys.length || signatureKeys.some((key, index) => key !== expectedSignatureKeys[index])) throw fail('DUAL_SIGNATURE_FIELDS_INVALID');
  const ed = signatures.ed25519 || {};
  const ml = signatures.ml_dsa_87 || {};
  const edKeys = Object.keys(ed).sort();
  const mlKeys = Object.keys(ml).sort();
  const expectedEdKeys = ['algorithm', 'key_id', 'signature_b64url'];
  const expectedMlKeys = ['algorithm', 'context_b64url', 'key_id', 'signature_b64url'];
  if (edKeys.length !== expectedEdKeys.length || edKeys.some((key, index) => key !== expectedEdKeys[index])) throw fail('ED25519_SIGNATURE_FIELDS_INVALID');
  if (mlKeys.length !== expectedMlKeys.length || mlKeys.some((key, index) => key !== expectedMlKeys[index])) throw fail('MLDSA_SIGNATURE_FIELDS_INVALID');
  if (ed.algorithm !== 'Ed25519' || ml.algorithm !== 'ML-DSA-87') throw fail('DUAL_SIGNATURE_ALGORITHM_INVALID');
  const expectedEdKeyId = envText('DIRAC_LOST_PASSKEY_ED25519_KEY_ID') || 'dirac-recovery-ed25519-2026-01';
  const expectedMlKeyId = envText('DIRAC_RECOVERY_MLDSA87_KEY_ID') || 'dirac-recovery-ml-dsa-87-2026-01';
  if (ed.key_id !== expectedEdKeyId || ml.key_id !== expectedMlKeyId) throw fail('DUAL_SIGNATURE_KEY_ID_INVALID');
  if (ml.context_b64url !== b64u(MLDSA_CONTEXT)) throw fail('MLDSA_CONTEXT_INVALID');
  const message = Buffer.from(jcs(payload), 'utf8');
  const edSignature = decodeB64u(ed.signature_b64url, 64, 256);
  const mlSignature = decodeB64u(ml.signature_b64url, null, 16 * 1024);
  const edPublicRaw = envText('DIRAC_LOST_PASSKEY_ED25519_PUBLIC_KEY_PEM') || envText('DIRAC_LOST_PASSKEY_ED25519_PUBLIC_KEY_DER_B64');
  const mlPublicRaw = envText('DIRAC_RECOVERY_MLDSA87_PUBLIC_KEY_PEM') || envText('DIRAC_RECOVERY_MLDSA87_PUBLIC_KEY_DER_B64');
  const edPublic = edPublicRaw
    ? parsePublicKey(edPublicRaw, 'ed25519')
    : crypto.createPublicKey(parsePrivateKey(envText('DIRAC_LOST_PASSKEY_ED25519_PRIVATE_KEY_PEM') || envText('DIRAC_LOST_PASSKEY_ED25519_PRIVATE_KEY'), 'ed25519'));
  const mlPublic = mlPublicRaw
    ? parsePublicKey(mlPublicRaw, 'ml-dsa-87')
    : crypto.createPublicKey(parsePrivateKey(envText('DIRAC_RECOVERY_MLDSA87_PRIVATE_KEY_PEM') || envText('DIRAC_RECOVERY_MLDSA87_PRIVATE_KEY_DER_B64'), 'ml-dsa-87'));
  try {
    const edOk = crypto.verify(null, message, edPublic, edSignature);
    const mlOk = crypto.verify(null, message, { key: mlPublic, context: MLDSA_CONTEXT }, mlSignature);
    if (!edOk || !mlOk) throw fail('DUAL_SIGNATURE_VERIFICATION_FAILED');
    return true;
  } finally {
    message.fill(0);
    edSignature.fill(0);
    mlSignature.fill(0);
  }
}

function assertRuntimePolicy() {
  const versionParts = String(process.versions.node || '').split('.').map((item) => Number(item || 0));
  const major = versionParts[0] || 0;
  const minor = versionParts[1] || 0;
  if (major < 24 || (major === 24 && minor < 8)) throw fail('NODE_VERSION_TOO_OLD');
  assertPostQuantumRuntime();
  if (envTrue('DIRAC_RECOVERY_FIPS_RUNTIME_REQUIRED')
      && (typeof crypto.getFips !== 'function' || crypto.getFips() !== 1)) {
    throw fail('FIPS_RUNTIME_REQUIRED');
  }
}

function assertExactObjectKeys(value, expectedKeys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail(code || 'OBJECT_SHAPE_INVALID');
  const actual = Object.keys(value).sort();
  const expected = Array.from(expectedKeys || []).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw fail(code || 'OBJECT_FIELDS_INVALID');
  }
  return value;
}

function assertArgon2Profile(params) {
  assertExactObjectKeys(params, ['memoryCost', 'timeCost', 'parallelism', 'hashLength'], 'ARGON2_FIELDS_INVALID');
  const memoryCost = Number(params.memoryCost);
  const timeCost = Number(params.timeCost);
  const parallelism = Number(params.parallelism);
  const hashLength = Number(params.hashLength);
  if (!Number.isSafeInteger(memoryCost)
      || memoryCost < 1048576
      || memoryCost > 5242880
      || !Number.isSafeInteger(timeCost)
      || timeCost < 4
      || timeCost > 12
      || parallelism !== 4
      || hashLength !== 64) {
    throw fail('ARGON2_PROFILE_INVALID');
  }
  return true;
}

function parseIsoMsStrict(value, code) {
  const clean = String(value || '');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(clean)) throw fail(code || 'TIME_FORMAT_INVALID');
  const parsed = Date.parse(clean);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== clean) throw fail(code || 'TIME_FORMAT_INVALID');
  return parsed;
}

function assertVaultBundlePolicy(bundle) {
  assertExactObjectKeys(bundle, [
    'aes_nonce', 'argon2id_params', 'auth_tag', 'ciphertext', 'hkdf_info', 'key_protection',
    'metadata', 'metadata_signature', 'payload', 'request_id', 'salt', 'transport', 'vault_id', 'version'
  ], 'VAULT_BUNDLE_FIELDS_INVALID');
  if (bundle.version !== VERSION || !/^[A-Za-z0-9_-]{16,120}$/.test(String(bundle.request_id || ''))) throw fail('VAULT_BUNDLE_ID_INVALID');
  const vaultId = decodeB64u(bundle.vault_id, 32, 128);
  const vaultSalt = decodeB64u(bundle.salt, 32, 128);
  try {
    assertArgon2Profile(bundle.argon2id_params);
    if (bundle.hkdf_info !== `dirac/recovery/v2/dek-wrap/${bundle.request_id}`) throw fail('VAULT_HKDF_INFO_INVALID');
    if (!/^(?:[a-f0-9]{64}|[A-Za-z0-9_-]{86})$/.test(String(bundle.metadata_signature || ''))) throw fail('VAULT_METADATA_SIGNATURE_INVALID');

    const metadata = assertExactObjectKeys(bundle.metadata, [
      'argon2id_params', 'created_at', 'dek_bits', 'dek_protection', 'domain', 'expires_at',
      'extra_nonce_entropy_hash', 'generation', 'input_policy', 'kdf', 'key_wrap', 'not_before',
      'one_time_use', 'payload_cipher', 'purpose', 'request_id', 'schema', 'signature_policy',
      'transport_suite', 'vault_id', 'version'
    ], 'VAULT_METADATA_FIELDS_INVALID');
    if (metadata.schema !== 'dirac-recovery-vault-metadata-v2'
        || metadata.version !== VERSION
        || metadata.purpose !== PURPOSE
        || metadata.domain !== 'https://secure.diracgroup.store'
        || metadata.request_id !== bundle.request_id
        || metadata.vault_id !== bundle.vault_id
        || metadata.generation !== 2
        || metadata.one_time_use !== true
        || metadata.payload_cipher !== PAYLOAD_CIPHER
        || metadata.key_wrap !== KEY_WRAP
        || metadata.kdf !== KDF
        || metadata.dek_bits !== 256
        || metadata.dek_protection !== 'A256KW-enveloped-DEK'
        || metadata.input_policy !== 'password+email-secret-100+website-secret-100'
        || metadata.transport_suite !== HYBRID_SUITE
        || metadata.signature_policy !== SIGNATURE_POLICY) {
      throw fail('VAULT_METADATA_POLICY_INVALID');
    }
    assertArgon2Profile(metadata.argon2id_params);
    if (jcs(metadata.argon2id_params) !== jcs(bundle.argon2id_params)) throw fail('VAULT_ARGON2_BINDING_INVALID');
    if (!/^(?:[a-f0-9]{64}|[A-Za-z0-9_-]{86})$/.test(String(metadata.extra_nonce_entropy_hash || ''))) throw fail('VAULT_ENTROPY_HASH_INVALID');
    const createdMs = parseIsoMsStrict(metadata.created_at, 'VAULT_CREATED_AT_INVALID');
    const notBeforeMs = parseIsoMsStrict(metadata.not_before, 'VAULT_NOT_BEFORE_INVALID');
    const expiresMs = parseIsoMsStrict(metadata.expires_at, 'VAULT_EXPIRES_AT_INVALID');
    if (notBeforeMs !== createdMs || expiresMs <= createdMs || expiresMs - createdMs > 15 * 60 * 1000) throw fail('VAULT_TIME_POLICY_INVALID');

    const payload = assertExactObjectKeys(bundle.payload, ['ciphertext_b64url', 'cipher', 'nonce_b64url', 'tag_b64url'], 'VAULT_PAYLOAD_FIELDS_INVALID');
    if (payload.cipher !== PAYLOAD_CIPHER) throw fail('VAULT_PAYLOAD_CIPHER_INVALID');
    const payloadNonce = decodeB64u(payload.nonce_b64url, 12, 128);
    const payloadCiphertext = decodeB64u(payload.ciphertext_b64url, null, 64 * 1024);
    const payloadTag = decodeB64u(payload.tag_b64url, 16, 128);
    try {
      if (!payloadCiphertext.length
          || bundle.aes_nonce !== payload.nonce_b64url
          || bundle.ciphertext !== payload.ciphertext_b64url
          || bundle.auth_tag !== payload.tag_b64url) {
        throw fail('VAULT_PAYLOAD_ALIAS_INVALID');
      }
    } finally {
      payloadNonce.fill(0); payloadCiphertext.fill(0); payloadTag.fill(0);
    }

    const protection = assertExactObjectKeys(bundle.key_protection, ['dek_wrap', 'policy'], 'VAULT_PROTECTION_FIELDS_INVALID');
    if (protection.policy !== 'A256KW-enveloped-DEK') throw fail('VAULT_PROTECTION_POLICY_INVALID');
    const dekWrap = assertExactObjectKeys(protection.dek_wrap, [
      'hkdf_info', 'kdf', 'key_id', 'salt_b64url', 'wrap', 'wrapped_dek_b64url'
    ], 'VAULT_DEK_WRAP_FIELDS_INVALID');
    if (dekWrap.wrap !== KEY_WRAP
        || dekWrap.kdf !== KDF
        || dekWrap.key_id !== 'dirac-vault-kek-v2'
        || dekWrap.hkdf_info !== bundle.hkdf_info) throw fail('VAULT_DEK_WRAP_POLICY_INVALID');
    const kekSalt = decodeB64u(dekWrap.salt_b64url, 32, 128);
    const wrappedDek = decodeB64u(dekWrap.wrapped_dek_b64url, 40, 256);
    kekSalt.fill(0); wrappedDek.fill(0);

    const transport = assertExactObjectKeys(bundle.transport, [
      'mlkem', 'mlkem_ciphertext_b64url', 'mlkem_ciphertext_sha512', 'mlkem_key_id',
      'shared_secret_wrap_info', 'shared_secret_wrap_salt_b64url', 'suite', 'wrapped_shared_secret_b64url'
    ], 'VAULT_TRANSPORT_FIELDS_INVALID');
    if (transport.suite !== HYBRID_SUITE
        || transport.mlkem !== 'ML-KEM-1024'
        || !/^[A-Za-z0-9._:-]{1,100}$/.test(String(transport.mlkem_key_id || ''))
        || transport.shared_secret_wrap_info !== `dirac/recovery/v2/mlkem-secret/${bundle.request_id}`) {
      throw fail('VAULT_TRANSPORT_POLICY_INVALID');
    }
    const mlkemCiphertext = decodeB64u(transport.mlkem_ciphertext_b64url, 1568, 4096);
    const wrappedShared = decodeB64u(transport.wrapped_shared_secret_b64url, 40, 256);
    const sharedSalt = decodeB64u(transport.shared_secret_wrap_salt_b64url, 32, 128);
    try {
      if (transport.mlkem_ciphertext_sha512 !== sha512B64u(mlkemCiphertext)) throw fail('VAULT_MLKEM_HASH_INVALID');
    } finally {
      mlkemCiphertext.fill(0); wrappedShared.fill(0); sharedSalt.fill(0);
    }
    return true;
  } finally {
    vaultId.fill(0); vaultSalt.fill(0);
  }
}

function assertManifestPolicy(payload) {
  assertExactObjectKeys(payload, [
    'action', 'argon2id_params', 'canonicalization', 'cipher', 'created_at', 'dek_bits',
    'dek_protection', 'expires_at', 'hpke_key_id', 'hpke_public_key_b64url',
    'hpke_public_key_sha512', 'input_factor_policy', 'kdf', 'kek_hkdf_info', 'kek_key_id',
    'kek_salt_sha512', 'key_id', 'key_wrap', 'legacy_fallback_allowed', 'manifest_schema',
    'metadata_sha512', 'minimum_reader_version', 'mlkem_ciphertext_sha512', 'mlkem_key_id',
    'not_before', 'payload_ciphertext_sha512', 'payload_nonce_sha512', 'payload_tag_sha512',
    'purpose', 'request_id', 'security_contract', 'signature_alg', 'signature_algorithms',
    'signature_policy', 'transport_suite', 'vault_bundle_sha512', 'vault_id', 'version',
    'wrapped_dek_sha512'
  ], 'MANIFEST_FIELDS_INVALID');
  if (payload.manifest_schema !== MANIFEST_SCHEMA
      || payload.version !== VERSION
      || payload.minimum_reader_version !== 2
      || payload.legacy_fallback_allowed !== false
      || payload.purpose !== PURPOSE
      || payload.action !== 'lost_passkey_recovery_link_open'
      || payload.signature_policy !== SIGNATURE_POLICY
      || payload.signature_alg !== 'Ed25519+ML-DSA-87'
      || jcs(payload.signature_algorithms) !== jcs(['Ed25519', 'ML-DSA-87'])
      || payload.canonicalization !== 'RFC8785-JCS'
      || payload.cipher !== PAYLOAD_CIPHER
      || payload.dek_bits !== 256
      || payload.dek_protection !== 'A256KW-enveloped-DEK'
      || payload.key_wrap !== KEY_WRAP
      || payload.kdf !== KDF
      || payload.input_factor_policy !== 'password+email-secret-100+website-secret-100'
      || payload.transport_suite !== HYBRID_SUITE) {
    throw fail('MANIFEST_SECURITY_POLICY_INVALID');
  }
  if (!/^[A-Za-z0-9_-]{16,120}$/.test(String(payload.request_id || ''))) throw fail('MANIFEST_REQUEST_ID_INVALID');
  decodeB64u(payload.vault_id, 32, 128).fill(0);
  assertArgon2Profile(payload.argon2id_params);
  const expectedEdKeyId = envText('DIRAC_LOST_PASSKEY_ED25519_KEY_ID') || 'dirac-recovery-ed25519-2026-01';
  if (payload.key_id !== expectedEdKeyId
      || !/^[A-Za-z0-9._:-]{1,80}$/.test(String(payload.hpke_key_id || ''))
      || !/^[A-Za-z0-9._:-]{1,100}$/.test(String(payload.mlkem_key_id || ''))
      || payload.kek_key_id !== 'dirac-vault-kek-v2'
      || payload.kek_hkdf_info !== `dirac/recovery/v2/dek-wrap/${payload.request_id}`) {
    throw fail('MANIFEST_KEY_BINDING_INVALID');
  }
  const hpkePublic = decodeB64u(payload.hpke_public_key_b64url, 32, 128);
  try {
    if (payload.hpke_public_key_sha512 !== sha512B64u(hpkePublic)) throw fail('MANIFEST_HPKE_PUBLIC_HASH_INVALID');
  } finally { hpkePublic.fill(0); }
  for (const key of [
    'mlkem_ciphertext_sha512', 'payload_ciphertext_sha512', 'payload_nonce_sha512',
    'payload_tag_sha512', 'metadata_sha512', 'wrapped_dek_sha512', 'kek_salt_sha512',
    'vault_bundle_sha512'
  ]) {
    if (!/^[A-Za-z0-9_-]{86}$/.test(String(payload[key] || ''))) throw fail('MANIFEST_HASH_INVALID');
  }
  const createdMs = parseIsoMsStrict(payload.created_at, 'MANIFEST_CREATED_AT_INVALID');
  const notBeforeMs = parseIsoMsStrict(payload.not_before, 'MANIFEST_NOT_BEFORE_INVALID');
  const expiresMs = parseIsoMsStrict(payload.expires_at, 'MANIFEST_EXPIRES_AT_INVALID');
  if (notBeforeMs !== createdMs || expiresMs <= createdMs || expiresMs - createdMs > 15 * 60 * 1000) throw fail('MANIFEST_TIME_POLICY_INVALID');
  const contract = assertExactObjectKeys(payload.security_contract, [
    'action', 'atomic_replay_claim_required', 'central_guard', 'central_guard_required',
    'dual_signature_required', 'email_secret_length', 'existing_three_inputs_required',
    'hybrid_transport_required', 'no_legacy_fallback', 'one_time_copy', 'recovery_code_length',
    'response_format', 'single_kek_envelope_required', 'vercel2_only', 'version',
    'website_secret_length'
  ], 'MANIFEST_CONTRACT_FIELDS_INVALID');
  if (contract.version !== SECURITY_CONTRACT
      || contract.central_guard_required !== true
      || contract.central_guard !== 'dirac-central-security-guard-v146'
      || contract.action !== payload.action
      || contract.vercel2_only !== true
      || contract.response_format !== 'json'
      || contract.single_kek_envelope_required !== true
      || contract.existing_three_inputs_required !== true
      || contract.hybrid_transport_required !== true
      || contract.atomic_replay_claim_required !== true
      || contract.dual_signature_required !== true
      || contract.no_legacy_fallback !== true
      || contract.one_time_copy !== true
      || contract.recovery_code_length !== 1200
      || contract.email_secret_length !== 100
      || contract.website_secret_length !== 100) {
    throw fail('MANIFEST_CONTRACT_POLICY_INVALID');
  }
  return true;
}

async function createVault(options) {
  assertRuntimePolicy();
  const required = ['requestId', 'expiresAt', 'nowIso', 'officialOrigin', 'passwordMaterial', 'emailSecret', 'websiteSecret', 'recoveryCode'];
  for (const key of required) if (!String(options && options[key] || '')) throw fail('VAULT_INPUT_MISSING_' + key.toUpperCase());
  if (!/^[A-Za-z0-9_-]{16,120}$/.test(String(options.requestId))) throw fail('VAULT_REQUEST_ID_INVALID');
  if (String(options.officialOrigin) !== 'https://secure.diracgroup.store') throw fail('VAULT_ORIGIN_INVALID');
  const createdAtMs = parseIsoMsStrict(options.nowIso, 'VAULT_CREATED_AT_INVALID');
  const expiresAtMs = parseIsoMsStrict(options.expiresAt, 'VAULT_EXPIRES_AT_INVALID');
  if (expiresAtMs <= createdAtMs || expiresAtMs - createdAtMs > 15 * 60 * 1000) throw fail('VAULT_TIME_POLICY_INVALID');
  if (String(options.recoveryCode).length !== 1200 || !/^[A-Za-z0-9_-]{1200}$/.test(String(options.recoveryCode))) throw fail('RECOVERY_CODE_INVALID');
  if (!/^[A-Za-z0-9_-]{100}$/.test(String(options.emailSecret))
      || !/^[A-Za-z0-9_-]{100}$/.test(String(options.websiteSecret))) throw fail('RECOVERY_INPUT_FORMAT_INVALID');
  if (typeof options.argon2RawFn !== 'function' || typeof options.vaultMaterialFn !== 'function') throw fail('ARGON2_ADAPTER_MISSING');

  const randomBytes = options.randomBytes || crypto.randomBytes;
  const vaultSalt = Buffer.from(randomBytes(32));
  const vaultId = Buffer.from(randomBytes(32));
  const extraNonceEntropy = Buffer.from(randomBytes(32));
  const kekSalt = Buffer.from(randomBytes(32));
  const transportWrapSalt = Buffer.from(randomBytes(32));
  const dek = Buffer.from(randomBytes(32));
  if ([vaultSalt, vaultId, extraNonceEntropy, kekSalt, transportWrapSalt, dek].some((value) => value.length !== 32)) {
    throw fail('CSPRNG_OUTPUT_INVALID');
  }

  const argon2Params = Object.freeze({
    memoryCost: Number(options.argon2Params && options.argon2Params.memoryCost || 0),
    timeCost: Number(options.argon2Params && options.argon2Params.timeCost || 0),
    parallelism: Number(options.argon2Params && options.argon2Params.parallelism || 0),
    hashLength: 64
  });
  assertArgon2Profile(argon2Params);

  const requestId = String(options.requestId);
  const vaultIdB64u = b64u(vaultId);
  const dekWrapInfo = `dirac/recovery/v2/dek-wrap/${requestId}`;
  const transportWrapInfo = `dirac/recovery/v2/mlkem-secret/${requestId}`;
  const vaultMaterial = Buffer.from(options.vaultMaterialFn(
    options.passwordMaterial,
    options.emailSecret,
    options.websiteSecret,
    vaultSalt,
    vaultId
  ));

  let argonRaw;
  let vaultKek;
  let transportKek;
  let mlkem;
  let wrappedDek;
  let wrappedMlkemSecret;
  let payloadPlaintext;
  try {
    argonRaw = Buffer.from(await options.argon2RawFn(vaultMaterial, vaultSalt, 64));
    if (argonRaw.length !== 64) throw fail('ARGON2_OUTPUT_INVALID');

    // Domain-separated HKDF outputs. The same existing three inputs remain
    // mandatory; no new user factor is added.
    vaultKek = hkdfSha512(argonRaw, kekSalt, dekWrapInfo, 32);
    transportKek = hkdfSha512(argonRaw, transportWrapSalt, transportWrapInfo, 32);
    mlkem = (options.mlkemEncapsulateFn || mlkemEncapsulate)();

    const metadata = {
      schema: 'dirac-recovery-vault-metadata-v2',
      version: VERSION,
      purpose: PURPOSE,
      domain: String(options.officialOrigin),
      request_id: requestId,
      vault_id: vaultIdB64u,
      created_at: String(options.nowIso),
      not_before: String(options.nowIso),
      expires_at: String(options.expiresAt),
      generation: 2,
      one_time_use: true,
      payload_cipher: PAYLOAD_CIPHER,
      key_wrap: KEY_WRAP,
      kdf: KDF,
      dek_bits: 256,
      dek_protection: 'A256KW-enveloped-DEK',
      input_policy: 'password+email-secret-100+website-secret-100',
      transport_suite: HYBRID_SUITE,
      signature_policy: SIGNATURE_POLICY,
      argon2id_params: argon2Params,
      extra_nonce_entropy_hash: typeof options.extraEntropyHashFn === 'function'
        ? String(options.extraEntropyHashFn(extraNonceEntropy))
        : sha512B64u(extraNonceEntropy)
    };
    const aad = Buffer.from(jcs(metadata), 'utf8');
    payloadPlaintext = Buffer.from(jcs({
      magic: 'DIRAC-RECOVERY-PAYLOAD-V2',
      purpose: PURPOSE,
      vault_id: vaultIdB64u,
      request_id: requestId,
      issued_at: String(options.nowIso),
      expires_at: String(options.expiresAt),
      generation: 2,
      recovery_code: String(options.recoveryCode)
    }), 'utf8');
    const payload = aesGcmEncrypt(dek, payloadPlaintext, aad);

    wrappedDek = aesKwWrap(vaultKek, dek);
    wrappedMlkemSecret = aesKwWrap(transportKek, mlkem.sharedKey);

    const bundle = {
      version: VERSION,
      request_id: requestId,
      vault_id: vaultIdB64u,
      salt: b64u(vaultSalt),
      argon2id_params: argon2Params,
      hkdf_info: dekWrapInfo,
      metadata,
      metadata_signature: typeof options.metadataSignatureFn === 'function'
        ? String(options.metadataSignatureFn(metadata))
        : sha512B64u(Buffer.from(jcs(metadata), 'utf8')),
      payload: {
        cipher: PAYLOAD_CIPHER,
        nonce_b64url: b64u(payload.nonce),
        ciphertext_b64url: b64u(payload.ciphertext),
        tag_b64url: b64u(payload.tag)
      },
      key_protection: {
        policy: 'A256KW-enveloped-DEK',
        dek_wrap: {
          wrap: KEY_WRAP,
          kdf: KDF,
          key_id: 'dirac-vault-kek-v2',
          salt_b64url: b64u(kekSalt),
          hkdf_info: dekWrapInfo,
          wrapped_dek_b64url: b64u(wrappedDek)
        }
      },
      transport: {
        suite: HYBRID_SUITE,
        mlkem: 'ML-KEM-1024',
        mlkem_key_id: envText('DIRAC_RECOVERY_MLKEM1024_KEY_ID') || 'dirac-recovery-ml-kem-1024-2026-01',
        mlkem_ciphertext_b64url: b64u(mlkem.ciphertext),
        mlkem_ciphertext_sha512: sha512B64u(mlkem.ciphertext),
        wrapped_shared_secret_b64url: b64u(wrappedMlkemSecret),
        shared_secret_wrap_salt_b64url: b64u(transportWrapSalt),
        shared_secret_wrap_info: transportWrapInfo
      },
      // Compatibility aliases retained only for existing DB columns/readers.
      aes_nonce: b64u(payload.nonce),
      ciphertext: b64u(payload.ciphertext),
      auth_tag: b64u(payload.tag)
    };
    assertVaultBundlePolicy(bundle);
    return {
      vaultBundle: bundle,
      metadataForAad: metadata,
      aad,
      argon2Params,
      compatibility: { vaultSalt, vaultId, extraNonceEntropy, encrypted: payload }
    };
  } finally {
    vaultMaterial.fill(0);
    dek.fill(0);
    if (argonRaw) argonRaw.fill(0);
    if (vaultKek) vaultKek.fill(0);
    if (transportKek) transportKek.fill(0);
    if (mlkem && mlkem.sharedKey) mlkem.sharedKey.fill(0);
    if (wrappedDek) wrappedDek.fill(0);
    if (wrappedMlkemSecret) wrappedMlkemSecret.fill(0);
    if (payloadPlaintext) payloadPlaintext.fill(0);
  }
}

function rawX25519Public(keyObject) {
  const der = crypto.createPublicKey(keyObject).export({ format: 'der', type: 'spki' });
  const prefix = Buffer.from('302a300506032b656e032100', 'hex');
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) throw fail('X25519_PUBLIC_ENCODING_INVALID');
  return Buffer.from(der.subarray(prefix.length));
}

function x25519PublicFromRaw(raw) {
  const prefix = Buffer.from('302a300506032b656e032100', 'hex');
  return crypto.createPublicKey({ key: Buffer.concat([prefix, Buffer.from(raw)]), format: 'der', type: 'spki' });
}

function hpkeExtract(hash, salt, ikm) {
  const digestLength = hash === 'sha512' ? 64 : 32;
  const realSalt = Buffer.from(salt || Buffer.alloc(0));
  return crypto.createHmac(hash, realSalt.length ? realSalt : Buffer.alloc(digestLength, 0)).update(Buffer.from(ikm || Buffer.alloc(0))).digest();
}

function hpkeExpand(hash, prk, info, length) {
  const digestLength = hash === 'sha512' ? 64 : 32;
  if (!Number.isSafeInteger(length) || length < 0 || length > 255 * digestLength) throw fail('HPKE_EXPAND_INVALID');
  const blocks = [];
  let previous = Buffer.alloc(0);
  let total = 0;
  for (let index = 1; total < length; index += 1) {
    const next = crypto.createHmac(hash, Buffer.from(prk)).update(previous).update(Buffer.from(info || Buffer.alloc(0))).update(Buffer.from([index])).digest();
    if (previous.length) previous.fill(0);
    previous = next;
    blocks.push(next);
    total += next.length;
  }
  const output = Buffer.from(Buffer.concat(blocks).subarray(0, length));
  for (const block of blocks) block.fill(0);
  return output;
}

function i2osp(value, length) {
  const output = Buffer.alloc(length);
  let remaining = Number(value);
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = remaining & 255;
    remaining = Math.floor(remaining / 256);
  }
  if (remaining !== 0) throw fail('I2OSP_INVALID');
  return output;
}

function hpkeLabeledExtract(hash, suiteId, salt, label, ikm) {
  const labeled = Buffer.concat([Buffer.from('HPKE-v1', 'ascii'), suiteId, Buffer.from(label, 'ascii'), Buffer.from(ikm || Buffer.alloc(0))]);
  try { return hpkeExtract(hash, salt, labeled); } finally { labeled.fill(0); }
}

function hpkeLabeledExpand(hash, suiteId, prk, label, info, length) {
  const labeled = Buffer.concat([i2osp(length, 2), Buffer.from('HPKE-v1', 'ascii'), suiteId, Buffer.from(label, 'ascii'), Buffer.from(info || Buffer.alloc(0))]);
  try { return hpkeExpand(hash, prk, labeled, length); } finally { labeled.fill(0); }
}

function x25519HpkeShared(privateKey, encRaw) {
  const receiverPublicRaw = rawX25519Public(privateKey);
  const ephemeralPublicKey = x25519PublicFromRaw(encRaw);
  const dh = crypto.diffieHellman({ privateKey, publicKey: ephemeralPublicKey });
  if (dh.length !== 32 || crypto.timingSafeEqual(dh, Buffer.alloc(32))) {
    dh.fill(0);
    throw fail('X25519_DH_INVALID');
  }
  const kemSuiteId = Buffer.concat([Buffer.from('KEM', 'ascii'), i2osp(0x0020, 2)]);
  const kemContext = Buffer.concat([Buffer.from(encRaw), receiverPublicRaw]);
  const eaePrk = hpkeLabeledExtract('sha256', kemSuiteId, Buffer.alloc(0), 'eae_prk', dh);
  const shared = hpkeLabeledExpand('sha256', kemSuiteId, eaePrk, 'shared_secret', kemContext, 32);
  dh.fill(0); receiverPublicRaw.fill(0); kemSuiteId.fill(0); kemContext.fill(0); eaePrk.fill(0);
  return shared;
}

function envelopeAad(body, mlkemCiphertextHash) {
  return {
    action: String(body.action || ''),
    version: ENVELOPE_VERSION,
    purpose: PURPOSE,
    origin: 'https://secure.diracgroup.store',
    request_id: String(body.request_id || ''),
    hpke_suite: HYBRID_SUITE,
    hpke_key_id: String(body.hpke_key_id || ''),
    mlkem_key_id: String(body.mlkem_key_id || ''),
    mlkem_ciphertext_sha512: String(mlkemCiphertextHash || ''),
    sent_at_ms: Number(body.sent_at_ms),
    expires_at_ms: Number(body.expires_at_ms)
  };
}

function validateEnvelope(body, expectedHpkeKeyId, expectedMlkemKeyId) {
  const source = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const now = Date.now();
  if (source.version !== ENVELOPE_VERSION || source.hpke_suite !== HYBRID_SUITE) throw fail('HYBRID_ENVELOPE_VERSION_INVALID');
  if (!/^[A-Za-z0-9_-]{16,120}$/.test(String(source.request_id || ''))) throw fail('HYBRID_REQUEST_ID_INVALID');
  if (String(source.hpke_key_id || '') !== String(expectedHpkeKeyId || '') || String(source.mlkem_key_id || '') !== String(expectedMlkemKeyId || '')) throw fail('HYBRID_KEY_ID_INVALID');
  const sentAt = Number(source.sent_at_ms);
  const expiresAt = Number(source.expires_at_ms);
  if (!Number.isSafeInteger(sentAt) || !Number.isSafeInteger(expiresAt) || sentAt > now + MAX_CLOCK_SKEW_MS || now - sentAt > MAX_ENVELOPE_LIFETIME_MS || expiresAt <= now || expiresAt <= sentAt || expiresAt - sentAt > MAX_ENVELOPE_LIFETIME_MS) {
    throw fail('HYBRID_ENVELOPE_TIME_INVALID');
  }
  decodeB64u(source.enc, 32, 128).fill(0);
  decodeB64u(source.aead_nonce, 12, 128).fill(0);
  decodeB64u(source.ciphertext, null, 64 * 1024).fill(0);
  return true;
}

function openHybridEnvelope(options) {
  const body = options.body;
  const bundle = options.bundle;
  const xPrivate = options.x25519PrivateKey || parsePrivateKey(envText('DIRAC_RECOVERY_HPKE_PRIVATE_KEY'), 'x25519');
  validateEnvelope(body, options.expectedHpkeKeyId, bundle.transport.mlkem_key_id);
  const enc = decodeB64u(body.enc, 32, 128);
  const nonce = decodeB64u(body.aead_nonce, 12, 128);
  const sealed = decodeB64u(body.ciphertext, null, 64 * 1024);
  if (sealed.length < 17) throw fail('HYBRID_CIPHERTEXT_INVALID');
  const mlkemCiphertext = decodeB64u(bundle.transport.mlkem_ciphertext_b64url, null, 8192);
  if (sha512B64u(mlkemCiphertext) !== bundle.transport.mlkem_ciphertext_sha512) throw fail('MLKEM_CIPHERTEXT_HASH_INVALID');
  let classicShared;
  let pqShared;
  let hybridKey;
  let transcriptHash;
  let plaintext;
  try {
    classicShared = x25519HpkeShared(xPrivate, enc);
    pqShared = (options.mlkemDecapsulateFn || mlkemDecapsulate)(mlkemCiphertext);
    const aadObject = envelopeAad(body, bundle.transport.mlkem_ciphertext_sha512);
    const aad = Buffer.from(jcs(aadObject), 'utf8');
    transcriptHash = sha512(aad);
    hybridKey = hkdfSha512(Buffer.concat([classicShared, pqShared]), transcriptHash, `dirac/recovery/v2/hybrid-transport/${body.request_id}`, 32);
    plaintext = aesGcmDecrypt(hybridKey, nonce, sealed.subarray(0, sealed.length - 16), sealed.subarray(sealed.length - 16), aad);
    const responseKey = hkdfSha512(hybridKey, transcriptHash, `dirac/recovery/v2/hybrid-response/${body.request_id}`, 32);
    return { plaintext, responseKey, transcriptHash, aadObject };
  } finally {
    enc.fill(0); nonce.fill(0); sealed.fill(0); mlkemCiphertext.fill(0);
    if (classicShared) classicShared.fill(0);
    if (pqShared) pqShared.fill(0);
    if (hybridKey) hybridKey.fill(0);
  }
}

function parseHybridPlaintext(plaintext, requestId) {
  const bytes = Buffer.from(plaintext);
  let parsed;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
    if (jcs(parsed) !== text) throw fail('HYBRID_PLAINTEXT_NON_CANONICAL');
  } catch (error) {
    if (error && error.code === 'HYBRID_PLAINTEXT_NON_CANONICAL') throw error;
    throw fail('HYBRID_PLAINTEXT_INVALID');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw fail('HYBRID_PLAINTEXT_INVALID');
  const expected = ['dek_b64url', 'request_id', 'signed_manifest', 'vault_bundle_sha512', 'version'];
  const keys = Object.keys(parsed).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw fail('HYBRID_PLAINTEXT_FIELDS_INVALID');
  if (parsed.version !== PLAINTEXT_VERSION || parsed.request_id !== requestId) throw fail('HYBRID_PLAINTEXT_BINDING_INVALID');
  const dek = decodeB64u(parsed.dek_b64url, 32, 128);
  return { parsed, dek };
}

async function openVaultPayload(options) {
  const bundle = options.bundle;
  assertVaultBundlePolicy(bundle);
  const dek = Buffer.from(options.dek || Buffer.alloc(0));
  if (dek.length !== 32) {
    if (dek.length) dek.fill(0);
    throw fail('DEK_LENGTH_INVALID');
  }
  let plaintext;
  try {
    const aad = Buffer.from(jcs(bundle.metadata), 'utf8');
    plaintext = aesGcmDecrypt(
      dek,
      decodeB64u(bundle.payload.nonce_b64url, 12, 128),
      decodeB64u(bundle.payload.ciphertext_b64url, null, 64 * 1024),
      decodeB64u(bundle.payload.tag_b64url, 16, 128),
      aad
    );
    return parseInnerPayload(plaintext, bundle);
  } finally {
    dek.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}

function parseInnerPayload(plaintext, bundle) {
  let parsed;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(plaintext));
    parsed = JSON.parse(text);
    if (jcs(parsed) !== text) throw fail('INNER_PAYLOAD_NON_CANONICAL');
  } catch (error) {
    if (error && error.code === 'INNER_PAYLOAD_NON_CANONICAL') throw error;
    throw fail('INNER_PAYLOAD_JSON_INVALID');
  }
  const expected = ['expires_at', 'generation', 'issued_at', 'magic', 'purpose', 'recovery_code', 'request_id', 'vault_id'];
  const keys = Object.keys(parsed || {}).sort();
  if (!parsed || keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw fail('INNER_PAYLOAD_FIELDS_INVALID');
  if (parsed.magic !== 'DIRAC-RECOVERY-PAYLOAD-V2' || parsed.purpose !== PURPOSE || parsed.generation !== 2 || parsed.request_id !== bundle.request_id || parsed.vault_id !== bundle.vault_id) {
    throw fail('INNER_PAYLOAD_BINDING_INVALID');
  }
  const expiresAt = parseIsoMsStrict(parsed.expires_at, 'INNER_EXPIRES_AT_INVALID');
  const issuedAt = parseIsoMsStrict(parsed.issued_at, 'INNER_ISSUED_AT_INVALID');
  const metadataIssuedAt = parseIsoMsStrict(bundle.metadata.created_at, 'INNER_METADATA_CREATED_AT_INVALID');
  const metadataExpiresAt = parseIsoMsStrict(bundle.metadata.expires_at, 'INNER_METADATA_EXPIRES_AT_INVALID');
  if (expiresAt <= Date.now()
      || issuedAt > Date.now() + MAX_CLOCK_SKEW_MS
      || issuedAt >= expiresAt
      || issuedAt !== metadataIssuedAt
      || expiresAt !== metadataExpiresAt) throw fail('INNER_PAYLOAD_EXPIRED');
  if (typeof parsed.recovery_code !== 'string' || !/^[A-Za-z0-9_-]{1200}$/.test(parsed.recovery_code)) throw fail('INNER_RECOVERY_CODE_INVALID');
  return parsed;
}

function buildManifest(options) {
  const row = options.row || {};
  const bundle = options.bundle;
  if (!bundle || bundle.version !== VERSION) throw fail('MANIFEST_VAULT_VERSION_INVALID');
  const hpkePublicRaw = Buffer.from(options.hpkePublicRaw);
  if (hpkePublicRaw.length !== 32) throw fail('MANIFEST_HPKE_KEY_INVALID');
  if (!bundle.key_protection || bundle.key_protection.policy !== 'A256KW-enveloped-DEK' || !bundle.key_protection.dek_wrap) {
    throw fail('MANIFEST_DEK_PROTECTION_INVALID');
  }
  const dekWrap = bundle.key_protection.dek_wrap;
  if (dekWrap.wrap !== KEY_WRAP || dekWrap.kdf !== KDF || dekWrap.hkdf_info !== bundle.hkdf_info) {
    throw fail('MANIFEST_DEK_WRAP_POLICY_INVALID');
  }
  const bundleCanonical = Buffer.from(jcs(bundle), 'utf8');
  const metadataCanonical = Buffer.from(jcs(bundle.metadata), 'utf8');
  const payloadCiphertext = decodeB64u(bundle.payload.ciphertext_b64url, null, 64 * 1024);
  const payloadNonce = decodeB64u(bundle.payload.nonce_b64url, 12, 128);
  const payloadTag = decodeB64u(bundle.payload.tag_b64url, 16, 128);
  const wrappedDek = decodeB64u(dekWrap.wrapped_dek_b64url, 40, 256);
  const kekSalt = decodeB64u(dekWrap.salt_b64url, 32, 128);
  try {
    return {
      manifest_schema: MANIFEST_SCHEMA,
      version: VERSION,
      minimum_reader_version: 2,
      legacy_fallback_allowed: false,
      purpose: PURPOSE,
      action: String(options.action || ''),
      request_id: String(bundle.request_id),
      vault_id: String(bundle.vault_id),
      signature_policy: SIGNATURE_POLICY,
      key_id: envText('DIRAC_LOST_PASSKEY_ED25519_KEY_ID') || 'dirac-recovery-ed25519-2026-01',
      signature_alg: 'Ed25519+ML-DSA-87',
      signature_algorithms: ['Ed25519', 'ML-DSA-87'],
      canonicalization: 'RFC8785-JCS',
      cipher: PAYLOAD_CIPHER,
      dek_bits: 256,
      dek_protection: 'A256KW-enveloped-DEK',
      key_wrap: KEY_WRAP,
      kdf: KDF,
      argon2id_params: bundle.argon2id_params,
      input_factor_policy: 'password+email-secret-100+website-secret-100',
      transport_suite: HYBRID_SUITE,
      hpke_key_id: String(options.hpkeKeyId),
      hpke_public_key_b64url: b64u(hpkePublicRaw),
      hpke_public_key_sha512: sha512B64u(hpkePublicRaw),
      mlkem_key_id: String(bundle.transport.mlkem_key_id),
      mlkem_ciphertext_sha512: String(bundle.transport.mlkem_ciphertext_sha512),
      payload_ciphertext_sha512: sha512B64u(payloadCiphertext),
      payload_nonce_sha512: sha512B64u(payloadNonce),
      payload_tag_sha512: sha512B64u(payloadTag),
      metadata_sha512: sha512B64u(metadataCanonical),
      wrapped_dek_sha512: sha512B64u(wrappedDek),
      kek_salt_sha512: sha512B64u(kekSalt),
      kek_key_id: String(dekWrap.key_id),
      kek_hkdf_info: String(dekWrap.hkdf_info),
      vault_bundle_sha512: sha512B64u(bundleCanonical),
      security_contract: {
        version: SECURITY_CONTRACT,
        central_guard_required: true,
        central_guard: String(options.centralGuard || ''),
        action: String(options.action || ''),
        vercel2_only: true,
        response_format: 'json',
        single_kek_envelope_required: true,
        existing_three_inputs_required: true,
        hybrid_transport_required: true,
        atomic_replay_claim_required: true,
        dual_signature_required: true,
        no_legacy_fallback: true,
        one_time_copy: true,
        recovery_code_length: 1200,
        email_secret_length: 100,
        website_secret_length: 100
      },
      created_at: String(bundle.metadata.created_at || ''),
      not_before: String(bundle.metadata.not_before || ''),
      expires_at: String(bundle.metadata.expires_at || '')
    };
  } finally {
    bundleCanonical.fill(0); metadataCanonical.fill(0); payloadCiphertext.fill(0); payloadNonce.fill(0); payloadTag.fill(0);
    wrappedDek.fill(0); kekSalt.fill(0);
  }
}

function makeSignedVaultResponse(options) {
  const payload = buildManifest(options);
  const signatures = dualSignManifest(payload);
  return {
    ok: true,
    version: VERSION,
    purpose: PURPOSE,
    request_id: payload.request_id,
    expires_at: payload.expires_at,
    vault_bundle: options.bundle,
    signed_manifest: {
      payload,
      signatures,
      // Retained for the existing local Ed25519 verifier.
      signature_b64: signatures.ed25519.signature_b64url
    },
    manifest: payload,
    signatures
  };
}

function verifySignedManifestContainer(container) {
  if (!container || typeof container !== 'object' || Array.isArray(container)) throw fail('SIGNED_MANIFEST_MISSING');
  const containerKeys = Object.keys(container).sort();
  const expectedContainerKeys = ['payload', 'signature_b64', 'signatures'];
  if (containerKeys.length !== expectedContainerKeys.length || containerKeys.some((key, index) => key !== expectedContainerKeys[index])) throw fail('SIGNED_MANIFEST_FIELDS_INVALID');
  const payload = container.payload;
  const signatures = container.signatures;
  verifyDualManifest(payload, signatures);
  assertManifestPolicy(payload);
  if (container.signature_b64 !== signatures.ed25519.signature_b64url) throw fail('SIGNED_MANIFEST_ALIAS_INVALID');
  return payload;
}

async function atomicClaim(supabaseFetch, body, bundle, row) {
  if (typeof supabaseFetch !== 'function') throw fail('ATOMIC_CLAIM_ADAPTER_MISSING');
  const requestId = String(body && body.request_id || '');
  const rowMetadata = row && row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata)
    ? row.metadata
    : null;
  if (!rowMetadata || String(row && row.request_id || '') !== requestId) throw fail('ATOMIC_REPLAY_STORAGE_UNAVAILABLE');

  const claimHash = sha512B64u(Buffer.from(jcs({
    request_id: requestId,
    enc: body.enc,
    aead_nonce: body.aead_nonce,
    ciphertext: body.ciphertext,
    mlkem_ciphertext_sha512: bundle.transport.mlkem_ciphertext_sha512
  }), 'utf8'));
  const claimedAt = new Date().toISOString();
  const claimField = 'hybrid_v2_claim_hash';
  const path = '/rest/v1/security_lost_passkey_recovery_requests'
    + '?select=' + encodeURIComponent('request_id,status,metadata')
    + '&request_id=eq.' + encodeURIComponent(requestId)
    + '&status=eq.pending'
    + '&used_at=is.null'
    + '&revoked_at=is.null'
    + '&locked_at=is.null'
    + '&expires_at=gt.' + encodeURIComponent(claimedAt)
    + '&' + encodeURIComponent('metadata->>' + claimField) + '=is.null';
  const result = await supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      metadata: {
        ...rowMetadata,
        [claimField]: claimHash,
        hybrid_v2_claimed_at: claimedAt
      }
    }
  });

  if (!result || result.ok !== true) throw fail('ATOMIC_REPLAY_STORAGE_UNAVAILABLE');
  if (!Array.isArray(result.data)) throw fail('ATOMIC_REPLAY_STORAGE_UNAVAILABLE');
  if (result.data.length === 0) throw fail('ATOMIC_REPLAY_REJECTED');
  if (result.data.length !== 1) throw fail('ATOMIC_REPLAY_STORAGE_UNAVAILABLE');
  const claimedRow = result.data[0];
  const claimedMetadata = claimedRow && claimedRow.metadata && typeof claimedRow.metadata === 'object' && !Array.isArray(claimedRow.metadata)
    ? claimedRow.metadata
    : null;
  if (!claimedRow
      || String(claimedRow.request_id || '') !== requestId
      || String(claimedRow.status || '') !== 'pending'
      || !claimedMetadata
      || String(claimedMetadata[claimField] || '') !== claimHash
      || String(claimedMetadata.hybrid_v2_claimed_at || '') !== claimedAt) {
    throw fail('ATOMIC_REPLAY_STORAGE_UNAVAILABLE');
  }
  // Preserve the durable claim marker in every later PATCH that spreads
  // row.metadata (for example the existing failed-verification counter path).
  row.metadata = claimedMetadata;
  return claimHash;
}

function encryptResponse(responseKey, transcriptHash, requestId, recoveryCode) {
  const aadObject = { version: RESPONSE_VERSION, purpose: PURPOSE, request_id: String(requestId) };
  const aad = Buffer.from(jcs(aadObject), 'utf8');
  const plaintext = Buffer.from(jcs({
    version: RESPONSE_VERSION,
    request_id: String(requestId),
    recovery_code: String(recoveryCode)
  }), 'utf8');
  try {
    const encrypted = aesGcmEncrypt(responseKey, plaintext, aad);
    const sealed = {
      version: RESPONSE_VERSION,
      request_id: String(requestId),
      aead_nonce: b64u(encrypted.nonce),
      ciphertext: b64u(Buffer.concat([encrypted.ciphertext, encrypted.tag])),
      transcript_sha512: b64u(transcriptHash)
    };
    const checkedNonce = decodeB64u(sealed.aead_nonce, 12, 128);
    const checkedCiphertext = decodeB64u(sealed.ciphertext, null, 64 * 1024);
    const checkedTranscript = decodeB64u(sealed.transcript_sha512, 64, 128);
    try {
      if (checkedCiphertext.length < 17) throw fail('SEALED_RECOVERY_CIPHERTEXT_LENGTH_INVALID');
      return sealed;
    } finally {
      checkedNonce.fill(0);
      checkedCiphertext.fill(0);
      checkedTranscript.fill(0);
    }
  } finally {
    aad.fill(0); plaintext.fill(0);
  }
}

return Object.freeze({
  VERSION,
  MANIFEST_SCHEMA,
  SECURITY_CONTRACT,
  ENVELOPE_VERSION,
  PLAINTEXT_VERSION,
  RESPONSE_VERSION,
  PURPOSE,
  HYBRID_SUITE,
  PAYLOAD_CIPHER,
  KEY_WRAP,
  KDF,
  SIGNATURE_POLICY,
  jcs,
  b64u,
  decodeB64u,
  sha512B64u,
  hkdfSha512,
  aesKwWrap,
  aesKwUnwrap,
  aesGcmEncrypt,
  aesGcmDecrypt,
  assertRuntimePolicy,
  assertExactObjectKeys,
  assertArgon2Profile,
  assertVaultBundlePolicy,
  assertManifestPolicy,
  mlkemEncapsulate,
  mlkemDecapsulate,
  dualSignManifest,
  verifyDualManifest,
  createVault,
  rawX25519Public,
  x25519HpkeShared,
  envelopeAad,
  validateEnvelope,
  openHybridEnvelope,
  parseHybridPlaintext,
  openVaultPayload,
  parseInnerPayload,
  buildManifest,
  makeSignedVaultResponse,
  verifySignedManifestContainer,
  atomicClaim,
  encryptResponse,
  fail
});
})();

/* source 1189-1194 */
const DEFAULT_ALLOWED_ORIGINS = [
  'https://diracgroup.store',
  'https://www.diracgroup.store',
  'https://companyprofilee-ochre.vercel.app',
  'https://companyprofilee-expk.vercel.app'
];

/* source 1210-1241 */
const DOMAIN_ACTION_ALIASES = Object.freeze({
  'domain-health': 'domain_health',
  'domain_health': 'domain_health',
  'hostinger-check': 'hostinger_check',
  'hostinger_check': 'hostinger_check',
  'hostinger-domain-check': 'hostinger_check',
  'domain_hostinger_check': 'hostinger_check',
  'check-domain': 'domain_check',
  'domain_check': 'domain_check',
  'create-order': 'domain_checkout',
  'domain_create_order': 'domain_checkout',
  'get-orders': 'domain_orders',
  'domain_get_orders': 'domain_orders',
  'domain-login': 'domain_login',
  'domain_login': 'domain_login',
  'login-domain': 'domain_login',
  'domain-register': 'domain_register',
  'domain_register': 'domain_register',
  'register-domain': 'domain_register',
  'domain-me': 'domain_me',
  'domain-dashboard-me': 'domain_dashboard_me',
  'domain_dashboard_me': 'domain_dashboard_me',
  'dashboard-me': 'domain_dashboard_me',
  'dashboard_me': 'domain_dashboard_me',
  'dashboard-summary': 'domain_dashboard_me',
  'dashboard_summary': 'domain_dashboard_me',
  'domain_logout': 'domain_logout',
  'domain-logout': 'domain_logout',
  'domain-mfa-status': 'domain_mfa_status',
  'domain_mfa_status': 'domain_mfa_status',
  'dashboard-mfa-status': 'domain_mfa_status'
});

/* source 1361-1370 */
function getAllowedOrigins() {
  const server2RecoveryOnly = /^(vercel2)$/i.test(String(process.env.DIRAC_CENTRAL_DEPLOYMENT_ROLE || process.env.DIRAC_DEPLOYMENT_ROLE || '').trim())
    || /^(1|true|yes|on|enabled|enable)$/i.test(String(process.env.DIRAC_CENTRAL_VERCEL2_ACTIONS_ENABLED || process.env.DIRAC_VERCEL2_ACTIONS_ENABLED || '').trim());
  if (server2RecoveryOnly) return ['https://secure.diracgroup.store'];

  const fromEnv = String(process.env.AI_ALLOWED_ORIGINS || '').split(',').map((item) => item.trim()).filter(Boolean);
  const domainSite = String(process.env.DOMAIN_SITE_URL || '').trim();
  const dev = process.env.NODE_ENV !== 'production' ? ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5173', 'http://127.0.0.1:5173'] : [];
  return Array.from(new Set([...DEFAULT_ALLOWED_ORIGINS, domainSite, ...fromEnv, ...dev].filter(Boolean)));
}

/* source 1382-1385 */
function normalizeDomainAction(action) {
  const cleanAction = String(action || '').trim();
  return DOMAIN_ACTION_ALIASES[cleanAction] || cleanAction;
}

/* source 1406-1406 */
const ACCESS_COOKIE = process.env.DOMAIN_SESSION_COOKIE || 'dirac_domain_session';

/* source 1407-1407 */
const REFRESH_COOKIE = process.env.DOMAIN_REFRESH_COOKIE || 'dirac_domain_refresh';

/* source 1408-1408 */
const CUSTOMER_MFA_COOKIE = process.env.DIRAC_CUSTOMER_MFA_COOKIE || 'dirac_customer_mfa_session';

/* source 1409-1409 */
const DOMAIN_SIGNED_SESSION_COOKIE = process.env.DOMAIN_SIGNED_SESSION_COOKIE || 'dirac_domain_signed_session';

/* source 1410-1410 */
const CUSTOMER_MFA_SESSION_TYPE = 'dirac-customer-mfa-session-v1';

/* source 1411-1411 */
const DOMAIN_SIGNED_SESSION_TYPE = 'dirac-domain-signed-session-v1';

/* Dedicated security database tables. Names are fixed to the hardened schema. */
const DIRAC_PERSISTENT_BAN_TABLE = 'dirac_persistent_bans';
const DIRAC_S2S_SECURITY_TABLE = 'dirac_s2s_security';
const LOGIN_SECURITY_PERSIST_TABLE = DIRAC_PERSISTENT_BAN_TABLE;

/* source 1469-1469 */
const LOGIN_SECURITY_PERSIST_TTL_SECONDS = 10 * 365 * 24 * 60 * 60;

function diracPersistentSecurityTableForKeyV209(securityKey) {
  const key = String(securityKey || '').trim();
  if (/^(?:s2s-|recovery-worker-nonce-v183:)/.test(key)) return DIRAC_S2S_SECURITY_TABLE;
  return DIRAC_PERSISTENT_BAN_TABLE;
}

function diracPersistentSecurityTableForKeysV209(securityKeys) {
  const tables = new Set((securityKeys || []).map(diracPersistentSecurityTableForKeyV209));
  return tables.size === 1 ? Array.from(tables)[0] : '';
}

/* source 1906-1912 */
function isStrictDomainLoginEmail(email) {
  const value = String(email || '').trim();
  if (!/^[a-z0-9@.]+$/.test(value)) return false;
  if ((value.match(/@/g) || []).length !== 1) return false;
  if (value.startsWith('.') || value.endsWith('.') || value.includes('..')) return false;
  return /^[a-z0-9]+(?:\.[a-z0-9]+)*@[a-z0-9]+(?:\.[a-z0-9]+)+$/.test(value);
}

/* source 1997-2007 */
function getLoginSecurityIp(req) {
  try {
    if (typeof diracCentralTrustedClientIpV183 === 'function') {
      return diracCentralTrustedClientIpV183(req);
    }
  } catch (_) {}
  const headers = (req && req.headers) || {};
  const vercelForwarded = String(headers['x-vercel-forwarded-for'] || '').split(',')[0].trim();
  const forwarded = String(headers['x-forwarded-for'] || '').split(',')[0].trim();
  return vercelForwarded || forwarded || String(headers['x-real-ip'] || req.socket && req.socket.remoteAddress || '').trim() || 'unknown';
}

/* source 2091-2107 */
async function readPersistentSecurityJson(securityKey) {
  const key = String(securityKey || '').trim();
  const table = diracPersistentSecurityTableForKeyV209(key);
  if (!table || !key) return null;

  try {
    const path = `/rest/v1/${encodeURIComponent(table)}?select=security_key,record_json,blocked_until_ms,expires_at&security_key=eq.${encodeURIComponent(key)}&limit=1`;
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok || !Array.isArray(result.data) || !result.data.length) return null;

    const row = result.data[0] || {};
    const expiresAtMs = Date.parse(row.expires_at || '');
    if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) return null;
    return row.record_json && typeof row.record_json === 'object' ? row.record_json : null;
  } catch (_) {
    return null;
  }
}

/* source 2109-2135 */
async function writePersistentSecurityJson(securityKey, record, blockedUntilMs = 0, ttlSeconds = LOGIN_SECURITY_PERSIST_TTL_SECONDS) {
  const key = String(securityKey || '').trim();
  const table = diracPersistentSecurityTableForKeyV209(key);
  if (!table || !key) return false;

  try {
    const now = Date.now();
    const safeRecord = record && typeof record === 'object' ? record : {};
    const expiresAt = new Date(now + Math.max(60, Number(ttlSeconds || 60)) * 1000).toISOString();
    const payload = [{
      security_key: key,
      record_json: safeRecord,
      blocked_until_ms: Number(blockedUntilMs || 0),
      updated_at: new Date(now).toISOString(),
      expires_at: expiresAt
    }];

    const result = await supabaseFetch(`/rest/v1/${encodeURIComponent(table)}?on_conflict=security_key`, {
      method: 'POST',
      auth: 'service',
      prefer: 'resolution=merge-duplicates',
      body: payload
    });
    return !!result.ok;
  } catch (_) {
    return false;
  }
}

/* source 2140-2162 */
async function readPersistentSecurityJsonStrictV194(securityKey) {
  const key = String(securityKey || '').trim();
  const table = diracPersistentSecurityTableForKeyV209(key);
  if (!table || !key) return { ok: false, found: false, record: null };
  try {
    const path = `/rest/v1/${encodeURIComponent(table)}?select=security_key,record_json,blocked_until_ms,expires_at&security_key=eq.${encodeURIComponent(key)}&limit=1`;
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result || result.ok !== true || !Array.isArray(result.data)) {
      return { ok: false, found: false, record: null };
    }
    if (result.data.length === 0) return { ok: true, found: false, record: null };
    const row = result.data[0] || {};
    const expiresAtMs = Date.parse(String(row.expires_at || ''));
    if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) {
      return { ok: true, found: false, record: null };
    }
    const record = row.record_json && typeof row.record_json === 'object'
      ? { ...row.record_json, blocked_until_ms: Number(row.blocked_until_ms || row.record_json.blocked_until_ms || 0) }
      : { blocked_until_ms: Number(row.blocked_until_ms || 0) };
    return { ok: true, found: true, record };
  } catch (_) {
    return { ok: false, found: false, record: null };
  }
}

/* source 2187-2194 */
async function writePersistentSecurityJsonRequiredV194(securityKey, record, blockedUntilMs, ttlSeconds) {
  if (!diracPersistentSecurityTableForKeyV209(securityKey) || typeof writePersistentSecurityJson !== 'function') return false;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const wrote = await writePersistentSecurityJson(securityKey, record, blockedUntilMs, ttlSeconds).catch(() => false);
    if (wrote === true) return true;
  }
  return false;
}

/* source 2196-2220 */
async function claimPersistentSecurityKeyOnceV194(securityKey, record, ttlSeconds) {
  const key = String(securityKey || '').trim();
  const table = diracPersistentSecurityTableForKeyV209(key);
  if (!table || !key) return false;
  const now = Date.now();
  const ttl = Math.max(60, Number(ttlSeconds || 60));
  const payload = [{
    security_key: key,
    record_json: record && typeof record === 'object' ? record : {},
    blocked_until_ms: 0,
    updated_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl * 1000).toISOString()
  }];
  try {
    const result = await supabaseFetch(`/rest/v1/${encodeURIComponent(table)}?on_conflict=security_key`, {
      method: 'POST',
      auth: 'service',
      prefer: 'resolution=ignore-duplicates,return=representation',
      body: payload
    });
    return Boolean(result && result.ok === true && Array.isArray(result.data) && result.data.length === 1
      && String(result.data[0] && result.data[0].security_key || '') === key);
  } catch (_) {
    return false;
  }
}

/* source 2267-2269 */
function loginSecurityHash(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

/* source 2776-2804 */
async function getSupabaseAuthUserByEmail(email) {
  const normalizedEmail = normalizeAuthEmail(email);
  if (!normalizedEmail || !isStrictDomainLoginEmail(normalizedEmail)) return { user: null, checked: false };

  try {
    const result = await supabaseFetch(`/auth/v1/admin/users?email=${encodeURIComponent(normalizedEmail)}`, {
      method: 'GET',
      auth: 'service'
    });

    if (!result.ok || !result.data) return { user: null, checked: false };

    const data = result.data;
    const candidates = [];
    if (Array.isArray(data)) candidates.push(...data);
    if (Array.isArray(data.users)) candidates.push(...data.users);
    if (data.user && typeof data.user === 'object') candidates.push(data.user);

    const user = candidates.find((item) => {
      if (!item || typeof item !== 'object') return false;
      const userEmail = normalizeAuthEmail(item.email || item.email_address || '');
      return userEmail === normalizedEmail;
    }) || null;

    return { user, checked: true };
  } catch (_) {
    return { user: null, checked: false };
  }
}

/* source 2806-2810 */
function normalizeSupabaseAdminUser(data) {
  if (!data || typeof data !== 'object') return null;
  if (data.user && typeof data.user === 'object') return data.user;
  return data;
}

/* source 3630-3692 */
async function requireDomainUser(req, res) {
  const cookies = parseCookies(req);
  const acceptFrontendAuthHeaders = shouldAcceptFrontendAuthHeaders();
  const headerToken = acceptFrontendAuthHeaders ? getBearerToken(req) : '';
  const headerRefreshToken = acceptFrontendAuthHeaders
    ? String((req.headers && (req.headers['x-domain-refresh'] || req.headers['x-refresh-token'])) || '').trim()
    : '';

  const accessTokens = uniqueNonEmptyStrings([
    headerToken,
    ...readCookieTokenCandidates(cookies, ACCESS_COOKIE)
  ]);

  for (const accessToken of accessTokens) {
    const userResult = await supabaseFetch('/auth/v1/user', {
      method: 'GET',
      auth: 'anon',
      bearer: accessToken
    });

    if (userResult.ok && userResult.data && userResult.data.id) {
      return userResult.data;
    }
  }

  const refreshTokens = uniqueNonEmptyStrings([
    headerRefreshToken,
    ...readCookieTokenCandidates(cookies, REFRESH_COOKIE)
  ]);

  for (const refreshToken of refreshTokens) {
    const refreshResult = await supabaseFetch('/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      auth: 'anon',
      body: { refresh_token: refreshToken }
    });

    if (refreshResult.ok && refreshResult.data && refreshResult.data.access_token) {
      const refreshedSession = Object.assign({}, refreshResult.data, {
        refresh_token: refreshResult.data.refresh_token || refreshToken
      });
      if (hasValidDomainSessionTokens(refreshedSession)) {
        setSessionCookies(res, refreshedSession);
        if (!shouldHideDomainAuthTokens()) {
          res.setHeader('X-Domain-Access-Token', refreshedSession.access_token);
          res.setHeader('X-Domain-Refresh-Token', refreshedSession.refresh_token);
        }
        res.setHeader('X-Domain-Token-Refreshed', 'true');
        return refreshedSession.user || refreshResult.data.user;
      }
    }
  }

  const signedSessionUser = await readSignedDomainSessionUser(cookies);
  if (signedSessionUser && signedSessionUser.id) {
    res.setHeader('X-Domain-Signed-Session', 'true');
    return signedSessionUser;
  }

  clearSessionCookies(res);
  res.status(401).json({ ok: false, message: 'Belum login atau sesi sudah habis.' });
  return null;
}

/* source 3703-3705 */
function signDashboardMfa(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

/* source 3707-3709 */
function hashDashboardMfa(value, secret) {
  return crypto.createHmac('sha256', secret).update(String(value || '')).digest('hex');
}

/* source 3711-3719 */
function getCustomerMfaSecret() {
  const secret = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  if (!secret || secret === 'rahasia-test' || Buffer.byteLength(secret, 'utf8') < diracCentralMinimumSecretBytesV146()) {
    const err = new Error('DIRAC_SECURITY_ROOT_SECRET production wajib memakai root secret acak minimal 3000 byte.');
    err.statusCode = 500;
    throw err;
  }
  return diracCentralDeriveSecretV146('customer-mfa', secret).toString('base64url');
}

/* source 3721-3723 */
function customerMfaProfileId(email) {
  return hashDashboardMfa(`dirac-customer-mfa-profile-v1:${normalizeAuthEmail(email)}`, getCustomerMfaSecret());
}

/* source 3725-3737 */
function decodeCustomerDashboardMfaToken(token) {
  const [payloadBase64, signature] = String(token || '').split('.');
  if (!payloadBase64 || !signature) return null;

  const expected = signDashboardMfa(payloadBase64, getCustomerMfaSecret());
  if (!safeEqual(signature, expected)) return null;

  try {
    return JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

/* source 3739-3747 */
function normalizeDashboardMfaOrigin(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw).origin;
  } catch (_) {
    return raw.replace(/\/+$/, '');
  }
}

/* source 3749-3752 */
function requestOrigin(req) {
  const headers = (req && req.headers) || {};
  return normalizeDashboardMfaOrigin(headers.origin) || normalizeDashboardMfaOrigin(headers.referer);
}

/* source 3754-3756 */
function requestUserAgent(req) {
  return String((req && req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
}

/* source 3758-3762 */
function customerMfaBindingHash(kind, value) {
  const text = String(value || '').trim();
  if (!text) return '';
  return hashDashboardMfa(`dirac-customer-mfa-binding-v2:${kind}:${text}`, getCustomerMfaSecret());
}

/* source 3764-3774 */
function getCustomerDashboardMfaToken(req) {
  const cookies = parseCookies(req);
  const cookieToken = String(cookies[CUSTOMER_MFA_COOKIE] || '').trim();
  if (cookieToken) return { token: cookieToken, source: 'http_only_cookie' };

  // PATCH 3B: full backend customer auth.
  // MFA proof dari header frontend sengaja ditolak. JavaScript tidak boleh membawa
  // X-Dirac-MFA-Proof / X-Dashboard-MFA-Proof / X-Dirac-Dashboard-MFA.
  // Satu-satunya sumber yang diterima adalah HttpOnly Secure cookie dari backend.
  return { token: '', source: 'missing_http_only_cookie' };
}

/* source 3776-3832 */
function verifyCustomerDashboardMfaCookie(req, user) {
  const proof = getCustomerDashboardMfaToken(req);
  const payload = decodeCustomerDashboardMfaToken(proof.token);
  const email = normalizeAuthEmail(user && user.email);
  const userId = String(user && user.id || '').trim();
  const customerId = String(user && (user.customer_id || user.customerId || user.customer || '') || '').trim();

  if (!payload || payload.type !== CUSTOMER_MFA_SESSION_TYPE) {
    return { ok: false, code: proof && proof.token ? 'mfa_cookie_invalid_or_unsigned' : 'mfa_cookie_missing', message: proof && proof.token ? 'Sesi A2F backend tidak valid. Login dan verifikasi A2F ulang dari domain resmi.' : 'Sesi A2F backend tidak ditemukan. Login dan verifikasi A2F ulang dari domain resmi.' };
  }

  if (!payload.expiresAtMs || Date.now() > Number(payload.expiresAtMs)) {
    return { ok: false, code: 'mfa_cookie_expired', message: 'Sesi A2F backend sudah expired. Login dan verifikasi A2F ulang.' };
  }

  if (!email || !payload.emailHash || !safeEqual(String(payload.emailHash), customerMfaProfileId(email))) {
    return { ok: false, code: 'mfa_cookie_user_mismatch', message: 'Sesi A2F backend tidak cocok dengan akun login.' };
  }

  if (!payload.authUserIdHash || !userId || !safeEqual(String(payload.authUserIdHash), customerMfaBindingHash('auth_user_id', userId))) {
    return { ok: false, code: 'mfa_cookie_auth_user_mismatch', message: 'Sesi A2F backend tidak cocok dengan akun login.' };
  }

  if (payload.customerIdHash && customerId && !safeEqual(String(payload.customerIdHash), customerMfaBindingHash('customer_id', customerId))) {
    return { ok: false, code: 'mfa_cookie_customer_mismatch', message: 'Sesi A2F backend tidak cocok dengan customer login.' };
  }

  if (payload.sessionHash) {
    let expectedSessionHash = '';
    try { expectedSessionHash = typeof diracCentralRequestSessionHashV146 === 'function' ? diracCentralRequestSessionHashV146(req) : ''; } catch (_) {}
    if (expectedSessionHash && !safeEqual(String(payload.sessionHash), expectedSessionHash)) {
      return { ok: false, code: 'mfa_cookie_session_mismatch', message: 'Sesi A2F backend tidak cocok dengan sesi login.' };
    }
  }

  if (payload.originHash) {
    const expectedOriginHash = customerMfaBindingHash('origin', requestOrigin(req));
    if (!expectedOriginHash || !safeEqual(String(payload.originHash), expectedOriginHash)) {
      return { ok: false, code: 'mfa_cookie_origin_mismatch', message: 'Sesi A2F backend tidak cocok dengan origin website ini. Login ulang dari domain resmi.' };
    }
  }

  if (payload.uaHash) {
    const expectedUaHash = customerMfaBindingHash('ua', requestUserAgent(req));
    if (!expectedUaHash || !safeEqual(String(payload.uaHash), expectedUaHash)) {
      return { ok: false, code: 'mfa_cookie_browser_mismatch', message: 'Sesi A2F backend tidak cocok dengan browser/perangkat ini. Login ulang dari browser yang sama.' };
    }
  }

  return {
    ok: true,
    method: String(payload.method || ''),
    activeAtMs: Number(payload.activeAtMs || 0),
    expiresAtMs: Number(payload.expiresAtMs || 0),
    source: proof.source
  };
}

/* source 4522-4563 */
const DIRAC_SUPABASE_TARGET_ENVS = Object.freeze({
  legacy: {
    url: 'DOMAIN_SUPABASE_URL',
    anonKey: 'DOMAIN_SUPABASE_ANON_KEY',
    serviceKey: 'DOMAIN_SUPABASE_SERVICE_ROLE_KEY'
  },
  security: {
    url: 'DIRAC_SECURITY_SUPABASE_URL',
    anonKey: 'DIRAC_SECURITY_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_SECURITY_SUPABASE_SERVICE_ROLE_KEY'
  },
  core: {
    url: 'DIRAC_CORE_SUPABASE_URL',
    anonKey: 'DIRAC_CORE_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_CORE_SUPABASE_SERVICE_ROLE_KEY'
  },
  adminGuard: {
    url: 'DIRAC_ADMIN_GUARD_SUPABASE_URL',
    anonKey: 'DIRAC_ADMIN_GUARD_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_ADMIN_GUARD_SUPABASE_SERVICE_ROLE_KEY'
  },
  customerSecurity: {
    url: 'DIRAC_CUSTOMER_SECURITY_SUPABASE_URL',
    anonKey: 'DIRAC_CUSTOMER_SECURITY_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_CUSTOMER_SECURITY_SUPABASE_SERVICE_ROLE_KEY'
  },
  publicMfa: {
    url: 'DIRAC_PUBLIC_MFA_SUPABASE_URL',
    anonKey: 'DIRAC_PUBLIC_MFA_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_PUBLIC_MFA_SUPABASE_SERVICE_ROLE_KEY'
  },
  domain: {
    url: 'DIRAC_DOMAIN_SUPABASE_URL',
    anonKey: 'DIRAC_DOMAIN_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_DOMAIN_SUPABASE_SERVICE_ROLE_KEY'
  },
  commerce: {
    url: 'DIRAC_COMMERCE_SUPABASE_URL',
    anonKey: 'DIRAC_COMMERCE_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_COMMERCE_SUPABASE_SERVICE_ROLE_KEY'
  },
  paymentService: {
    url: 'DIRAC_PAYMENT_SERVICE_SUPABASE_URL',
    anonKey: 'DIRAC_PAYMENT_SERVICE_SUPABASE_ANON_KEY',
    serviceKey: 'DIRAC_PAYMENT_SERVICE_SUPABASE_SERVICE_ROLE_KEY'
  }
});

/* source 4565-4616 */
const DIRAC_TABLE_DB_MAP = Object.freeze({
  customers: 'core',
  admin_users: 'core',
  settings: 'core',
  user_totp_mfa: 'core',
  a2f_locks: 'core',
  a2f_lockouts: 'core',
  admin_a2f_sessions: 'core',

  admin_logs: 'adminGuard',
  admin_clipboard_otp_challenges: 'adminGuard',
  admin_clipboard_security: 'adminGuard',
  dirac_security_rate_limits: 'adminGuard',
  security_logs: 'adminGuard',
  security_login_guard_blocks: 'adminGuard',
  security_customer_login_logs: 'adminGuard',

  security_customer_access_blocks: 'customerSecurity',
  security_customer_auth_links: 'customerSecurity',
  security_customer_password_hashes: 'customerSecurity',
  security_customer_recovery_codes: 'customerSecurity',
  security_customer_sessions: 'customerSecurity',
  security_customer_settings: 'customerSecurity',

  public_mfa_recovery_codes: 'publicMfa',
  public_security_challenges: 'publicMfa',
  public_security_rate_limits: 'publicMfa',
  domain_a2f_sessions: 'publicMfa',
  domain_mfa_challenges: 'publicMfa',
  domain_mfa_methods: 'publicMfa',

  domain_products: 'domain',
  domain_tld_prices: 'domain',
  domain_orders: 'domain',
  domain_order_items: 'domain',
  domain_passkeys: 'domain',
  domain_remember_devices: 'domain',

  products: 'commerce',
  products_backup_before_admin_documents_sync: 'commerce',
  orders: 'commerce',
  order_items: 'commerce',
  vouchers: 'commerce',
  voucher_tiers: 'commerce',

  payment_transactions: 'paymentService',
  payment_gateway_events: 'paymentService',
  number_orders: 'paymentService',
  website_projects: 'paymentService',
  security_customer_account_requests: 'paymentService',
  security_customer_events: 'paymentService'
});

/* source 4618-4620 */
function shouldUseDiracMultiDbRouter() {
  return isEnvTrue('DIRAC_ENABLE_MULTI_DB_ROUTER') || isEnvTrue('DIRAC_MULTI_DB_ROUTER_ENABLED');
}

/* source 4622-4624 */
function shouldUseStrictDiracMultiDbRouter() {
  return isEnvTrue('DIRAC_MULTI_DB_STRICT');
}

/* source 4626-4639 */
function getDiracRestTableFromPath(path) {
  const value = String(path || '');
  const prefix = '/rest/v1/';
  if (!value.startsWith(prefix)) return '';

  const rawTable = value.slice(prefix.length).split('?')[0].split('/')[0];
  if (!rawTable || rawTable === 'rpc') return '';

  try {
    return decodeURIComponent(rawTable);
  } catch (_) {
    return rawTable;
  }
}

/* source 4641-4649 */
function resolveDiracSupabaseTargetKey(path, options = {}) {
  const forced = String(options.db || options.database || '').trim();
  if (forced && DIRAC_SUPABASE_TARGET_ENVS[forced]) return forced;

  const tableName = getDiracRestTableFromPath(path);
  const dedicatedSecurityTables = new Set([
    DIRAC_PERSISTENT_BAN_TABLE,
    DIRAC_S2S_SECURITY_TABLE,
    String(typeof DOMAIN_LOGIN_RATE_TABLE !== 'undefined' ? DOMAIN_LOGIN_RATE_TABLE : '').trim()
  ].filter(Boolean));
  if (tableName && dedicatedSecurityTables.has(tableName)) return 'security';

  if (!shouldUseDiracMultiDbRouter()) return 'legacy';
  return DIRAC_TABLE_DB_MAP[tableName] || 'legacy';
}

/* source 4761-4771 */
function hasValidDomainSessionTokens(session) {
  const data = session && typeof session === 'object' ? session : {};
  return Boolean(
    data.access_token &&
    typeof data.access_token === 'string' &&
    data.access_token.length > 20 &&
    data.refresh_token &&
    typeof data.refresh_token === 'string' &&
    data.refresh_token.length > 10
  );
}

/* source 4791-4795 */
function shouldHideDomainAuthTokens() {
  // PATCH 3A: customer auth wajib backend-only.
  // Access/refresh token Supabase tidak boleh dikirim ke JavaScript/frontend.
  return true;
}

/* source 4797-4801 */
function shouldAcceptFrontendAuthHeaders() {
  // PATCH 3A: jangan percaya Authorization, X-Domain-Refresh, atau MFA proof dari frontend.
  // Sumber otoritas customer hanya HttpOnly Secure cookie + validasi backend.
  return false;
}

/* source 4810-4812 */
function isEnvTrue(name) {
  return String(process.env[name] || '').trim().toLowerCase() === 'true';
}

/* source 4814-4816 */
function normalizeAuthEmail(value) {
  return String(value || '').trim().toLowerCase();
}

/* source 4818-4820 */
function isValidAuthEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

/* source 4928-4987 */
function parseCookies(req) {
  const header = String(req && req.headers && req.headers.cookie || '');
  if (req && req.__diracParseCookiesCache && req.__diracParseCookiesCache.header === header) {
    return req.__diracParseCookiesCache.cookies;
  }

  const cookies = Object.create(null);

  Object.defineProperty(cookies, '__all', {
    value: Object.create(null),
    enumerable: false,
    configurable: false,
    writable: false
  });

  // Refuse ambiguous or resource-exhausting Cookie headers. The Central Guard
  // treats the resulting request as unauthenticated and continues fail-closed.
  const parts = Buffer.byteLength(header, 'utf8') <= 16 * 1024
    ? header.split(';').slice(0, 128).map((item) => item.trim()).filter(Boolean)
    : [];

  parts.forEach((item) => {
    const index = item.indexOf('=');
    const key = String(index === -1 ? item : item.slice(0, index)).trim();
    if (!key || key.length > 256 || key === '__all'
        || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(key)) return;
    let value = index === -1 ? '' : item.slice(index + 1);
    if (Buffer.byteLength(value, 'utf8') > 8 * 1024) return;
    try {
      value = decodeURIComponent(value);
    } catch (_) {
      value = String(value || '');
    }

    if (Buffer.byteLength(value, 'utf8') > 8 * 1024) return;

    if (!cookies.__all[key]) cookies.__all[key] = [];
    if (cookies.__all[key].length < 8) cookies.__all[key].push(value);

    // Tetap simpan bentuk lama untuk kompatibilitas fungsi lain.
    // Kalau browser mengirim cookie dobel dari host/domain berbeda, nilai terakhir tetap legacy,
    // sedangkan requireDomainUser akan mencoba semua kandidat lewat __all.
    cookies[key] = value;
  });

  if (req) {
    try {
      Object.defineProperty(req, '__diracParseCookiesCache', {
        value: { header, cookies },
        enumerable: false,
        configurable: true,
        writable: true
      });
    } catch (_) {
      req.__diracParseCookiesCache = { header, cookies };
    }
  }

  return cookies;
}

/* source 4989-4994 */
function normalizeCookieSameSite(value) {
  const clean = String(value || 'Lax').trim().toLowerCase();
  if (clean === 'strict') return 'Strict';
  if (clean === 'none') return 'None';
  return 'Lax';
}

/* source 4996-5001 */
function normalizeCookieDomain(value) {
  const clean = String(value || '').trim().toLowerCase().replace(/^\./, '');
  if (!clean || /^(none|false|off|host-only|host_only)$/i.test(clean)) return '';
  if (/^localhost$|^127\.|^0\.0\.0\.0$/.test(clean)) return '';
  return clean;
}

/* source 5027-5039 */
function appendSetCookie(res, cookies) {
  const nextCookies = (Array.isArray(cookies) ? cookies : [cookies]).filter(Boolean);
  if (!nextCookies.length) return;

  const current = typeof res.getHeader === 'function' ? res.getHeader('Set-Cookie') : null;
  const previousCookies = Array.isArray(current)
    ? current
    : current
      ? [String(current)]
      : [];

  res.setHeader('Set-Cookie', previousCookies.concat(nextCookies));
}

/* source 5041-5075 */
function makeCookie(name, value, options = {}) {
  // Produksi paling aman: token customer hanya lewat backend-only cookie.
  // Default None agar cookie tetap dikirim saat frontend dan API beda origin
  // (misal diracgroup.store -> *.vercel.app). Untuk dev HTTP lokal, set env DOMAIN_COOKIE_SAMESITE=Lax.
  const sameSite = normalizeCookieSameSite(process.env.DOMAIN_COOKIE_SAMESITE || 'None');
  if (process.env.NODE_ENV === 'production' && sameSite !== 'Strict') {
    const err = new Error('DOMAIN_COOKIE_SAMESITE production wajib Strict.');
    err.statusCode = 500;
    throw err;
  }
  const secureCookie = sameSite === 'None' || process.env.NODE_ENV !== 'development' || isEnvTrue('DOMAIN_COOKIE_FORCE_SECURE');
  const parts = [
    `${name}=${encodeURIComponent(value || '')}`,
    'Path=/',
    'HttpOnly'
  ];

  if (secureCookie) parts.push('Secure');
  const cookieDomain = Object.prototype.hasOwnProperty.call(options, 'domain')
    ? normalizeCookieDomain(options.domain)
    : normalizeCookieDomain(process.env.DOMAIN_COOKIE_DOMAIN || '');
  if (cookieDomain) parts.push(`Domain=${cookieDomain}`);
  parts.push(`SameSite=${sameSite}`);
  parts.push('Priority=High');

  if (options.maxAge !== undefined) {
    const maxAge = Math.floor(Number(options.maxAge));
    parts.push(`Max-Age=${Number.isFinite(maxAge) ? maxAge : 0}`);
    if (Number.isFinite(maxAge) && maxAge <= 0) {
      parts.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    }
  }

  return parts.join('; ');
}

/* source 5077-5077 */
const DOMAIN_COOKIE_CHUNK_SIZE = 3400;

/* source 5078-5078 */
const DOMAIN_COOKIE_MAX_CHUNKS = 12;

/* source 5080-5099 */
function getCompactCookieDomainsForSession() {
  const fingerprint = String(process.env.DOMAIN_COOKIE_DOMAIN || '');
  const cached = getCompactCookieDomainsForSession.__diracCache;
  if (cached && cached.fingerprint === fingerprint) return cached.value.slice();

  const domains = [];
  const add = (value) => {
    const domain = normalizeCookieDomain(value);
    const key = domain || '__host_only__';
    if (domains.some((item) => (item || '__host_only__') === key)) return;
    domains.push(domain);
  };

  // Host-only harus utama agar diracgroup.store langsung membaca cookie hasil login/register.
  add('');
  add(process.env.DOMAIN_COOKIE_DOMAIN);
  add('diracgroup.store');
  getCompactCookieDomainsForSession.__diracCache = { fingerprint, value: domains.slice() };
  return domains;
}

/* source 5101-5103 */
function makeCompactClearCookie(name) {
  return getCompactCookieDomainsForSession().map((domain) => makeCookie(name, '', { maxAge: 0, domain }));
}

/* source 5105-5113 */
function makeCompactClearTokenCookieChunks(name) {
  const cookies = [];
  getCompactCookieDomainsForSession().forEach((domain) => {
    for (let index = 0; index < DOMAIN_COOKIE_MAX_CHUNKS; index += 1) {
      cookies.push(makeCookie(`${name}__${index}`, '', { maxAge: 0, domain }));
    }
  });
  return cookies;
}

/* source 5115-5145 */
function makeTokenCookieSet(name, value, options = {}) {
  const token = String(value || '');
  const cookies = [];

  if (!token) return cookies;

  // FIX: jangan kirim puluhan Set-Cookie clear saat login.
  // Sebelumnya login mengirim clear cookie untuk host-only + domain + semua chunk,
  // lalu baru mengirim cookie sesi baru. Di mobile Safari / edge proxy / Vercel,
  // header Set-Cookie yang terlalu banyak bisa membuat cookie sesi baru tidak tersimpan.
  // Clear besar tetap dilakukan hanya di logout melalui makeClearTokenCookieSet().
  if (token.length <= DOMAIN_COOKIE_CHUNK_SIZE) {
    cookies.push(makeCookie(name, token, Object.assign({}, options, { domain: '' })));
    return cookies;
  }

  const chunks = [];
  for (let index = 0; index < token.length; index += DOMAIN_COOKIE_CHUNK_SIZE) {
    chunks.push(token.slice(index, index + DOMAIN_COOKIE_CHUNK_SIZE));
  }

  if (chunks.length > DOMAIN_COOKIE_MAX_CHUNKS) {
    return cookies;
  }

  cookies.push(makeCookie(name, `__chunked_${chunks.length}`, Object.assign({}, options, { domain: '' })));
  chunks.forEach((chunk, index) => {
    cookies.push(makeCookie(`${name}__${index}`, chunk, Object.assign({}, options, { domain: '' })));
  });
  return cookies;
}

/* source 5151-5156 */
function makeClearTokenCookieSet(name) {
  return [
    ...makeCompactClearCookie(name),
    ...makeCompactClearTokenCookieChunks(name)
  ];
}

/* source 5158-5168 */
function uniqueNonEmptyStrings(values) {
  const seen = new Set();
  const output = [];
  (Array.isArray(values) ? values : [values]).forEach((value) => {
    const clean = String(value || '').trim();
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    output.push(clean);
  });
  return output;
}

/* source 5170-5177 */
function getCookieAllValues(cookies, name) {
  const jar = cookies && typeof cookies === 'object' ? cookies : {};
  const all = jar.__all && typeof jar.__all === 'object' && Array.isArray(jar.__all[name])
    ? jar.__all[name]
    : [];
  const values = all.length ? all.slice() : [jar[name]];
  return uniqueNonEmptyStrings(values).reverse();
}

/* source 5179-5208 */
function readCookieTokenFromMarker(cookies, name, markerValue) {
  const jar = cookies && typeof cookies === 'object' ? cookies : {};
  const marker = String(markerValue || '');
  const chunkMatch = marker.match(/^__chunked_(\d+)$/);
  if (chunkMatch) {
    const count = Math.max(0, Math.min(DOMAIN_COOKIE_MAX_CHUNKS, Number(chunkMatch[1]) || 0));
    let token = '';
    for (let index = 0; index < count; index += 1) {
      const chunk = jar[`${name}__${index}`];
      if (!chunk) return '';
      token += String(chunk);
    }
    return token;
  }

  if (marker) return marker;

  // Recovery untuk browser/proxy yang menghilangkan marker utama tapi masih mengirim chunks.
  if (jar[`${name}__0`]) {
    let token = '';
    for (let index = 0; index < DOMAIN_COOKIE_MAX_CHUNKS; index += 1) {
      const chunk = jar[`${name}__${index}`];
      if (!chunk) break;
      token += String(chunk);
    }
    return token;
  }

  return '';
}

/* source 5210-5215 */
function readCookieTokenCandidates(cookies, name) {
  const markers = getCookieAllValues(cookies, name);
  const candidates = markers.map((marker) => readCookieTokenFromMarker(cookies, name, marker));
  candidates.push(readCookieTokenFromMarker(cookies, name, cookies && cookies[name]));
  return uniqueNonEmptyStrings(candidates);
}

/* source 5247-5260 */
function setSessionCookies(res, session) {
  if (!hasValidDomainSessionTokens(session)) {
    clearSessionCookies(res);
    return false;
  }

  const maxAge = 60 * 60 * 24 * 7;
  appendSetCookie(res, [
    ...makeTokenCookieSet(ACCESS_COOKIE, session.access_token, { maxAge }),
    ...makeTokenCookieSet(REFRESH_COOKIE, session.refresh_token, { maxAge }),
    ...makeSignedDomainSessionCookieSet(session, { maxAge })
  ]);
  return true;
}

/* source 5262-5269 */
function clearSessionCookies(res) {
  appendSetCookie(res, [
    ...makeClearTokenCookieSet(ACCESS_COOKIE),
    ...makeClearTokenCookieSet(REFRESH_COOKIE),
    ...makeClearTokenCookieSet(CUSTOMER_MFA_COOKIE),
    ...makeClearTokenCookieSet(DOMAIN_SIGNED_SESSION_COOKIE)
  ]);
}

/* source 5271-5273 */
function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/* source 5275-5281 */
function parseBase64UrlJson(value) {
  try {
    return JSON.parse(Buffer.from(String(value || ''), 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

/* source 5283-5287 */
function decodeJwtPayloadUnsafe(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;
  return parseBase64UrlJson(parts[1]);
}

/* source 5289-5291 */
function getDomainSignedSessionSecret() {
  return diracCentralDeriveSecretV146('domain-signed-session').toString('base64url');
}

/* source 5293-5301 */
function extractUserForSignedDomainSession(session) {
  const sessionObj = session && typeof session === 'object' ? session : {};
  const user = sessionObj.user && typeof sessionObj.user === 'object' ? sessionObj.user : {};
  const jwt = decodeJwtPayloadUnsafe(sessionObj.access_token);
  const id = String(user.id || user.sub || (jwt && (jwt.sub || jwt.user_id)) || '').trim();
  const email = normalizeAuthEmail(user.email || (jwt && jwt.email) || '');
  if (!id || !email) return null;
  return { id, email };
}

/* source 5303-5309 */
function signDomainSessionPayload(payload) {
  const secret = getDomainSignedSessionSecret();
  if (!secret) return '';
  const body = base64UrlJson(payload);
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/* source 5311-5328 */
function verifyDomainSessionCookieValue(value) {
  const secret = getDomainSignedSessionSecret();
  if (!secret) return null;
  const raw = String(value || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (!safeEqual(sig, expected)) return null;
  const payload = parseBase64UrlJson(body);
  if (!payload || payload.typ !== DOMAIN_SIGNED_SESSION_TYPE) return null;
  const exp = Number(payload.exp || 0);
  if (!Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) return null;
  const id = String(payload.uid || payload.id || '').trim();
  const email = normalizeAuthEmail(payload.email || '');
  if (!id || !email) return null;
  return { id, email, exp };
}

/* source 5330-5349 */
function makeSignedDomainSessionCookieSet(session, options = {}) {
  const user = extractUserForSignedDomainSession(session);
  const maxAge = Math.max(60, Math.floor(Number(options.maxAge || 60 * 60 * 24 * 7)));
  const cookies = [];
  if (!user) return cookies;

  const now = Math.floor(Date.now() / 1000);
  const value = signDomainSessionPayload({
    typ: DOMAIN_SIGNED_SESSION_TYPE,
    uid: user.id,
    email: user.email,
    iat: now,
    exp: now + maxAge,
    nonce: crypto.randomBytes(12).toString('base64url')
  });
  if (!value) return cookies;

  cookies.push(makeCookie(DOMAIN_SIGNED_SESSION_COOKIE, value, { maxAge, domain: '' }));
  return cookies;
}

/* source 5351-5366 */
async function readSignedDomainSessionUser(cookies) {
  const values = readCookieTokenCandidates(cookies, DOMAIN_SIGNED_SESSION_COOKIE);
  for (const value of values) {
    const payload = verifyDomainSessionCookieValue(value);
    if (!payload) continue;

    const checked = await getSupabaseAuthUserByEmail(payload.email);
    if (checked && checked.user) {
      const user = normalizeSupabaseAdminUser(checked.user);
      if (user && String(user.id || '') === payload.id) {
        return user;
      }
    }
  }
  return null;
}

/* source 5396-5401 */
function getBearerToken(req) {
  const auth = String((req.headers && req.headers.authorization) || '').trim();
  if (!auth) return '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

/* source 5403-5409 */
function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} belum diisi di Environment Variables Vercel.`);
  }
  return value;
}

/* source 5506-5536 */
async function customerSecurityFetchAuthLink(authUserId) {
  const cleanAuthUserId = String(authUserId || '').trim();
  if (!customerSecurityLooksLikeUuid(cleanAuthUserId)) {
    return { ok: false, status: 400, data: [], reason: 'invalid_auth_user_id' };
  }

  const select = [
    'id',
    'auth_user_id',
    'customer_id',
    'email',
    'link_status',
    'match_confidence',
    'disabled_at',
    'revoked_at',
    'updated_at'
  ].join(',');

  const path = '/rest/v1/security_customer_auth_links?select=' + encodeURIComponent(select)
    + '&auth_user_id=eq.' + encodeURIComponent(cleanAuthUserId)
    + '&link_status=eq.active'
    + '&disabled_at=is.null'
    + '&revoked_at=is.null'
    + '&order=updated_at.desc'
    + '&limit=2';

  return supabaseFetch(path, {
    method: 'GET',
    auth: 'service'
  });
}

/* source 5538-5543 */
function customerSecurityPickSingleActiveAuthLink(linkResult) {
  const rows = linkResult && linkResult.ok && Array.isArray(linkResult.data)
    ? linkResult.data.filter((row) => row && row.link_status === 'active' && !row.disabled_at && !row.revoked_at && customerSecurityLooksLikeUuid(row.customer_id))
    : [];
  return rows.length === 1 ? rows[0] : null;
}

/* source 5550-5557 */
function customerSecurityIsSchemaCacheMissing(result) {
  if (!result || Number(result.status) !== 404) return false;
  const data = result.data;
  const text = typeof data === 'string'
    ? data
    : String((data && (data.message || data.error || data.detail || data.hint || data.code)) || '');
  return /schema cache|could not find the table|PGRST205|PGRST202/i.test(text);
}

/* source 5874-5883 */
async function customerSecurityFetchRows(tableName, columns, customerId, orderBy, limit) {
  const safeTable = String(tableName || '').trim();
  const select = columns.join(',');
  const path = `/rest/v1/${encodeURIComponent(safeTable)}?select=${encodeURIComponent(select)}&customer_id=eq.${encodeURIComponent(customerId)}&order=${encodeURIComponent(orderBy)}&limit=${encodeURIComponent(String(limit))}`;

  return supabaseFetch(path, {
    method: 'GET',
    auth: 'service'
  });
}

/* source 6056-6058 */
function customerSecurityLooksLikeUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

/* source 6166-6213 */
async function customerSecurityEnsureSettingsRow(customerId) {
  const existing = await customerSecurityFetchRows(
    'security_customer_settings',
    ['id', 'customer_id', 'two_factor_enabled', 'two_factor_method'],
    customerId,
    'created_at.desc',
    1
  );

  if (!existing.ok) return { ok: false, reason: 'settings_read_failed', status: existing.status };

  const rows = Array.isArray(existing.data) ? existing.data : [];
  const mandatoryBody = {
    two_factor_enabled: true,
    two_factor_method: 'authenticator',
    last_security_check_at: new Date().toISOString()
  };

  if (rows.length && rows[0] && rows[0].id) {
    const currentMethod = String(rows[0].two_factor_method || '').trim().toLowerCase();
    const alreadyMandatory = rows[0].two_factor_enabled === true && currentMethod && currentMethod !== 'none';

    if (alreadyMandatory) return { ok: true, created: false, enforced: false };

    const patched = await supabaseFetch('/rest/v1/security_customer_settings?id=eq.' + encodeURIComponent(rows[0].id), {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: mandatoryBody
    });

    if (!patched.ok) return { ok: false, reason: 'settings_enforce_failed', status: patched.status };
    return { ok: true, created: false, enforced: true };
  }

  const created = await supabaseFetch('/rest/v1/security_customer_settings', {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      customer_id: customerId,
      ...mandatoryBody
    }]
  });

  if (!created.ok) return { ok: false, reason: 'settings_create_failed', status: created.status };
  return { ok: true, created: true, enforced: true };
}

/* source 6285-6314 */
function customerSecurityBuildSessionFingerprint(req, customerId) {
  const cookies = parseCookies(req);
  const headerToken = getBearerToken(req);
  const headerRefreshToken = String((req.headers && (req.headers['x-domain-refresh'] || req.headers['x-refresh-token'])) || '').trim();
  const tokenMaterial = uniqueNonEmptyStrings([
    headerToken,
    ...readCookieTokenCandidates(cookies, ACCESS_COOKIE),
    headerRefreshToken,
    ...readCookieTokenCandidates(cookies, REFRESH_COOKIE),
    ...readCookieTokenCandidates(cookies, DOMAIN_SIGNED_SESSION_COOKIE)
  ])[0] || '';

  const userAgent = String((req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
  const ip = customerSecurityRequestIp(req);
  if (!tokenMaterial) return null;

  const sessionTokenHash = customerSecuritySha256(tokenMaterial);
  const deviceId = customerSecuritySha256(['device', userAgent, ip].filter(Boolean).join('|')).slice(0, 48);

  return {
    session_token_hash: sessionTokenHash,
    device_id: deviceId,
    device_name: customerSecurityDeviceName(userAgent),
    browser_name: customerSecurityBrowserName(userAgent),
    operating_system: customerSecurityOperatingSystem(userAgent),
    user_agent: userAgent,
    ip_address: ip,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
  };
}

/* source 6316-6318 */
function customerSecuritySha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

/* source 6320-6326 */
function customerSecurityRequestIp(req) {
  const forwarded = String((req.headers && (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.headers['cf-connecting-ip'])) || '').trim();
  const first = forwarded.split(',')[0].trim();
  if (!first) return null;
  if (/^[0-9a-f:.]+$/i.test(first)) return first.slice(0, 64);
  return null;
}

/* source 6328-6337 */
function customerSecurityDeviceName(userAgent) {
  const ua = String(userAgent || '');
  if (/iPhone/i.test(ua)) return 'iPhone';
  if (/iPad/i.test(ua)) return 'iPad';
  if (/Android/i.test(ua)) return /Mobile/i.test(ua) ? 'Android Phone' : 'Android Tablet';
  if (/Macintosh|Mac OS X/i.test(ua)) return 'Mac';
  if (/Windows/i.test(ua)) return 'Windows PC';
  if (/Linux/i.test(ua)) return 'Linux Device';
  return 'Unknown Device';
}

/* source 6339-6349 */
function customerSecurityBrowserName(userAgent) {
  const ua = String(userAgent || '');
  if (/Edg\//i.test(ua)) return 'Microsoft Edge';
  if (/OPR\//i.test(ua)) return 'Opera';
  if (/CriOS\//i.test(ua)) return 'Chrome iOS';
  if (/Chrome\//i.test(ua)) return 'Chrome';
  if (/FxiOS\//i.test(ua)) return 'Firefox iOS';
  if (/Firefox\//i.test(ua)) return 'Firefox';
  if (/Safari\//i.test(ua)) return 'Safari';
  return 'Unknown Browser';
}

/* source 6351-6359 */
function customerSecurityOperatingSystem(userAgent) {
  const ua = String(userAgent || '');
  if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
  if (/Android/i.test(ua)) return 'Android';
  if (/Windows NT/i.test(ua)) return 'Windows';
  if (/Mac OS X|Macintosh/i.test(ua)) return 'macOS';
  if (/Linux/i.test(ua)) return 'Linux';
  return 'Unknown OS';
}

/* source 6423-6431 */
const CUSTOMER_SECURITY_GUARDED_ACTIONS = new Set([
  'customer_security_guard_status',
  'customer_security_revoke_session',
  'customer_security_revoke_other_sessions',
  'customer_security_account_request',
  'customer_security_recovery_codes_generate',
  'customer_security_recovery_codes_status',
  'customer_security_recovery_code_verify'
]);

/* source 6450-6450 */
const CUSTOMER_SECURITY_RATE_LIMIT_STORE = globalThis.__DIRAC_CUSTOMER_SECURITY_RATE_LIMIT_STORE__ || new Map();

/* source 6451-6451 */
globalThis.__DIRAC_CUSTOMER_SECURITY_RATE_LIMIT_STORE__ = CUSTOMER_SECURITY_RATE_LIMIT_STORE;

/* source 6558-6642 */
async function customerSecurityRequireAccess(req, res, options = {}) {
  const user = await requireDomainUser(req, res);
  if (!user) {
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'user_not_active');
    return null;
  }

  const authUserId = String(user.id || '').trim();
  if (!authUserId || !customerSecurityLooksLikeUuid(authUserId)) {
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'invalid_session');
    res.status(401).json({ ok: false, message: 'Sesi tidak valid.' });
    return null;
  }

  const rate = customerSecurityCheckRateLimit(req, options.action || 'customer_security', authUserId, options.rateLimit);
  if (!rate.ok) {
    res.setHeader('Retry-After', String(Math.ceil(rate.retryAfterMs / 1000)));
    res.status(429).json({
      ok: false,
      message: 'Terlalu banyak percobaan. Coba lagi sebentar.',
      retry_after_seconds: Math.ceil(rate.retryAfterMs / 1000)
    });
    return null;
  }

  const linkResult = await customerSecurityFetchAuthLink(authUserId);
  if (!linkResult.ok) {
    if (customerSecurityIsSchemaCacheMissing(linkResult)) {
      res.status(503).json({
        ok: false,
        message: 'Storage keamanan belum siap. Coba lagi setelah sinkronisasi schema selesai.',
        source: 'customer_security_guard'
      });
      return null;
    }

    res.status(500).json({
      ok: false,
      message: 'Gagal memverifikasi akses customer security.',
      source: 'customer_security_guard'
    });
    return null;
  }

  const link = customerSecurityPickSingleActiveAuthLink(linkResult);
  const customerId = String(link && link.customer_id || '').trim();

  if (!link || link.link_status !== 'active' || !customerSecurityLooksLikeUuid(customerId)) {
    await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'auth_link_not_active');
    res.status(403).json({
      ok: false,
      message: 'Akun belum terhubung ke customer profile aktif.',
      source: 'customer_security_guard'
    });
    return null;
  }

  await customerSecurityEnsureSettingsRow(customerId).catch(() => null);

  let mfa = null;
  if (options.requireMfa) {
    mfa = verifyCustomerDashboardMfaCookie(req, user);
    if (!mfa || !mfa.ok) {
      await customerSecurityWriteGuardEvent(customerId, {
        event_type: 'security_settings_updated',
        status: 'warning',
        risk_level: 'medium',
        description: 'Aksi keamanan ditolak karena MFA/re-auth proof tidak valid.',
        req,
        metadata: { action: options.action || 'customer_security', reason: 'missing_or_invalid_mfa_proof' }
      });
      await customerSecurityRegisterFailedVerification(req, options.action || 'customer_security', 'missing_or_invalid_mfa_proof', customerId);
      res.status(403).json({
        ok: false,
        code: 'MFA_REQUIRED',
        message: 'Aksi ini membutuhkan verifikasi A2F/MFA ulang dari dashboard resmi.'
      });
      return null;
    }
  } else {
    try { mfa = verifyCustomerDashboardMfaCookie(req, user); } catch (_) { mfa = null; }
  }

  return { user, authUserId, customerId, link, mfa };
}

/* source 6644-6669 */
function customerSecurityCheckRateLimit(req, action, userId, config = {}) {
  const limit = Math.max(1, Number(config.limit || 12));
  const windowMs = Math.max(1000, Number(config.windowMs || 60_000));
  const ip = customerSecurityRequestIp(req) || 'no-ip';
  const key = [String(action || 'customer_security'), String(userId || 'anonymous'), ip].join(':');
  const now = Date.now();
  const bucket = CUSTOMER_SECURITY_RATE_LIMIT_STORE.get(key) || [];
  const fresh = bucket.filter(ts => now - ts < windowMs);
  if (fresh.length >= limit) {
    const oldest = fresh[0] || now;
    return { ok: false, retryAfterMs: Math.max(1000, windowMs - (now - oldest)) };
  }
  fresh.push(now);
  CUSTOMER_SECURITY_RATE_LIMIT_STORE.set(key, fresh);

  if (CUSTOMER_SECURITY_RATE_LIMIT_STORE.size > 5000) {
    for (const [k, values] of CUSTOMER_SECURITY_RATE_LIMIT_STORE.entries()) {
      const active = values.filter(ts => now - ts < windowMs);
      if (active.length) CUSTOMER_SECURITY_RATE_LIMIT_STORE.set(k, active);
      else CUSTOMER_SECURITY_RATE_LIMIT_STORE.delete(k);
      if (CUSTOMER_SECURITY_RATE_LIMIT_STORE.size <= 3500) break;
    }
  }

  return { ok: true };
}

/* source 6877-6886 */
function diracUltraXssCleanLogText(value, maxLength = 500, fallback = '') {
  const safeMax = Number.isFinite(Number(maxLength)) ? Math.min(Math.max(Number(maxLength), 1), 2000) : 500;
  const text = String(value === undefined || value === null ? fallback : value)
    .replace(/[<>&"'`]/g, ' ')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, safeMax);
  return text || String(fallback || '').slice(0, safeMax);
}

/* source 6922-6924 */
function customerSecuritySanitizeReason(value) {
  return diracUltraXssCleanLogText(value || 'Customer security request.', 500, 'Customer security request.');
}

/* source 6964-6980 */
function diracApplySecurityResponseHeaders(res, options = {}) {
  try {
    if (!res || !res.setHeader) return;

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');

    if (options.allowCors === false) {
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    }
  } catch (_) {}
}

/* source 6996-6996 */
const CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY = globalThis.__DIRAC_CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY__ || new Map();

/* source 6997-6997 */
globalThis.__DIRAC_CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY__ = CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY;

/* source 6998-6998 */
const CUSTOMER_SECURITY_ACCESS_BLOCK_SECONDS = 300;

/* source 7000-7013 */
function customerSecurityAccessBlockIdentity(req) {
  const ip = customerSecurityRequestIp(req) || 'no-ip';
  const ua = String((req && req.headers && req.headers['user-agent']) || '').trim().slice(0, 512);
  const origin = requestOrigin(req);
  const deviceHeader = String((req && req.headers && (req.headers['x-dirac-device-id'] || req.headers['x-device-id'])) || '').trim().slice(0, 160);
  const deviceMaterial = [deviceHeader, ua, origin].filter(Boolean).join('|') || 'unknown-device';
  return {
    ip,
    ua,
    origin,
    ip_hash: customerSecuritySha256('security-block-ip-v1:' + ip),
    device_hash: customerSecuritySha256('security-block-device-v1:' + deviceMaterial)
  };
}

/* source 7043-7082 */
async function customerSecurityRegisterFailedVerification(req, action, reason, customerId = null) {
  const identity = customerSecurityAccessBlockIdentity(req);
  const untilMs = Date.now() + CUSTOMER_SECURITY_ACCESS_BLOCK_SECONDS * 1000;
  const blockedUntil = new Date(untilMs).toISOString();
  const memKey = identity.ip_hash + ':' + identity.device_hash;
  CUSTOMER_SECURITY_ACCESS_BLOCK_MEMORY.set(memKey, untilMs);

  try {
    await supabaseFetch('/rest/v1/security_customer_access_blocks', {
      method: 'POST',
      auth: 'service',
      prefer: 'return=representation',
      body: [{
        customer_id: customerSecurityLooksLikeUuid(customerId) ? customerId : null,
        ip_hash: identity.ip_hash,
        device_hash: identity.device_hash,
        reason: customerSecuritySanitizeReason(reason || 'security_gate_failed'),
        action: String(action || 'customer_security').slice(0, 120),
        fail_count: 1,
        blocked_until: blockedUntil,
        metadata: { source: 'customer_security_gate', origin: identity.origin || null, user_agent_hash: customerSecuritySha256('ua:' + identity.ua) }
      }]
    });
  } catch (_) {}

  try {
    if (customerSecurityLooksLikeUuid(customerId)) {
      await customerSecurityWriteGuardEvent(customerId, {
        event_type: 'security_access_blocked',
        status: 'warning',
        risk_level: 'high',
        description: 'Akses customer security diblokir sementara setelah verifikasi backend gagal.',
        req,
        metadata: { action, reason, blocked_until: blockedUntil }
      });
    }
  } catch (_) {}

  return { blocked_until: blockedUntil, retry_after_seconds: CUSTOMER_SECURITY_ACCESS_BLOCK_SECONDS };
}

/* source 7102-7104 */
function customerSecurityPickRecoveryChar(charset) {
  return charset[crypto.randomInt(0, charset.length)];
}

/* source 7132-7139 */
function customerSecurityGenerateLostPasskeyRecoveryCode() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let out = '';
  while (out.length < LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157) {
    out += customerSecurityPickRecoveryChar(alphabet);
  }
  return out;
}

/* source 7145-7153 */
function customerSecurityNormalizeRecoveryCodeInput(code) {
  // Recovery code alphabet intentionally excludes whitespace.
  // PDF/mobile copy can turn the ASCII hyphen from the encrypted PDF into look-alike dash glyphs.
  // Normalize only those dash glyphs back to '-' before stripping whitespace/invisible formatting marks.
  return String(code || '')
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D]/g, '-')
    .replace(/[\s\u00AD\u034F\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]+/g, '')
    .trim();
}

/* source 7165-7174 */
function customerSecurityGetArgon2() {
  try {
    return require('argon2');
  } catch (error) {
    const err = new Error('Dependency argon2 belum terpasang. Tambahkan dependency "argon2" di package.json lalu redeploy.');
    err.statusCode = 500;
    err.code = 'ARGON2ID_DEPENDENCY_MISSING';
    throw err;
  }
}

/* source 7242-7242 */
const LOST_PASSKEY_RECOVERY_REQUEST_TABLE = 'security_lost_passkey_recovery_requests';

/* source 7243-7243 */
const LOST_PASSKEY_RECOVERY_SESSION_TABLE = 'security_lost_passkey_recovery_sessions';

/* source 7246-7246 */
const LOST_PASSKEY_RECOVERY_PURPOSE = 'register_new_passkey';

/* source 7250-7250 */
const LOST_PASSKEY_RECOVERY_ATTEMPT_LIMIT = 5;

/* source 7251-7251 */
const DIRAC_RECOVERY_WORKER_ACTION = 'dirac_recovery_worker_generate';

/* source 7252-7252 */
const DIRAC_RECOVERY_WORKER_TASK_GENERATE = 'lost_passkey_generate';

/* source 7253-7253 */
const DIRAC_RECOVERY_WORKER_TASK_VERIFY = 'lost_passkey_verify';

/* source 7254-7254 */
const DIRAC_RECOVERY_WORKER_TASK_FINALIZE = 'lost_passkey_finalize';

/* source 7255-7255 */
const DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165 = 'lost_passkey_recovery_link_open';

/* source 7259-7259 */
const DIRAC_LOST_PASSKEY_VAULT_PATCH_V157 = 'lost-passkey-html-vault-aes256gcm-argon2id-v157';

/* source 7260-7260 */
const LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157 = 1200;

/* source 7261-7261 */
const LOST_PASSKEY_SECRET_100_CHAR_LENGTH_V157 = 100;

/* source 7262-7262 */
const LOST_PASSKEY_LINK_TOKEN_BYTES_V157 = 250;

/* source 7264-7264 */
const LOST_PASSKEY_RECOVERY_SALT_BYTES_V157 = 2500;

/* source 7265-7265 */
const LOST_PASSKEY_RECOVERY_VAULT_ID_BYTES_V157 = 2500;

/* source 7266-7266 */
const LOST_PASSKEY_RECOVERY_EXTRA_NONCE_BYTES_V157 = 2500;

/* source 7267-7267 */
const LOST_PASSKEY_RECOVERY_TTL_MINUTES_V157 = 7;

/* source 7271-7271 */
const LOST_PASSKEY_ROOT_SECRET_MIN_BYTES_V157 = 3000;

/* source 7272-7272 */
const LOST_PASSKEY_DB_PEPPER_MIN_BYTES_V157 = 64;

/* source 7273-7273 */
const LOST_PASSKEY_SECRET_100_ALPHABET_V157 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/* source 7281-7281 */
const DIRAC_LOST_PASSKEY_GENERATE_QUEUE_PATCH_V164 = 'lost-passkey-generate-argon2id-queue-v164';

/* source 7282-7282 */
const DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164 = 'dirac:lost-passkey-generate:argon2id-global-lock:v164';

/* source 7283-7283 */
const DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164 = globalThis.__DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164__ || new Map();

/* source 7284-7284 */
globalThis.__DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164__ = DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164;

/* source 7286-7290 */
function customerSecurityLostPasskeyQueueIntV164(name, fallback, min, max) {
  const raw = Number(process.env[name] || fallback);
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
}

/* source 7292-7294 */
function customerSecurityLostPasskeyQueueTableV164() {
  return DIRAC_PERSISTENT_BAN_TABLE;
}

/* source 7296-7298 */
function customerSecurityLostPasskeyQueueTtlMsV164() {
  return customerSecurityLostPasskeyQueueIntV164('DIRAC_LOST_PASSKEY_QUEUE_LOCK_TTL_SECONDS', 360, 60, 1200) * 1000;
}

/* source 7300-7302 */
function customerSecurityLostPasskeyQueueMaxWaitMsV164() {
  return customerSecurityLostPasskeyQueueIntV164('DIRAC_LOST_PASSKEY_QUEUE_MAX_WAIT_SECONDS', 240, 15, 840) * 1000;
}

/* source 7307-7311 */
function customerSecurityLostPasskeyQueueMaxWaitForTaskMsV191(queueTask) {
  return [DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165, DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159].includes(String(queueTask || ''))
    ? 5000
    : customerSecurityLostPasskeyQueueMaxWaitMsV164();
}

/* source 7313-7315 */
function customerSecurityLostPasskeyQueuePollMsV164() {
  return customerSecurityLostPasskeyQueueIntV164('DIRAC_LOST_PASSKEY_QUEUE_POLL_MS', 1200, 250, 5000);
}

/* source 7317-7319 */
function customerSecurityLostPasskeyQueueHeartbeatMsV188() {
  return Math.max(5000, Math.min(60000, Math.floor(customerSecurityLostPasskeyQueueTtlMsV164() / 3)));
}

/* source 7321-7324 */
function customerSecurityLostPasskeyQueueEnabledV164() {
  const value = String(process.env.DIRAC_LOST_PASSKEY_QUEUE_DISABLED || '').trim().toLowerCase();
  return !(value === '1' || value === 'true' || value === 'yes' || value === 'on');
}

/* source 7326-7328 */
function customerSecurityLostPasskeyQueueSleepV164(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(25, Math.floor(Number(ms || 0)))));
}

/* source 7330-7332 */
function customerSecurityLostPasskeyQueueOwnerV164() {
  return 'qv164_' + crypto.randomBytes(24).toString('base64url');
}

/* source 7334-7348 */
function customerSecurityLostPasskeyQueueRecordV164(ownerId, nowMs, lockUntilMs, context = {}) {
  const currentMs = Number(nowMs || Date.now());
  return {
    type: 'lost_passkey_generate_argon2id_queue_lock_v164',
    patch: DIRAC_LOST_PASSKEY_GENERATE_QUEUE_PATCH_V164,
    scope: 'all_lost_passkey_argon2id',
    owner_id: String(ownerId || ''),
    locked_at_ms: Number(context.lockedAtMs || currentMs),
    heartbeat_at_ms: currentMs,
    locked_until_ms: Number(lockUntilMs || 0),
    request_nonce_hash: customerSecurityLostPasskeySha256B64(Buffer.from(String(context.nonce || ''), 'utf8')),
    caller_id_hash: customerSecurityLostPasskeySha256B64(Buffer.from(String(context.callerId || ''), 'utf8')),
    worker_action: String(context.workerAction || context.worker_action || DIRAC_RECOVERY_WORKER_TASK_GENERATE).slice(0, 80)
  };
}

/* source 7364-7380 */
async function customerSecurityLostPasskeyQueueReadStateV189() {
  const table = customerSecurityLostPasskeyQueueTableV164();
  if (!table) return { ok: false, row: null, reason: 'queue_table_missing' };
  const path = '/rest/v1/' + encodeURIComponent(table)
    + '?select=security_key,record_json,blocked_until_ms,expires_at'
    + '&security_key=eq.' + encodeURIComponent(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164)
    + '&limit=1';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' }).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data)) {
    return { ok: false, row: null, reason: 'queue_storage_unavailable' };
  }
  return {
    ok: true,
    row: result.data.length ? (result.data[0] || null) : null,
    reason: result.data.length ? 'queue_row_found' : 'queue_row_absent'
  };
}

/* source 7382-7385 */
function customerSecurityLostPasskeyQueueRowOwnerV164(row) {
  const record = row && row.record_json && typeof row.record_json === 'object' ? row.record_json : {};
  return String(record.owner_id || '');
}

/* source 7387-7390 */
function customerSecurityLostPasskeyQueueRowActiveV164(row, nowMs) {
  const lockUntilMs = Number(row && row.blocked_until_ms || 0);
  return Number.isFinite(lockUntilMs) && lockUntilMs > Number(nowMs || Date.now());
}

/* source 7392-7424 */
async function customerSecurityLostPasskeyQueueRenewV188(ownerId, context = {}) {
  const cleanOwner = String(ownerId || '');
  const table = customerSecurityLostPasskeyQueueTableV164();
  if (!cleanOwner || !table) return false;
  const nowMs = Date.now();
  const lockUntilMs = nowMs + customerSecurityLostPasskeyQueueTtlMsV164();
  const path = '/rest/v1/' + encodeURIComponent(table)
    + '?security_key=eq.' + encodeURIComponent(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164)
    + '&' + encodeURIComponent('record_json->>owner_id') + '=eq.' + encodeURIComponent(cleanOwner)
    + '&blocked_until_ms=gt.' + encodeURIComponent(String(nowMs));
  const result = await supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      record_json: customerSecurityLostPasskeyQueueRecordV164(cleanOwner, nowMs, lockUntilMs, context),
      blocked_until_ms: lockUntilMs,
      updated_at: new Date(nowMs).toISOString(),
      expires_at: new Date(lockUntilMs + 60_000).toISOString()
    }
  }).catch(() => null);
  const renewed = Boolean(result && result.ok && Array.isArray(result.data) && result.data.some((row) => (
    customerSecurityLostPasskeyQueueRowOwnerV164(row) === cleanOwner
    && customerSecurityLostPasskeyQueueRowActiveV164(row, Date.now())
  )));
  if (renewed) {
    DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.set(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164, {
      ownerId: cleanOwner,
      lockUntilMs
    });
  }
  return renewed;
}

/* source 7426-7446 */
function customerSecurityLostPasskeyQueueHeartbeatV188(ownerId, context = {}) {
  let active = true;
  let leaseLost = false;
  let pending = Promise.resolve();
  const tick = () => {
    if (!active || leaseLost) return;
    pending = customerSecurityLostPasskeyQueueRenewV188(ownerId, context)
      .then((renewed) => { if (!renewed) leaseLost = true; })
      .catch(() => { leaseLost = true; });
  };
  const timer = setInterval(tick, customerSecurityLostPasskeyQueueHeartbeatMsV188());
  if (timer && typeof timer.unref === 'function') timer.unref();
  return {
    healthy: () => !leaseLost,
    stop: async () => {
      active = false;
      clearInterval(timer);
      await pending.catch(() => null);
    }
  };
}

/* source 7448-7450 */
function customerSecurityLostPasskeyQueueLeaseHealthyV188(ticket) {
  return Boolean(ticket && ticket.ok && (typeof ticket.leaseHealthy !== 'function' || ticket.leaseHealthy()));
}

/* source 7504-7531 */
async function customerSecurityLostPasskeyQueueTryPatchAvailableV167(ownerId, context = {}) {
  const table = customerSecurityLostPasskeyQueueTableV164();
  if (!table) return { ok: false, reason: 'queue_table_missing' };
  const nowMs = Date.now();
  const lockUntilMs = nowMs + customerSecurityLostPasskeyQueueTtlMsV164();
  const payload = {
    record_json: customerSecurityLostPasskeyQueueRecordV164(ownerId, nowMs, lockUntilMs, context),
    blocked_until_ms: lockUntilMs,
    updated_at: new Date(nowMs).toISOString(),
    expires_at: new Date(lockUntilMs + 60_000).toISOString()
  };
  const path = '/rest/v1/' + encodeURIComponent(table)
    + '?security_key=eq.' + encodeURIComponent(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164)
    + '&blocked_until_ms=lte.' + encodeURIComponent(String(nowMs));
  const result = await supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: payload
  }).catch(() => null);
  if (result && result.ok && Array.isArray(result.data) && result.data.some((row) => (
    customerSecurityLostPasskeyQueueRowOwnerV164(row) === ownerId
    && customerSecurityLostPasskeyQueueRowActiveV164(row, Date.now())
  ))) {
    return { ok: true, ownerId, claimed: 'expired_or_released' };
  }
  return { ok: false, reason: 'queue_lock_busy_or_absent' };
}

/* source 7533-7558 */
async function customerSecurityLostPasskeyQueueTryInsertAvailableV167(ownerId, context = {}) {
  const table = customerSecurityLostPasskeyQueueTableV164();
  if (!table) return { ok: false, reason: 'queue_table_missing' };
  const nowMs = Date.now();
  const lockUntilMs = nowMs + customerSecurityLostPasskeyQueueTtlMsV164();
  const payload = [{
    security_key: DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164,
    record_json: customerSecurityLostPasskeyQueueRecordV164(ownerId, nowMs, lockUntilMs, context),
    blocked_until_ms: lockUntilMs,
    updated_at: new Date(nowMs).toISOString(),
    expires_at: new Date(lockUntilMs + 60_000).toISOString()
  }];
  const result = await supabaseFetch('/rest/v1/' + encodeURIComponent(table) + '?on_conflict=security_key', {
    method: 'POST',
    auth: 'service',
    prefer: 'resolution=ignore-duplicates,return=representation',
    body: payload
  }).catch(() => null);
  if (result && result.ok && Array.isArray(result.data) && result.data.some((row) => (
    customerSecurityLostPasskeyQueueRowOwnerV164(row) === ownerId
    && customerSecurityLostPasskeyQueueRowActiveV164(row, Date.now())
  ))) {
    return { ok: true, ownerId, claimed: 'inserted' };
  }
  return { ok: false, reason: 'queue_lock_busy' };
}

/* source 7560-7664 */
async function customerSecurityLostPasskeyQueueAcquireV164(req, body = {}) {
  if (!customerSecurityLostPasskeyQueueEnabledV164()) {
    return { ok: true, disabled: true, leaseHealthy: () => true, release: async () => {} };
  }
  const ownerId = customerSecurityLostPasskeyQueueOwnerV164();
  const startMs = Date.now();
  const queueTask = String(body && (body.worker_action || body.queue_task) || '').trim();
  const mayWaitForExistingArgon2 = queueTask === DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
    || queueTask === DIRAC_RECOVERY_WORKER_TASK_VERIFY
    || queueTask === DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159;
  const deadlineMs = mayWaitForExistingArgon2
    ? startMs + customerSecurityLostPasskeyQueueMaxWaitForTaskMsV191(queueTask)
    : startMs;
  const context = {
    nonce: body && body.nonce,
    callerId: body && body.caller_id,
    workerAction: queueTask,
    lockedAtMs: startMs
  };
  let attempts = 0;
  let lastReason = 'queue_lock_busy';

  while (true) {
    attempts += 1;
    const nowMs = Date.now();
    const memory = DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.get(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164);
    let claimed = null;
    let patched = null;

    if (memory && Number(memory.lockUntilMs || 0) > nowMs && String(memory.ownerId || '') !== ownerId) {
      const persistentState = await customerSecurityLostPasskeyQueueReadStateV189();
      if (!persistentState.ok) {
        // Never clear a live-looking memory lock when persistent storage cannot
        // confirm its state. This intentionally remains fail-closed.
        lastReason = 'memory_lock_busy_persistent_state_unavailable';
      } else {
        const persistentOwner = customerSecurityLostPasskeyQueueRowOwnerV164(persistentState.row);
        const persistentActive = customerSecurityLostPasskeyQueueRowActiveV164(persistentState.row, nowMs);
        const memoryOwner = String(memory.ownerId || '');
        if (!persistentActive || !persistentOwner || persistentOwner !== memoryOwner) {
          DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.delete(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164);
          lastReason = 'stale_memory_lock_cleared';
          continue;
        }
        lastReason = 'memory_and_persistent_lock_busy';
      }
    } else {
      if (memory && Number(memory.lockUntilMs || 0) <= nowMs) {
        DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.delete(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164);
      }
      patched = await customerSecurityLostPasskeyQueueTryPatchAvailableV167(ownerId, context);
      claimed = patched.ok ? patched : await customerSecurityLostPasskeyQueueTryInsertAvailableV167(ownerId, context);
      if (claimed && claimed.ok) {
        DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.set(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164, {
          ownerId,
          lockUntilMs: Date.now() + customerSecurityLostPasskeyQueueTtlMsV164()
        });
        const heartbeat = customerSecurityLostPasskeyQueueHeartbeatV188(ownerId, context);
        return {
          ok: true,
          ownerId,
          attempts,
          waited_ms: Date.now() - startMs,
          claim_mode: claimed.claimed || 'fast_claim',
          leaseHealthy: heartbeat.healthy,
          release: async () => {
            await heartbeat.stop();
            return customerSecurityLostPasskeyQueueReleaseV164(ownerId);
          }
        };
      }
      lastReason = (claimed && claimed.reason) || (patched && patched.reason) || 'queue_lock_busy';
    }

    const remainingMs = deadlineMs - Date.now();
    if (!mayWaitForExistingArgon2 || remainingMs <= 0) break;
    await customerSecurityLostPasskeyQueueSleepV164(Math.min(customerSecurityLostPasskeyQueuePollMsV164(), remainingMs));
  }

  try {
    await customerSecurityWriteGuardEvent(null, {
      event_type: 'lost_passkey_generate_queue_busy',
      status: 'blocked',
      risk_level: 'medium',
      description: 'SERVER 2 menolak proses lost-passkey karena lock Argon2id sedang aktif.',
      req,
      metadata: {
        patch: DIRAC_LOST_PASSKEY_GENERATE_QUEUE_PATCH_V164,
        queue_task: queueTask,
        bounded_wait_enabled: mayWaitForExistingArgon2,
        attempts,
        waited_ms: Date.now() - startMs,
        reason: lastReason
      }
    }).catch(() => null);
  } catch (_) {}
  return {
    ok: false,
    status: 429,
    code: 'RECOVERY_GENERATE_QUEUE_BUSY',
    reason: lastReason,
    attempts,
    waited_ms: Date.now() - startMs
  };
}

/* source 7666-7698 */
async function customerSecurityLostPasskeyQueueReleaseV164(ownerId) {
  const cleanOwner = String(ownerId || '');
  if (!cleanOwner) return false;
  const memory = DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.get(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164);
  if (memory && String(memory.ownerId || '') === cleanOwner) DIRAC_LOST_PASSKEY_GENERATE_QUEUE_MEMORY_V164.delete(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164);
  const table = customerSecurityLostPasskeyQueueTableV164();
  if (!table) return false;
  const nowMs = Date.now();
  const releasedRecord = {
    type: 'lost_passkey_generate_argon2id_queue_lock_v164',
    patch: DIRAC_LOST_PASSKEY_GENERATE_QUEUE_PATCH_V164,
    released_at_ms: nowMs,
    released_by_owner_id_hash: customerSecurityLostPasskeySha256B64(Buffer.from(cleanOwner, 'utf8')),
    owner_id: '',
    status: 'released',
    worker_action: DIRAC_RECOVERY_WORKER_TASK_GENERATE
  };
  const path = '/rest/v1/' + encodeURIComponent(table)
    + '?security_key=eq.' + encodeURIComponent(DIRAC_LOST_PASSKEY_GENERATE_QUEUE_LOCK_KEY_V164)
    + '&' + encodeURIComponent('record_json->>owner_id') + '=eq.' + encodeURIComponent(cleanOwner);
  const result = await supabaseFetch(path, {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=minimal',
    body: {
      record_json: releasedRecord,
      blocked_until_ms: 0,
      updated_at: new Date(nowMs).toISOString(),
      expires_at: new Date(nowMs + 60_000).toISOString()
    }
  }).catch(() => null);
  return !!(result && result.ok);
}

/* source 7700-7703 */
function customerSecurityNormalizeLostPasskeyRequestId(value) {
  const clean = String(value || '').trim();
  return /^[a-zA-Z0-9_-]{16,120}$/.test(clean) ? clean : '';
}

/* source 7705-7707 */
function customerSecurityLostPasskeyRequestId() {
  return crypto.randomBytes(24).toString('base64url');
}

/* source 7709-7715 */
function customerSecurityLostPasskeySecret(scope) {
  const secret = diracCentralDeriveSecretV146('lost-passkey-recovery:' + String(scope || 'default'));
  if (!Buffer.isBuffer(secret) || secret.length < 64) {
    const error = new Error('LOST_PASSKEY_DERIVED_SECRET_INVALID');
    error.code = 'LOST_PASSKEY_DERIVED_SECRET_INVALID';
    throw error;
  }
  return secret;
}

/* source 7717-7719 */
function customerSecurityLostPasskeyHashHex(scope, value) {
  return crypto.createHmac('sha256', customerSecurityLostPasskeySecret(scope)).update(String(value || '')).digest('hex');
}

/* source 7729-7731 */
function customerSecurityLostPasskeyRecoverySessionHash(token) {
  return customerSecurityLostPasskeyHashHex('recovery-session', token);
}

/* source 7741-7743 */
function customerSecurityLostPasskeyB64(value) {
  return Buffer.from(value || Buffer.alloc(0)).toString('base64url');
}

/* source 7745-7747 */
function customerSecurityLostPasskeySha256B64(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

/* source 7749-7759 */
function customerSecurityRecoveryWorkerUrl() {
  const raw = String(process.env.DIRAC_RECOVERY_WORKER_URL || '').trim();
  if (!raw) return '';
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:') return '';
    return url.origin + url.pathname.replace(/\/+$/, '');
  } catch (_) {
    return '';
  }
}

/* source 7761-7765 */
function customerSecurityRecoveryWorkerSecret() {
  const secret = String(process.env.DIRAC_RECOVERY_WORKER_SECRET || '').trim();
  if (Buffer.byteLength(secret, 'utf8') < 64) return '';
  return secret;
}

/* source 7767-7770 */
function customerSecurityRecoveryWorkerAsciiToken(value) {
  const clean = String(value || '').trim();
  return /^[A-Za-z0-9_.-]{1,80}$/.test(clean) ? clean : '';
}

/* source 7772-7774 */
function customerSecurityRecoveryWorkerCaller() {
  return customerSecurityRecoveryWorkerAsciiToken(process.env.DIRAC_RECOVERY_WORKER_CALLER);
}

/* source 7776-7778 */
function customerSecurityRecoveryWorkerAllowedCaller() {
  return customerSecurityRecoveryWorkerAsciiToken(process.env.DIRAC_RECOVERY_WORKER_ALLOWED_CALLER);
}

/* source 7781-7852 */
function customerSecurityRecoveryWorkerMainEnvDiagnostics() {
  const rawUrl = String(process.env.DIRAC_RECOVERY_WORKER_URL || '').trim();
  const rawSecret = String(process.env.DIRAC_RECOVERY_WORKER_SECRET || '').trim();
  const rawCaller = String(process.env.DIRAC_RECOVERY_WORKER_CALLER || '').trim();
  const server2OnlyEnv = [
    'DIRAC_RECOVERY_WORKER_ALLOWED_CALLER',
    'DIRAC_RECOVERY_WORKER_MAX_BODY_BYTES',
    'DIRAC_RECOVERY_WORKER_CLOCK_SKEW_SECONDS',
    'DIRAC_LOST_PASSKEY_ARGON2_MEMORY_KIB',
    'DIRAC_LOST_PASSKEY_ARGON2_TIME_COST',
    'DIRAC_LOST_PASSKEY_ARGON2_PARALLELISM',
    'DIRAC_LOST_PASSKEY_ROOT_SECRET',
    'DIRAC_LOST_PASSKEY_ROOT_SECRET_VERSION',
    'DIRAC_LOST_PASSKEY_DB_PEPPER',
    'DIRAC_LOST_PASSKEY_MAX_RUNNING',
    'DIRAC_LOST_PASSKEY_QUEUE_MAX',
    'DIRAC_LOST_PASSKEY_PROCESSING_LOCK_TTL_SECONDS',
    'DIRAC_RECOVERY_WORKER_X25519_PRIVATE_KEY',
    'DIRAC_RECOVERY_WORKER_MLKEM1024_PRIVATE_KEY'
  ];
  const diagnostics = {
    role: 'server1_main_recovery_caller',
    required_env: [
      'DIRAC_RECOVERY_WORKER_URL',
      'DIRAC_RECOVERY_WORKER_SECRET',
      'DIRAC_RECOVERY_WORKER_CALLER'
    ],
    server2_only_env: server2OnlyEnv,
    allowed_shared_env: [
      'DIRAC_RECOVERY_WORKER_SECRET',
      'DOMAIN_COOKIE_SAMESITE'
    ],
    missing_env: [],
    invalid_env: [],
    wrong_server_env: [],
    env_state: {
      DIRAC_RECOVERY_WORKER_URL: rawUrl ? 'present' : 'missing',
      DIRAC_RECOVERY_WORKER_SECRET: rawSecret ? 'present' : 'missing',
      DIRAC_RECOVERY_WORKER_CALLER: rawCaller ? 'present' : 'missing'
    }
  };
  for (const name of server2OnlyEnv) {
    const present = String(process.env[name] || '').trim() ? true : false;
    diagnostics.env_state[name] = present ? 'present_on_server1_remove_it' : 'absent';
    if (present) diagnostics.wrong_server_env.push(name + ' belongs to Vercel 2, remove it from Vercel 1');
  }

  if (!rawUrl) diagnostics.missing_env.push('DIRAC_RECOVERY_WORKER_URL');
  else {
    try {
      const url = new URL(rawUrl);
      diagnostics.env_state.worker_url_protocol = url.protocol.replace(/:$/, '');
      diagnostics.env_state.worker_url_host = url.hostname;
      diagnostics.env_state.worker_url_path = url.pathname.replace(/\/+$/, '') || '/';
      if (url.protocol !== 'https:') diagnostics.invalid_env.push('DIRAC_RECOVERY_WORKER_URL must use https');
      if (!url.hostname) diagnostics.invalid_env.push('DIRAC_RECOVERY_WORKER_URL host is empty');
    } catch (_) {
      diagnostics.invalid_env.push('DIRAC_RECOVERY_WORKER_URL is not a valid URL');
    }
  }

  if (!rawSecret) diagnostics.missing_env.push('DIRAC_RECOVERY_WORKER_SECRET');
  else if (Buffer.byteLength(rawSecret, 'utf8') < 64) diagnostics.invalid_env.push('DIRAC_RECOVERY_WORKER_SECRET must be at least 64 bytes');

  if (!rawCaller) diagnostics.missing_env.push('DIRAC_RECOVERY_WORKER_CALLER');
  else if (!customerSecurityRecoveryWorkerAsciiToken(rawCaller)) diagnostics.invalid_env.push('DIRAC_RECOVERY_WORKER_CALLER must match ASCII /^[A-Za-z0-9_.-]{1,80}$/');

  diagnostics.ok = diagnostics.missing_env.length === 0
    && diagnostics.invalid_env.length === 0
    && diagnostics.wrong_server_env.length === 0;
  return diagnostics;
}

/* source 7854-7858 */
function customerSecurityRecoveryWorkerMaxBodyBytes() {
  const raw = Number(process.env.DIRAC_RECOVERY_WORKER_MAX_BODY_BYTES || 32768);
  if (!Number.isFinite(raw)) return 32768;
  return Math.max(4096, Math.min(128 * 1024, Math.floor(raw)));
}

/* source 7860-7864 */
function customerSecurityRecoveryWorkerClockSkewMs() {
  const raw = Number(process.env.DIRAC_RECOVERY_WORKER_CLOCK_SKEW_SECONDS || 120);
  if (!Number.isFinite(raw)) return 120 * 1000;
  return Math.max(30, Math.min(600, Math.floor(raw))) * 1000;
}

/* source 7866-7876 */
function customerSecurityRecoveryWorkerSign(caller, timestamp, canonicalBody) {
  return crypto.createHmac('sha512', customerSecurityRecoveryWorkerSecret())
    .update('dirac-recovery-worker-transport-hmac-v190')
    .update('\n')
    .update(String(caller || ''))
    .update('\n')
    .update(String(timestamp || ''))
    .update('\n')
    .update(String(canonicalBody || ''))
    .digest('base64url');
}

/* source 8215-8225 */
function customerSecurityRecoveryWorkerLocalEnabled() {
  const role = String(
    diracCentralEnvValueV150('DIRAC_CENTRAL_DEPLOYMENT_ROLE')
      || diracCentralEnvValueV150('DIRAC_DEPLOYMENT_ROLE')
      || ''
  ).trim().toLowerCase();
  const enabled = diracCentralEnvTrueV150('DIRAC_CENTRAL_VERCEL2_ACTIONS_ENABLED')
    || diracCentralEnvTrueV150('DIRAC_VERCEL2_ACTIONS_ENABLED');
  return role === 'vercel2'
    && enabled
    && !customerSecurityRecoveryWorkerUrl()
    && !customerSecurityRecoveryWorkerCaller()
    && Boolean(customerSecurityRecoveryWorkerSecret())
    && Boolean(customerSecurityRecoveryWorkerAllowedCaller());
}

/* source 8227-8237 */
function diracCentralGuardPassedForHandlerV168(req) {
  const ctx = diracCentralCurrentContextV149();
  return Boolean(
    req
    && req.__diracCentralSecurityGuardPassedV146 === true
    && ctx
    && ctx.req === req
    && ctx.guardPassport
    && ctx.guardPassport.integrity_checked === true
  );
}

/* source 8239-8246 */
function customerSecurityLostPasskeyCanonical(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) return '[' + value.map(customerSecurityLostPasskeyCanonical).join(',') + ']';
  if (typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + customerSecurityLostPasskeyCanonical(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

/* source 8250-8250 */
const DIRAC_RECOVERY_WORKER_TRANSPORT_VERSION_V190 = 'dirac-recovery-worker-hybrid-v191';

/* source 8251-8251 */
const DIRAC_RECOVERY_WORKER_TRANSPORT_SUITE_V190 = 'X25519+ML-KEM-1024+HKDF-SHA512+AES-256-GCM';

/* source 8252-8252 */
const DIRAC_RECOVERY_WORKER_RESPONSE_VERSION_V190 = 'dirac-recovery-worker-response-v191';

/* source 8253-8253 */
const DIRAC_RECOVERY_WORKER_TRANSPORT_TTL_MS_V190 = 120000;

/* source 8255-8259 */
function customerSecurityRecoveryWorkerTransportFailV190(code) {
  const error = new Error(String(code || 'RECOVERY_WORKER_TRANSPORT_FAILED'));
  error.code = String(code || 'RECOVERY_WORKER_TRANSPORT_FAILED');
  return error;
}

/* source 8261-8272 */
function customerSecurityRecoveryWorkerDecodeB64uV190(value, exactLength, maximumTextLength = 64 * 1024) {
  const clean = String(value || '').trim();
  if (!clean || clean.length > maximumTextLength || !/^[A-Za-z0-9_-]+$/.test(clean) || clean.length % 4 === 1) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_BASE64URL_INVALID');
  }
  const decoded = Buffer.from(clean, 'base64url');
  if (decoded.toString('base64url') !== clean || (exactLength !== null && decoded.length !== exactLength)) {
    decoded.fill(0);
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_BASE64URL_LENGTH_INVALID');
  }
  return decoded;
}

/* source 8274-8289 */
function customerSecurityRecoveryWorkerPrivateKeyV190(name, expectedType) {
  const raw = String(process.env[name] || '').trim();
  if (!raw) throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_PRIVATE_KEY_MISSING');
  let key;
  try {
    key = raw.includes('-----BEGIN')
      ? crypto.createPrivateKey(raw.replace(/\\n/g, '\n'))
      : crypto.createPrivateKey({ key: Buffer.from(raw, 'base64'), format: 'der', type: 'pkcs8' });
  } catch (_) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_PRIVATE_KEY_INVALID');
  }
  if (!key || key.asymmetricKeyType !== expectedType) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_PRIVATE_KEY_TYPE_INVALID');
  }
  return key;
}

/* source 8291-8306 */
function customerSecurityRecoveryWorkerKeyFingerprintV190(x25519Key, mlkemKey) {
  const xPublic = x25519Key && x25519Key.type === 'public' ? x25519Key : crypto.createPublicKey(x25519Key);
  const mlPublic = mlkemKey && mlkemKey.type === 'public' ? mlkemKey : crypto.createPublicKey(mlkemKey);
  const xDer = xPublic.export({ format: 'der', type: 'spki' });
  const mlDer = mlPublic.export({ format: 'der', type: 'spki' });
  const lengthPrefix = Buffer.alloc(8);
  lengthPrefix.writeUInt32BE(xDer.length, 0);
  lengthPrefix.writeUInt32BE(mlDer.length, 4);
  try {
    return crypto.createHash('sha512').update(lengthPrefix).update(xDer).update(mlDer).digest('base64url');
  } finally {
    lengthPrefix.fill(0);
    xDer.fill(0);
    mlDer.fill(0);
  }
}

/* source 8308-8324 */
function customerSecurityRecoveryWorkerTransportAadV190(envelope) {
  return {
    action: String(envelope.action || ''),
    worker_action: String(envelope.worker_action || ''),
    caller_id: String(envelope.caller_id || ''),
    nonce: String(envelope.nonce || ''),
    transport_version: String(envelope.transport_version || ''),
    transport_suite: String(envelope.transport_suite || ''),
    receiver_key_fingerprint: String(envelope.receiver_key_fingerprint || ''),
    sent_at_ms: Number(envelope.sent_at_ms),
    expires_at_ms: Number(envelope.expires_at_ms),
    x25519_ephemeral_public_key_b64url: String(envelope.x25519_ephemeral_public_key_b64url || ''),
    mlkem_ciphertext_b64url: String(envelope.mlkem_ciphertext_b64url || ''),
    hkdf_salt_b64url: String(envelope.hkdf_salt_b64url || ''),
    aead_nonce_b64url: String(envelope.aead_nonce_b64url || '')
  };
}

/* source 8326-8440 */
function customerSecurityRecoveryWorkerOpenV190(envelope, caller, timestampText) {
  if (typeof crypto.decapsulate !== 'function') {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_MLKEM_RUNTIME_UNAVAILABLE');
  }
  const source = envelope && typeof envelope === 'object' && !Array.isArray(envelope) ? envelope : {};
  const expectedKeys = [
    'action', 'aead_nonce_b64url', 'auth_tag_b64url', 'caller_id', 'ciphertext_b64url',
    'expires_at_ms', 'hkdf_salt_b64url', 'mlkem_ciphertext_b64url', 'nonce',
    'receiver_key_fingerprint', 'sent_at_ms',
    'transport_suite', 'transport_version', 'worker_action', 'x25519_ephemeral_public_key_b64url'
  ];
  const actualKeys = Object.keys(source).sort();
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_FIELDS_INVALID');
  }
  const sentAt = Number(source.sent_at_ms);
  const expiresAt = Number(source.expires_at_ms);
  const now = Date.now();
  if (source.transport_version !== DIRAC_RECOVERY_WORKER_TRANSPORT_VERSION_V190
    || source.transport_suite !== DIRAC_RECOVERY_WORKER_TRANSPORT_SUITE_V190
    || source.action !== DIRAC_RECOVERY_WORKER_ACTION
    || source.caller_id !== caller
    || sentAt !== Number(timestampText)
    || !Number.isSafeInteger(sentAt)
    || !Number.isSafeInteger(expiresAt)
    || sentAt > now + 30000
    || now - sentAt > DIRAC_RECOVERY_WORKER_TRANSPORT_TTL_MS_V190
    || expiresAt <= now
    || expiresAt <= sentAt
    || expiresAt - sentAt !== DIRAC_RECOVERY_WORKER_TRANSPORT_TTL_MS_V190) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_BINDING_INVALID');
  }
  const ephemeralDer = customerSecurityRecoveryWorkerDecodeB64uV190(source.x25519_ephemeral_public_key_b64url, 44, 256);
  const mlkemCiphertext = customerSecurityRecoveryWorkerDecodeB64uV190(source.mlkem_ciphertext_b64url, 1568, 4096);
  const salt = customerSecurityRecoveryWorkerDecodeB64uV190(source.hkdf_salt_b64url, 64, 256);
  const aeadNonce = customerSecurityRecoveryWorkerDecodeB64uV190(source.aead_nonce_b64url, 12, 128);
  const ciphertext = customerSecurityRecoveryWorkerDecodeB64uV190(source.ciphertext_b64url, null, 128 * 1024);
  const tag = customerSecurityRecoveryWorkerDecodeB64uV190(source.auth_tag_b64url, 16, 128);
  const x25519Private = customerSecurityRecoveryWorkerPrivateKeyV190('DIRAC_RECOVERY_WORKER_X25519_PRIVATE_KEY', 'x25519');
  const mlkemPrivate = customerSecurityRecoveryWorkerPrivateKeyV190('DIRAC_RECOVERY_WORKER_MLKEM1024_PRIVATE_KEY', 'ml-kem-1024');
  const fingerprint = customerSecurityRecoveryWorkerKeyFingerprintV190(x25519Private, mlkemPrivate);
  if (!safeEqual(fingerprint, source.receiver_key_fingerprint)) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_RECEIVER_KEY_MISMATCH');
  }
  let ephemeralPublic;
  try {
    ephemeralPublic = crypto.createPublicKey({ key: ephemeralDer, format: 'der', type: 'spki' });
  } catch (_) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_EPHEMERAL_KEY_INVALID');
  }
  if (ephemeralPublic.asymmetricKeyType !== 'x25519') {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_EPHEMERAL_KEY_TYPE_INVALID');
  }
  const classicShared = crypto.diffieHellman({ privateKey: x25519Private, publicKey: ephemeralPublic });
  const pqShared = Buffer.from(crypto.decapsulate(mlkemPrivate, mlkemCiphertext));
  if (classicShared.length !== 32 || pqShared.length !== 32 || crypto.timingSafeEqual(classicShared, Buffer.alloc(32))) {
    classicShared.fill(0);
    pqShared.fill(0);
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_SHARED_SECRET_INVALID');
  }
  const aad = Buffer.from(customerSecurityLostPasskeyCanonical(customerSecurityRecoveryWorkerTransportAadV190(source)), 'utf8');
  const transcriptHash = crypto.createHash('sha512').update(aad).digest();
  const ikm = Buffer.concat([classicShared, pqShared]);
  const requestKey = Buffer.from(crypto.hkdfSync('sha512', ikm, salt, Buffer.concat([
    Buffer.from('dirac/recovery-worker/v190/request\n', 'utf8'),
    transcriptHash
  ]), 32));
  const responseKey = Buffer.from(crypto.hkdfSync('sha512', ikm, salt, Buffer.concat([
    Buffer.from('dirac/recovery-worker/v190/response\n', 'utf8'),
    transcriptHash
  ]), 32));
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', requestKey, aeadNonce, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || customerSecurityLostPasskeyCanonical(parsed) !== text) {
      throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_PLAINTEXT_INVALID');
    }
    if (parsed.action !== source.action
      || parsed.worker_action !== source.worker_action
      || parsed.caller_id !== source.caller_id
      || parsed.nonce !== source.nonce) {
      throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_INNER_BINDING_INVALID');
    }
    return {
      body: parsed,
      responseKey,
      requestNonce: source.nonce,
      workerAction: source.worker_action,
      caller: source.caller_id
    };
  } catch (error) {
    responseKey.fill(0);
    if (error && error.code) throw error;
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_TRANSPORT_AUTHENTICATION_FAILED');
  } finally {
    ephemeralDer.fill(0);
    mlkemCiphertext.fill(0);
    salt.fill(0);
    aeadNonce.fill(0);
    ciphertext.fill(0);
    tag.fill(0);
    classicShared.fill(0);
    pqShared.fill(0);
    aad.fill(0);
    transcriptHash.fill(0);
    ikm.fill(0);
    requestKey.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}

/* source 8442-8450 */
function customerSecurityRecoveryWorkerResponseAadV190(context, status) {
  return {
    version: DIRAC_RECOVERY_WORKER_RESPONSE_VERSION_V190,
    request_nonce: String(context && context.requestNonce || ''),
    worker_action: String(context && context.workerAction || ''),
    caller_id: String(context && context.caller || ''),
    status: Number(status)
  };
}

/* source 8452-8480 */
function customerSecurityRecoveryWorkerEncryptResponseV190(payload, context, status) {
  const plaintext = Buffer.from(customerSecurityLostPasskeyCanonical(payload), 'utf8');
  const nonce = crypto.randomBytes(12);
  const aadObject = customerSecurityRecoveryWorkerResponseAadV190(context, status);
  const aad = Buffer.from(customerSecurityLostPasskeyCanonical(aadObject), 'utf8');
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', context.responseKey, nonce, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const result = {
      version: DIRAC_RECOVERY_WORKER_RESPONSE_VERSION_V190,
      request_nonce: context.requestNonce,
      worker_action: context.workerAction,
      caller_id: context.caller,
      status: Number(status),
      nonce_b64url: nonce.toString('base64url'),
      ciphertext_b64url: ciphertext.toString('base64url'),
      auth_tag_b64url: tag.toString('base64url')
    };
    ciphertext.fill(0);
    tag.fill(0);
    return result;
  } finally {
    plaintext.fill(0);
    nonce.fill(0);
    aad.fill(0);
  }
}

/* source 8482-8510 */
function customerSecurityRecoveryWorkerInstallResponseGuardV190(req, ctx, transportContext) {
  const res = ctx && ctx.res;
  if (!req || !ctx || !res || typeof res.json !== 'function' || !transportContext || !Buffer.isBuffer(transportContext.responseKey)) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_RESPONSE_GUARD_UNAVAILABLE');
  }
  if (res.__diracRecoveryWorkerResponseGuardV190 === true) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_WORKER_RESPONSE_GUARD_DUPLICATE');
  }
  const originalJson = res.json.bind(res);
  let used = false;
  res.json = function customerSecurityRecoveryWorkerEncryptedJsonV190(payload) {
    if (used || req.__diracRecoveryWorkerTransportVerifiedV190 !== true) {
      return originalJson({ ok: false, code: 'RECOVERY_WORKER_RESPONSE_GUARD_REJECTED', message: 'Respons recovery ditolak.' });
    }
    used = true;
    try {
      const status = Number(res.statusCode || 200);
      const encrypted = customerSecurityRecoveryWorkerEncryptResponseV190(payload, transportContext, status);
      return originalJson({ ok: true, transport_encrypted: true, transport_response: encrypted });
    } catch (_) {
      try { if (typeof res.status === 'function') res.status(500); } catch (_) {}
      return originalJson({ ok: false, code: 'RECOVERY_WORKER_RESPONSE_ENCRYPTION_FAILED', message: 'Respons recovery ditolak.' });
    } finally {
      transportContext.responseKey.fill(0);
      ctx.__diracRecoveryWorkerResponseKeyV190 = null;
    }
  };
  Object.defineProperty(res, '__diracRecoveryWorkerResponseGuardV190', { value: true, enumerable: false });
}

/* source 8512-8523 */
function customerSecurityLostPasskeyArgon2EnvIntegerV191(name, fallback, minimum, maximum) {
  const raw = String(process.env[String(name || '')] || '').trim();
  if (!raw) return fallback;
  if (!/^\d+$/.test(raw)) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_ARGON2_PROFILE_INVALID');
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw customerSecurityRecoveryWorkerTransportFailV190('RECOVERY_ARGON2_PROFILE_INVALID');
  }
  return value;
}

/* source 8525-8562 */
function customerSecurityLostPasskeyArgon2ProfilesV191() {
  const configuredMemory = customerSecurityLostPasskeyArgon2EnvIntegerV191(
    'DIRAC_LOST_PASSKEY_ARGON2_MEMORY_KIB', 1048576, 1048576, 5242880
  );
  const configuredTime = customerSecurityLostPasskeyArgon2EnvIntegerV191(
    'DIRAC_LOST_PASSKEY_ARGON2_TIME_COST', 4, 4, 12
  );
  const configuredParallelism = customerSecurityLostPasskeyArgon2EnvIntegerV191(
    'DIRAC_LOST_PASSKEY_ARGON2_PARALLELISM', 4, 4, 4
  );
  const hpkeMinimumMemory = customerSecurityLostPasskeyArgon2EnvIntegerV191(
    'DIRAC_RECOVERY_HPKE_ARGON2_MEMORY_KIB', configuredMemory, 1048576, 5242880
  );
  const hpkeMinimumTime = customerSecurityLostPasskeyArgon2EnvIntegerV191(
    'DIRAC_RECOVERY_HPKE_ARGON2_TIME_COST', configuredTime, 4, 12
  );
  const main = Object.freeze({
    memoryCost: Math.max(configuredMemory, hpkeMinimumMemory),
    timeCost: Math.max(configuredTime, hpkeMinimumTime),
    parallelism: configuredParallelism
  });
  const linkOpen = Object.freeze({
    memoryCost: customerSecurityLostPasskeyArgon2EnvIntegerV191(
      'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_MEMORY_KIB', main.memoryCost, 1048576, 5242880
    ),
    timeCost: customerSecurityLostPasskeyArgon2EnvIntegerV191(
      'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_TIME_COST', main.timeCost, 4, 12
    ),
    parallelism: customerSecurityLostPasskeyArgon2EnvIntegerV191(
      'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_PARALLELISM', 4, 4, 4
    )
  });
  return Object.freeze({
    main,
    linkOpen,
    hpkeMinimum: Object.freeze({ memoryCost: hpkeMinimumMemory, timeCost: hpkeMinimumTime })
  });
}

/* source 8564-8572 */
function customerSecurityLostPasskeyArgon2ParamsV157(hashLength) {
  const profile = customerSecurityLostPasskeyArgon2ProfilesV191().main;
  return {
    memoryCost: profile.memoryCost,
    timeCost: profile.timeCost,
    parallelism: profile.parallelism,
    hashLength: Math.max(32, Math.min(128, Number(hashLength || 32)))
  };
}

/* source 8574-8582 */
function customerSecurityLostPasskeyLinkOpenArgon2ParamsV171(hashLength) {
  const profile = customerSecurityLostPasskeyArgon2ProfilesV191().linkOpen;
  return {
    memoryCost: profile.memoryCost,
    timeCost: profile.timeCost,
    parallelism: profile.parallelism,
    hashLength: Math.max(32, Math.min(128, Number(hashLength || 32)))
  };
}

/* source 8589-8601 */
async function customerSecurityLostPasskeyArgon2Raw(input, salt, hashLength) {
  const argon2 = customerSecurityGetArgon2();
  const params = customerSecurityLostPasskeyArgon2ParamsV157(hashLength);
  return Buffer.from(await argon2.hash(input, {
    type: argon2.argon2id,
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    hashLength: params.hashLength,
    salt: Buffer.from(salt),
    raw: true
  }));
}

/* source 8625-8629 */
function customerSecurityLostPasskeyRootSecretV157() {
  const secret = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').normalize('NFC');
  if (Buffer.byteLength(secret, 'utf8') < LOST_PASSKEY_ROOT_SECRET_MIN_BYTES_V157) return '';
  return secret;
}

/* source 8631-8634 */
function customerSecurityLostPasskeyRootSecretVersionV157() {
  const clean = String(process.env.DIRAC_SECURITY_ROOT_SECRET_VERSION || process.env.DIRAC_LOST_PASSKEY_ROOT_SECRET_VERSION || 'v1').trim();
  return /^[A-Za-z0-9_.-]{1,80}$/.test(clean) ? clean : 'v1';
}

/* source 8636-8644 */
function customerSecurityLostPasskeyDbPepperV157() {
  const pepper = String(process.env.DIRAC_LOST_PASSKEY_DB_PEPPER || '').normalize('NFC');
  if (Buffer.byteLength(pepper, 'utf8') >= LOST_PASSKEY_DB_PEPPER_MIN_BYTES_V157) return pepper;
  const rootSecret = customerSecurityLostPasskeyRootSecretV157();
  if (!rootSecret) return '';
  return crypto.createHmac('sha512', rootSecret)
    .update('dirac-lost-passkey-db-pepper-v157')
    .digest('base64url');
}

/* source 8646-8652 */
function customerSecurityLostPasskeyRequireVaultSecretsV157() {
  const rootSecret = customerSecurityLostPasskeyRootSecretV157();
  const pepper = customerSecurityLostPasskeyDbPepperV157();
  if (!rootSecret) return { ok: false, code: 'LOST_PASSKEY_ROOT_SECRET_INVALID', message: 'Konfigurasi recovery vault belum valid.' };
  if (!pepper) return { ok: false, code: 'LOST_PASSKEY_DB_PEPPER_INVALID', message: 'Konfigurasi recovery vault belum valid.' };
  return { ok: true, rootSecret, pepper, rootSecretVersion: customerSecurityLostPasskeyRootSecretVersionV157() };
}

/* source 8654-8658 */
function customerSecurityLostPasskeyRandomTextV157(length) {
  let out = '';
  while (out.length < Number(length || 0)) out += customerSecurityPickRecoveryChar(LOST_PASSKEY_SECRET_100_ALPHABET_V157);
  return out;
}

/* source 8660-8660 */
const DIRAC_RECOVERY_DUAL_DELIVERY_PATCH_V182 = 'lost-passkey-email-website-code-all-or-reject-v182';

/* source 8662-8669 */
function customerSecurityLostPasskeyExactSecret100V182(value) {
  if (typeof value !== 'string') return '';
  if (value.length !== LOST_PASSKEY_SECRET_100_CHAR_LENGTH_V157) return '';
  for (const char of value) {
    if (!LOST_PASSKEY_SECRET_100_ALPHABET_V157.includes(char)) return '';
  }
  return value;
}

/* source 8671-8689 */
function customerSecurityLostPasskeyGenerateSuccessPayloadV182(input = {}) {
  const websiteRecoveryCode = customerSecurityLostPasskeyExactSecret100V182(input.websiteRecoveryCode);
  if (!websiteRecoveryCode) return null;
  const requestId = String(input.requestId || '').trim();
  const expiresAt = String(input.expiresAt || '').trim();
  if (!requestId || !expiresAt) return null;
  return {
    ok: true,
    request_id: requestId,
    expires_at: expiresAt,
    delivery: 'official_recovery_html_link',
    website_recovery_code: websiteRecoveryCode,
    websiteRecoveryCode: websiteRecoveryCode,
    website_code: websiteRecoveryCode,
    email_code_delivery: 'included_in_email_100_char',
    message: String(input.message || 'Link recovery resmi sudah dikirim ke email resmi akun.'),
    time: String(input.time || diracNowIso())
  };
}

/* source 8691-8693 */
function customerSecurityLostPasskeyNormalizeSecretV157(value) {
  return String(value || '').normalize('NFKC').replace(/[\u200B-\u200D\uFEFF\s]+/g, '').trim();
}

/* source 8695-8700 */
function customerSecurityLostPasskeyNormalizePasswordV157(value) {
  const normalized = String(value || '').normalize('NFC');
  if (Buffer.byteLength(normalized, 'utf8') < 6) return '';
  if (Buffer.byteLength(normalized, 'utf8') > 1024) return '';
  return normalized;
}

/* source 8702-8704 */
function customerSecurityExtractPasswordMaterialV157(body) {
  return customerSecurityLostPasskeyNormalizePasswordV157(body && (body.password_latest_material || body.password_latest_proof || body.account_password || body.current_password || body.currentPassword || ''));
}

/* source 8706-8708 */
function customerSecurityLostPasskeySha256HexV157(value) {
  return crypto.createHash('sha256').update(Buffer.isBuffer(value) ? value : Buffer.from(String(value || ''), 'utf8')).digest('hex');
}

function customerSecurityLostPasskeyDiagnosticCodeV210(value, maximum = 120) {
  return String(value || 'recovery_worker_event')
    .replace(/[^a-zA-Z0-9_.:-]/g, '_')
    .slice(0, Math.max(1, Math.min(160, Number(maximum || 120))));
}

function customerSecurityLostPasskeyDiagnosticHashV210(label, value) {
  const input = String(value || '');
  if (!input) return '';
  const secret = Buffer.from(customerSecurityLostPasskeySecret('diagnostic-v210'));
  try {
    return crypto.createHmac('sha512', secret)
      .update('dirac-recovery-diagnostic-v210\n', 'utf8')
      .update(String(label || 'value'), 'utf8')
      .update('\n', 'utf8')
      .update(input, 'utf8')
      .digest('hex');
  } finally {
    secret.fill(0);
  }
}

/* source 8710-8717 */
function customerSecurityLostPasskeyHmacHexV157(secret, label, value) {
  return crypto.createHmac('sha256', Buffer.from(String(secret || ''), 'utf8'))
    .update('dirac-lost-passkey-v157\n')
    .update(String(label || ''))
    .update('\n')
    .update(Buffer.isBuffer(value) ? value : Buffer.from(String(value || ''), 'utf8'))
    .digest('hex');
}

/* source 8730-8738 */
function customerSecurityLostPasskeySensitiveHashInputV157(label, value, pepper, rootSecret) {
  return Buffer.from(customerSecurityLostPasskeyCanonical({
    version: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157,
    label: String(label || ''),
    value: String(value || ''),
    pepper,
    root_secret_commitment: customerSecurityLostPasskeySha256HexV157(rootSecret)
  }), 'utf8');
}

/* source 8740-8752 */
async function customerSecurityLostPasskeyArgon2EncodedHashV157(label, value, salt, pepper, rootSecret) {
  const argon2 = customerSecurityGetArgon2();
  const params = customerSecurityLostPasskeyArgon2ParamsV157(64);
  return await argon2.hash(customerSecurityLostPasskeySensitiveHashInputV157(label, value, pepper, rootSecret), {
    type: argon2.argon2id,
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    hashLength: 64,
    salt: Buffer.from(salt),
    raw: false
  });
}

/* source 8754-8766 */
async function customerSecurityLostPasskeyArgon2EncodedHashLinkOpenV171(label, value, salt, pepper, rootSecret) {
  const argon2 = customerSecurityGetArgon2();
  const params = customerSecurityLostPasskeyLinkOpenArgon2ParamsV171(64);
  return await argon2.hash(customerSecurityLostPasskeySensitiveHashInputV157(label, value, pepper, rootSecret), {
    type: argon2.argon2id,
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    hashLength: 64,
    salt: Buffer.from(salt),
    raw: false
  });
}

/* source 8768-8777 */
function customerSecurityLostPasskeyArgon2EncodedParamsV171(encodedHash) {
  const hash = String(encodedHash || '');
  const match = hash.match(/\$m=(\d+),t=(\d+),p=(\d+)\$/);
  if (!match) return null;
  return {
    memoryCost: Number(match[1] || 0),
    timeCost: Number(match[2] || 0),
    parallelism: Number(match[3] || 0)
  };
}

/* source 8891-8896 */
async function customerSecurityLostPasskeyArgon2VerifyHashV157(label, value, encodedHash, pepper, rootSecret) {
  const hash = String(encodedHash || '');
  if (!hash.startsWith('$argon2id$')) return false;
  const argon2 = customerSecurityGetArgon2();
  return await argon2.verify(hash, customerSecurityLostPasskeySensitiveHashInputV157(label, value, pepper, rootSecret));
}

/* source 8902-8917 */
function customerSecurityLostPasskeyOfficialBaseUrlV157() {
  // SERVER 2 SECURE ORIGIN LOCK v169:
  // Lost-passkey static HTML and vault API are only allowed on secure.diracgroup.store.
  // Do not fall back to diracgroup.store or www.diracgroup.store.
  const requiredOrigin = 'https://secure.diracgroup.store';
  const raw = String(process.env.DIRAC_LOST_PASSKEY_RECOVERY_BASE_URL || requiredOrigin).trim().replace(/\/+$/, '');
  try {
    const url = new URL(raw);
    const host = String(url.hostname || '').toLowerCase();
    if (url.protocol !== 'https:') return requiredOrigin;
    if (host !== 'secure.diracgroup.store') return requiredOrigin;
    return requiredOrigin;
  } catch (_) {
    return requiredOrigin;
  }
}

/* source 8919-8921 */
function customerSecurityLostPasskeyLinkTokenShapeV162(value) {
  return /^[A-Za-z0-9_-]{320,360}$/.test(String(value || '').trim());
}

/* source 9326-9326 */
const DIRAC_RECOVERY_WORKER_ROOT_CAUSE_DEBUG_V173 = 'server2-lost-passkey-worker-root-cause-debug-v173';

/* source 9332-9335 */
function customerSecurityLostPasskeyRootCauseDebugEnabledV173() {
  const value = String(process.env.DIRAC_RECOVERY_WORKER_ROOT_CAUSE_DEBUG || process.env.DIRAC_RECOVERY_WORKER_DEBUG || '').trim().toLowerCase();
  return process.env.NODE_ENV !== 'production'
    && (value === '1' || value === 'true' || value === 'yes' || value === 'on');
}

/* source 9337-9348 */
function customerSecurityLostPasskeyCompareHashV173(field, stored, incoming) {
  const storedText = String(stored || '').trim();
  const incomingText = String(incoming || '').trim();
  return {
    field,
    stored_present: Boolean(storedText),
    incoming_present: Boolean(incomingText),
    stored_shape_64_hex: /^[a-f0-9]{64}$/i.test(storedText),
    incoming_shape_64_hex: /^[a-f0-9]{64}$/i.test(incomingText),
    matched: Boolean(storedText && incomingText && safeEqual(storedText, incomingText))
  };
}

/* source 9350-9369 */
function customerSecurityLostPasskeyRowStateV173(row) {
  if (!row || !row.id) return { found: false };
  const expiresMs = Date.parse(String(row.expires_at || ''));
  const nowMs = Date.now();
  return {
    found: true,
    status: String(row.status || ''),
    attempt_count: Number(row.attempt_count || 0),
    expires_at_present: Boolean(row.expires_at),
    expires_at_valid: Number.isFinite(expiresMs),
    expires_in_ms: Number.isFinite(expiresMs) ? expiresMs - nowMs : null,
    expired: Number.isFinite(expiresMs) ? expiresMs <= nowMs : true,
    used_present: Boolean(row.used_at),
    revoked_present: Boolean(row.revoked_at),
    locked_present: Boolean(row.locked_at),
    old_passkey_count: Array.isArray(row.old_passkey_ids) ? row.old_passkey_ids.length : null,
    recovery_code_hash_present: Boolean(row.recovery_code_hash),
    metadata_present: Boolean(row.metadata && typeof row.metadata === 'object')
  };
}

/* source 9371-9438 */
function customerSecurityLostPasskeyWorkerRootCauseDebugV173(reason, ctx = {}) {
  const body = ctx.body && typeof ctx.body === 'object' ? ctx.body : {};
  const owner = ctx.owner && typeof ctx.owner === 'object' ? ctx.owner : null;
  const bindings = ctx.bindings && typeof ctx.bindings === 'object' ? ctx.bindings : null;
  const row = ctx.row && typeof ctx.row === 'object' ? ctx.row : null;
  const metadata = row && row.metadata && typeof row.metadata === 'object' ? row.metadata : (ctx.metadata && typeof ctx.metadata === 'object' ? ctx.metadata : {});
  const codeText = String(ctx.code || '');
  const rowState = customerSecurityLostPasskeyRowStateV173(row);
  const binding_compare = row && bindings ? [
    customerSecurityLostPasskeyCompareHashV173('email_hash', row.email_hash, bindings.emailBindingHash),
    customerSecurityLostPasskeyCompareHashV173('customer_binding_hash', row.customer_binding_hash, bindings.customerBindingHash),
    customerSecurityLostPasskeyCompareHashV173('auth_user_binding_hash', row.auth_user_binding_hash, bindings.authUserBindingHash),
    customerSecurityLostPasskeyCompareHashV173('device_binding_hash', row.device_binding_hash, bindings.deviceBindingHash),
    customerSecurityLostPasskeyCompareHashV173('ip_hash', row.ip_hash, bindings.ipHash),
    customerSecurityLostPasskeyCompareHashV173('user_agent_hash', row.user_agent_hash, bindings.userAgentHash)
  ] : [];

  const rootCauseCandidates = [];
  const cleanReason = String(reason || '').slice(0, 120);
  if (cleanReason) rootCauseCandidates.push(cleanReason);
  if (!owner || owner.ok !== true) rootCauseCandidates.push('owner_not_resolved_or_invalid');
  if (!bindings) rootCauseCandidates.push('worker_binding_payload_invalid_or_owner_core_binding_mismatch');
  if (!customerSecurityNormalizeLostPasskeyRequestId(ctx.requestId || body.request_id || '')) rootCauseCandidates.push('request_id_missing_or_invalid');
  if (codeText && Array.from(codeText).length !== LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157) rootCauseCandidates.push('recovery_code_length_not_1200_after_normalization');
  if (rowState.found === false && (ctx.rowChecked === true || cleanReason.includes('not_found'))) rootCauseCandidates.push('request_row_not_found_in_security_lost_passkey_recovery_requests');
  if (rowState.found && rowState.status !== 'pending') rootCauseCandidates.push('request_status_not_pending');
  if (rowState.found && rowState.used_present) rootCauseCandidates.push('request_already_used');
  if (rowState.found && rowState.revoked_present) rootCauseCandidates.push('request_revoked');
  if (rowState.found && rowState.locked_present) rootCauseCandidates.push('request_locked');
  if (rowState.found && rowState.expired) rootCauseCandidates.push('request_expired_or_expires_at_invalid');
  if (binding_compare.some((item) => item && item.matched === false)) rootCauseCandidates.push('one_or_more_binding_hashes_do_not_match_server1_payload');
  if (metadata && !metadata.binding_hash_commitment) rootCauseCandidates.push('metadata_binding_hash_commitment_missing');
  if (ctx.bindingCommitmentOk === false) rootCauseCandidates.push('binding_argon2_commitment_mismatch_root_secret_or_binding_changed');
  if (ctx.recoveryCodeOk === false) rootCauseCandidates.push('recovery_code_argon2_hash_mismatch_or_wrong_code');
  if (ctx.activePasskeyCount === 0) rootCauseCandidates.push('active_passkey_not_found_for_owner');

  return {
    diagnostic_version: DIRAC_RECOVERY_WORKER_ROOT_CAUSE_DEBUG_V173,
    reason: cleanReason || 'recovery_worker_rejected',
    worker_action: String(body.worker_action || ctx.workerAction || '').slice(0, 80),
    request_id_present: Boolean(customerSecurityNormalizeLostPasskeyRequestId(ctx.requestId || body.request_id || '')),
    request_id_hash: customerSecurityLostPasskeyDiagnosticHashV210('request_id', customerSecurityNormalizeLostPasskeyRequestId(ctx.requestId || body.request_id || '')),
    code_length_after_normalization: codeText ? Array.from(codeText).length : 0,
    expected_code_length: LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157,
    owner: {
      ok: Boolean(owner && owner.ok === true),
      customer_match_row: Boolean(owner && row && String(owner.customerId || '') === String(row.customer_id || '')),
      auth_user_match_row: Boolean(owner && row && String(owner.authUserId || '') === String(row.auth_user_id || '')),
      email_present: Boolean(owner && owner.email)
    },
    row: rowState,
    binding_compare,
    metadata: {
      binding_hash_commitment_present: Boolean(metadata && metadata.binding_hash_commitment),
      vault_bundle_present: Boolean(metadata && metadata.vault_bundle && typeof metadata.vault_bundle === 'object'),
      root_secret_version_present: Boolean(metadata && metadata.root_secret_version),
      hash_salts_present: Boolean(metadata && metadata.hash_salts && typeof metadata.hash_salts === 'object')
    },
    checks: {
      binding_commitment_ok: ctx.bindingCommitmentOk === undefined ? null : Boolean(ctx.bindingCommitmentOk),
      recovery_code_ok: ctx.recoveryCodeOk === undefined ? null : Boolean(ctx.recoveryCodeOk),
      active_passkey_count: ctx.activePasskeyCount === undefined ? null : Number(ctx.activePasskeyCount || 0),
      supabase_status: ctx.supabaseStatus === undefined ? null : Number(ctx.supabaseStatus || 0)
    },
    root_cause_candidates: Array.from(new Set(rootCauseCandidates)).slice(0, 12),
    time: diracNowIso()
  };
}

/* source 9440-9455 */
function customerSecurityLostPasskeySecurityReportPayloadV157(reason, body, debugContext) {
  const payload = {
    source: 'server2_lost_passkey_worker',
    version: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157,
    reason: customerSecurityLostPasskeyDiagnosticCodeV210(reason || 'recovery_worker_rejected'),
    request_id_hash: customerSecurityLostPasskeyDiagnosticHashV210('request_id', customerSecurityNormalizeLostPasskeyRequestId(body && body.request_id || '')) || null,
    customer_id_hash: customerSecurityLostPasskeyDiagnosticHashV210('customer_id', String(body && body.customer_id || '')) || null,
    auth_user_id_hash: customerSecurityLostPasskeyDiagnosticHashV210('auth_user_id', String(body && body.auth_user_id || '')) || null,
    email_hash: customerSecurityLostPasskeyDiagnosticHashV210('email', normalizeAuthEmail(body && body.email)) || null,
    time: diracNowIso()
  };
  if (customerSecurityLostPasskeyRootCauseDebugEnabledV173()
      && debugContext
      && typeof debugContext === 'object') {
    payload.root_cause_debug = customerSecurityLostPasskeyWorkerRootCauseDebugV173(reason, { ...debugContext, body });
  }
  return payload;
}

/* source 9457-9470 */
function customerSecurityLostPasskeyGenericWorkerErrorV157(res, status, reason, body, debugContext) {
  const securityReportPayload = customerSecurityLostPasskeySecurityReportPayloadV157(reason, body, debugContext);
  try {
    console.error('[dirac-recovery-worker-event-v210]', JSON.stringify({
      source: securityReportPayload.source,
      reason: securityReportPayload.reason,
      request_id_hash: securityReportPayload.request_id_hash,
      http_status: Number(status || 403),
      time: securityReportPayload.time
    }));
  } catch (_) {}
  const responseBody = {
    ok: false,
    code: 'RECOVERY_WORKER_REJECTED',
    message: 'Permintaan recovery ditolak.',
    security_report_payload: securityReportPayload
  };
  if (customerSecurityLostPasskeyRootCauseDebugEnabledV173() && securityReportPayload.root_cause_debug) {
    responseBody.worker_root_cause_debug = securityReportPayload.root_cause_debug;
  }
  return res.status(status || 403).json(responseBody);
}

/* source 9477-9477 */
const DIRAC_RECOVERY_WORKER_VERIFY_DEBUG_V174 = 'server2-lost-passkey-worker-verify-debug-v174';

/* source 9479-9504 */
function customerSecurityLostPasskeyWorkerVerifyTraceV174(stage, reason, ctx = {}) {
  const safeCtx = ctx && typeof ctx === 'object' ? ctx : {};
  const responseBody = safeCtx.responseBody && typeof safeCtx.responseBody === 'object' ? safeCtx.responseBody : {};
  const debug = customerSecurityLostPasskeyWorkerRootCauseDebugV173(reason || stage || 'verify_trace', safeCtx);
  const trace = {
    ...debug,
    diagnostic_version: DIRAC_RECOVERY_WORKER_VERIFY_DEBUG_V174,
    stage: String(stage || 'unknown').slice(0, 80),
    http_status: safeCtx.httpStatus === undefined ? null : Number(safeCtx.httpStatus || 0),
    verify_contract: {
      server2_worker_task: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
      recovery_request_table: LOST_PASSKEY_RECOVERY_REQUEST_TABLE,
      recovery_session_table: LOST_PASSKEY_RECOVERY_SESSION_TABLE,
      code_length_expected: LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157,
      session_insert_attempted_by_this_branch: Boolean(safeCtx.sessionInsertAttempted),
      response_includes_recovery_session_token: Boolean(responseBody && responseBody.recovery_session_token),
      response_includes_recovery_session_expires_at: Boolean(responseBody && responseBody.recovery_session_expires_at),
      response_ok: responseBody.ok === undefined ? null : Boolean(responseBody.ok),
      response_valid: responseBody.valid === undefined ? null : Boolean(responseBody.valid),
      html_can_open_passkey_stage_from_this_response: Boolean(responseBody && responseBody.ok === true && responseBody.recovery_session_token)
    },
    debug_hint: String(safeCtx.debugHint || '').slice(0, 220)
  };
  try {
    console.error('[dirac-recovery-worker-verify-v210]', JSON.stringify({
      stage: customerSecurityLostPasskeyDiagnosticCodeV210(stage, 80),
      reason: customerSecurityLostPasskeyDiagnosticCodeV210(reason, 120),
      request_id_hash: trace.request_id_hash || null,
      http_status: trace.http_status,
      time: trace.time
    }));
  } catch (_) {}
  return trace;
}

/* source 9643-9653 */
async function customerSecurityVerifyAccountPasswordForPdfV156(email, accountPassword) {
  const normalizedEmail = normalizeAuthEmail(email);
  const password = String(accountPassword || '');
  if (!isValidAuthEmail(normalizedEmail) || !password) return { ok: false, status: 400 };
  const result = await supabaseFetch('/auth/v1/token?grant_type=password', {
    method: 'POST',
    auth: 'anon',
    body: { email: normalizedEmail, password }
  });
  return { ok: !!result.ok, status: result.status || (result.ok ? 200 : 403) };
}

/* source 9720-9740 */
function customerSecurityLostPasskeyBindings(req, owner) {
  const email = normalizeAuthEmail(owner && owner.email);
  const customerId = String(owner && owner.customerId || '');
  const authUserId = String(owner && owner.authUserId || '');
  const ip = customerSecurityRequestIp(req) || '';
  const ua = requestUserAgent(req);
  const acceptLanguage = String(req && req.headers && req.headers['accept-language'] || '');
  const secChUa = String(req && req.headers && req.headers['sec-ch-ua'] || '');
  const origin = requestOrigin(req);
  let sessionHash = '';
  try { sessionHash = typeof diracCentralRequestSessionHashV146 === 'function' ? diracCentralRequestSessionHashV146(req) : ''; } catch (_) {}
  const deviceMaterial = [ip, ua, acceptLanguage, secChUa, origin, sessionHash].join('|');
  return {
    emailBindingHash: customerSecurityLostPasskeyHashHex('email-binding', email),
    customerBindingHash: customerSecurityLostPasskeyHashHex('customer-binding', customerId),
    authUserBindingHash: customerSecurityLostPasskeyHashHex('auth-user-binding', authUserId),
    deviceBindingHash: customerSecurityLostPasskeyHashHex('device-binding', deviceMaterial),
    ipHash: customerSecurityLostPasskeyHashHex('ip', ip),
    userAgentHash: customerSecurityLostPasskeyHashHex('ua', ua)
  };
}

/* source 9742-9761 */
async function customerSecurityResolveLostPasskeyOwner(access) {
  const user = access && access.user;
  const authUserId = String(access && access.authUserId || user && user.id || '').trim();
  const sessionEmail = normalizeAuthEmail(user && user.email);
  const customerId = String(access && access.customerId || access && access.link && access.link.customer_id || '').trim();
  if (!customerSecurityLooksLikeUuid(authUserId) || !isValidAuthEmail(sessionEmail) || !customerSecurityLooksLikeUuid(customerId)) {
    return { ok: false, status: 401, message: 'Sesi recovery tidak valid.' };
  }
  if (!access.link || access.link.link_status !== 'active' || String(access.link.customer_id) !== customerId) {
    return { ok: false, status: 403, message: 'Auth link recovery tidak aktif.' };
  }
  const customerResult = await diracPasskeyA2FFetchCustomerById(customerId);
  if (!customerResult.ok) return { ok: false, status: customerResult.status || 500, message: 'Gagal membaca customer resmi.' };
  const customer = Array.isArray(customerResult.data) ? customerResult.data[0] : null;
  const customerEmail = normalizeAuthEmail(customer && customer.email);
  if (!customer || !isValidAuthEmail(customerEmail) || customerEmail !== sessionEmail) {
    return { ok: false, status: 403, message: 'Email session tidak cocok dengan email resmi customer.' };
  }
  return { ok: true, authUserId, customerId, email: customerEmail, customer };
}

/* source 9763-9767 */
async function customerSecurityLostPasskeyActivePasskeys(owner) {
  if (typeof diracPasskeyA2FListActivePasskeys !== 'function') return [];
  const rows = await diracPasskeyA2FListActivePasskeys(owner).catch(() => []);
  return (Array.isArray(rows) ? rows : []).filter((row) => row && row.is_active === true && diracPasskeyA2FOwnerMatches(row, owner));
}

/* source 9883-9891 */
function customerSecurityRecoverySmtpConfig() {
  const host = String(process.env.DIRAC_RECOVERY_SMTP_HOST || '').trim();
  const port = Number(process.env.DIRAC_RECOVERY_SMTP_PORT || 465);
  const secure = String(process.env.DIRAC_RECOVERY_SMTP_SECURE || 'true').trim().toLowerCase() !== 'false';
  const user = String(process.env.DIRAC_RECOVERY_SMTP_USER || '').trim();
  const pass = String(process.env.DIRAC_RECOVERY_SMTP_APP_PASSWORD || '').trim();
  if (!host || !port || !secure || !user || !pass) return null;
  return { host, port, secure, user, pass };
}

/* source 9893-9897 */
function customerSecurityRecoveryEmailAddress(value) {
  const text = String(value || '').trim();
  const match = text.match(/<([^<>@\s]+@[^<>\s]+)>/);
  return normalizeAuthEmail(match ? match[1] : text);
}

/* source 9899-9901 */
function customerSecurityRecoveryBase64Lines(value) {
  return Buffer.from(value).toString('base64').replace(/.{1,76}/g, '$&\r\n').trim();
}

/* source 9903-9905 */
function customerSecurityRecoveryMimeHeader(value) {
  return '=?UTF-8?B?' + Buffer.from(String(value || ''), 'utf8').toString('base64') + '?=';
}

/* source 9907-9909 */
function customerSecurityRecoveryDotStuff(value) {
  return String(value || '').replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
}

/* source 9962-9983 */
async function customerSecuritySmtpRead(socket) {
  return await new Promise((resolve, reject) => {
    let buffer = '';
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split(/\r?\n/).filter(Boolean);
      const last = lines[lines.length - 1] || '';
      if (/^\d{3}\s/.test(last)) cleanup(resolve, { code: Number(last.slice(0, 3)), text: buffer });
    };
    const onError = (error) => cleanup(reject, error);
    const onTimeout = () => cleanup(reject, new Error('SMTP_TIMEOUT'));
    const cleanup = (done, value) => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('timeout', onTimeout);
      done(value);
    };
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('timeout', onTimeout);
  });
}

/* source 9985-9995 */
async function customerSecuritySmtpCommand(socket, command, allowed) {
  if (command) socket.write(command + '\r\n');
  const response = await customerSecuritySmtpRead(socket);
  const allowedCodes = Array.isArray(allowed) ? allowed : [allowed];
  if (!allowedCodes.includes(response.code)) {
    const error = new Error('SMTP_UNEXPECTED_RESPONSE');
    error.smtpCode = response.code;
    throw error;
  }
  return response;
}

/* source 10117-10119 */
function customerSecurityLostPasskeyEmailEscapeHtmlV157(value) {
  return String(value || '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

/* source 10121-10133 */
function customerSecurityLostPasskeyRecoveryEmailBannerUrlV172() {
  const fallback = 'https://secure.diracgroup.store/mmmail.webp';
  const raw = String(process.env.DIRAC_RECOVERY_EMAIL_BANNER_URL || process.env.DIRAC_LOST_PASSKEY_EMAIL_BANNER_URL || fallback).trim();
  try {
    const url = new URL(raw);
    const host = url.hostname.toLowerCase();
    if (url.protocol !== 'https:') return fallback;
    if (host !== 'diracgroup.store' && host !== 'www.diracgroup.store' && host !== 'secure.diracgroup.store' && !host.endsWith('.diracgroup.store')) return fallback;
    return url.toString();
  } catch (_) {
    return fallback;
  }
}

/* source 10135-10179 */
function customerSecurityLostPasskeyRecoveryLinkEmailHtmlV157(context = {}) {
  const requestId = customerSecurityLostPasskeyEmailEscapeHtmlV157(context.requestId || '');
  const expiresAt = customerSecurityLostPasskeyEmailEscapeHtmlV157(context.expiresAt || '');
  const recoveryLink = customerSecurityLostPasskeyEmailEscapeHtmlV157(context.recoveryLink || '');
  const emailSecret = customerSecurityLostPasskeyEmailEscapeHtmlV157(context.emailSecret || '');
  const bannerUrl = customerSecurityLostPasskeyEmailEscapeHtmlV157(customerSecurityLostPasskeyRecoveryEmailBannerUrlV172());

  return '<!doctype html>'
    + '<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dirac Group Secure Recovery</title></head>'
    + '<body style="margin:0;padding:0;background:#1f1f1f;font-family:Arial,Helvetica,sans-serif;color:#f1f3f4">'
    + '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;background:#1f1f1f;margin:0;padding:24px 0"><tr><td align="center" style="padding:0 12px">'
    + '<table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="width:600px;max-width:100%;border-collapse:collapse;border:1px solid #b8c3d9;background:#202124">'
    + '<tr><td style="height:2px;line-height:2px;font-size:0;background:#b8c3d9">&nbsp;</td></tr>'
    + '<tr><td style="padding:0;border-bottom:1px solid #b8c3d9;background:#202124">'
    + '<img src="' + bannerUrl + '" width="600" alt="Dirac Group Secure Recovery" style="display:block;width:100%;max-width:600px;height:auto;border:0;outline:none;text-decoration:none">'
    + '</td></tr>'
    + '<tr><td style="padding:28px 28px 12px;background:#202124;color:#f1f3f4">'
    + '<p style="margin:0 0 18px;font-size:15px;line-height:1.8;color:#f1f3f4">Yth. Pengguna Dirac Group,</p>'
    + '<p style="margin:0 0 18px;font-size:15px;line-height:1.8;color:#f1f3f4">Permintaan pemulihan Passkey Anda telah diterima dan paket recovery terenkripsi sudah disiapkan oleh sistem Dirac Group.</p>'
    + '<p style="margin:0 0 18px;font-size:15px;line-height:1.8;color:#f1f3f4">Silakan buka link resmi berikut untuk mengambil vault recovery. Proses decrypt tetap dilakukan secara lokal di browser dan membutuhkan Secret Email, Secret Website, serta material password terbaru akun Anda.</p>'
    + '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;margin:20px 0 24px;background:#202124;border:1px solid #b8c3d9">'
    + '<tr><td style="padding:13px 14px;border-bottom:1px solid #b8c3d9;color:#d7dbe3;font-size:13px">Request ID</td><td style="padding:13px 14px;border-bottom:1px solid #b8c3d9;color:#ffffff;font-size:13px;font-weight:700;text-align:right;word-break:break-all">' + requestId + '</td></tr>'
    + '<tr><td style="padding:13px 14px;color:#d7dbe3;font-size:13px">Berlaku sampai</td><td style="padding:13px 14px;color:#ffffff;font-size:13px;font-weight:700;text-align:right;word-break:break-all">' + expiresAt + '</td></tr>'
    + '</table>'
    + '<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:6px 0 24px"><tr><td bgcolor="#6f8df7" style="border-radius:9px">'
    + '<a href="' + recoveryLink + '" style="display:inline-block;padding:13px 18px;font-size:14px;font-weight:700;color:#ffffff;text-decoration:none;border-radius:9px">Buka Recovery Resmi</a>'
    + '</td></tr></table>'
    + '<p style="margin:0 0 8px;font-size:14px;line-height:1.6;color:#f1f3f4;font-weight:700;letter-spacing:.2px">SECRET_EMAIL_100_CHAR</p>'
    + '<div style="font-family:Consolas,Menlo,Monaco,monospace;font-size:12px;line-height:1.7;color:#f1f5ff;background:#202124;border:1px solid #b8c3d9;border-radius:10px;padding:14px;word-break:break-all;white-space:pre-wrap">' + emailSecret + '</div>'
    + '<div style="margin:20px 0 0;padding:15px 16px;background:#202124;border-left:4px solid #b8c3d9;color:#f1f3f4;font-size:13px;line-height:1.7">'
    + '<b style="color:#ffffff">Petunjuk singkat:</b><br>'
    + '1. Buka link recovery resmi di atas.<br>'
    + '2. Setelah vault diterima, halaman akan meminta decrypt lokal/offline.<br>'
    + '3. Masukkan material password terbaru, Secret Email, dan Secret Website sesuai instruksi sistem.'
    + '</div>'
    + '<p style="margin:22px 0 0;font-size:13px;line-height:1.7;color:#f1f3f4">Jangan membagikan link recovery, Secret Email, Secret Website, atau hasil decrypt kepada pihak mana pun. Jika Anda tidak meminta pemulihan ini, abaikan email ini dan segera hubungi bantuan resmi Dirac Group.</p>'
    + '<p style="margin:24px 0 0;font-size:14px;line-height:1.8;color:#f1f3f4">Terima kasih,<br><b>Dirac Group</b></p>'
    + '</td></tr>'
    + '<tr><td style="padding:16px 28px 22px;background:#202124;color:#f1f3f4;font-size:12px;line-height:1.7;border-top:1px solid #b8c3d9">'
    + '(Email ini dibuat otomatis oleh sistem, mohon untuk tidak dibalas.)<br>Dirac Group Secure Recovery • Dirac Group'
    + '</td></tr>'
    + '</table>'
    + '</td></tr></table>'
    + '</body></html>';
}

/* source 10181-10197 */
function customerSecurityLostPasskeyOfficialEmailLinkV187(context = {}) {
  const raw = String(context.recoveryLink || '').trim();
  try {
    const url = new URL(raw);
    const official = new URL(customerSecurityLostPasskeyOfficialBaseUrlV157());
    const params = new URLSearchParams(String(url.hash || '').replace(/^#/, ''));
    const requestId = String(params.get('rid') || '');
    const linkToken = String(params.get('token') || '');
    const keys = Array.from(params.keys());
    if (url.protocol !== 'https:' || url.origin !== official.origin || url.pathname !== '/lost-passkey.html' || url.search) return '';
    if (keys.length !== 2 || keys.some((key) => key !== 'rid' && key !== 'token')) return '';
    if (!customerSecurityNormalizeLostPasskeyRequestId(requestId) || !customerSecurityLostPasskeyLinkTokenShapeV162(linkToken)) return '';
    return official.origin + '/lost-passkey.html#rid=' + encodeURIComponent(requestId) + '&token=' + encodeURIComponent(linkToken);
  } catch (_) {
    return '';
  }
}

/* source 10199-10295 */
async function customerSecuritySendLostPasskeyRecoveryLinkEmailV157(to, context = {}) {
  const email = normalizeAuthEmail(to);
  if (!isValidAuthEmail(email)) return { ok: false, status: 400, code: 'RECOVERY_EMAIL_INVALID', message: 'Email resmi customer tidak valid.' };
  const recoveryLink = customerSecurityLostPasskeyOfficialEmailLinkV187(context);
  if (!recoveryLink) return { ok: false, status: 500, code: 'RECOVERY_EMAIL_LINK_INVALID', message: 'Link recovery resmi tidak valid.' };
  const emailContext = Object.assign({}, context, { recoveryLink });
  const from = String(process.env.DIRAC_RECOVERY_EMAIL_FROM || process.env.DIRAC_EMAIL_FROM || process.env.RESEND_FROM || 'Dirac Secure <no-reply@diracgroup.store>').trim();
  const subject = 'DiracGroup Secure Recovery - Link Pemulihan Passkey';
  const text = [
    'Link recovery Passkey resmi sudah dibuat.',
    'Request ID: ' + String(context.requestId || ''),
    'Berlaku sampai: ' + String(context.expiresAt || ''),
    'Link resmi: ' + recoveryLink,
    'SECRET_EMAIL_100_CHAR: ' + String(context.emailSecret || ''),
    'Jangan bagikan email secret, link, atau isi pesan ini kepada pihak lain. Website secret hanya tampil di website yang masih login.'
  ].join('\n\n');
  const html = customerSecurityLostPasskeyRecoveryLinkEmailHtmlV157(emailContext);

  if (customerSecurityRecoverySmtpConfig()) {
    const config = customerSecurityRecoverySmtpConfig();
    const fromEmail = customerSecurityRecoveryEmailAddress(from);
    if (!isValidAuthEmail(fromEmail)) return { ok: false, status: 503, code: 'RECOVERY_SMTP_FROM_INVALID', message: 'Email pengirim recovery tidak valid.' };
    const boundary = 'dirac-recovery-link-' + crypto.randomBytes(18).toString('hex');
    const mime = [
      'From: ' + from,
      'To: ' + email,
      'Subject: ' + customerSecurityRecoveryMimeHeader(subject),
      'MIME-Version: 1.0',
      'Content-Type: multipart/alternative; boundary="' + boundary + '"',
      '',
      '--' + boundary,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      customerSecurityRecoveryBase64Lines(Buffer.from(text, 'utf8')),
      '--' + boundary,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      customerSecurityRecoveryBase64Lines(Buffer.from(html, 'utf8')),
      '--' + boundary + '--',
      ''
    ].join('\r\n');
    let socket = null;
    try {
      const tls = require('tls');
      socket = tls.connect({ host: config.host, port: config.port, servername: config.host, timeout: 20_000 });
      await customerSecuritySmtpCommand(socket, '', 220);
      await customerSecuritySmtpCommand(socket, 'EHLO diracgroup.store', 250);
      const auth = Buffer.from('\u0000' + config.user + '\u0000' + config.pass, 'utf8').toString('base64');
      await customerSecuritySmtpCommand(socket, 'AUTH PLAIN ' + auth, 235);
      await customerSecuritySmtpCommand(socket, 'MAIL FROM:<' + fromEmail + '>', 250);
      await customerSecuritySmtpCommand(socket, 'RCPT TO:<' + email + '>', [250, 251]);
      await customerSecuritySmtpCommand(socket, 'DATA', 354);
      await customerSecuritySmtpCommand(socket, customerSecurityRecoveryDotStuff(mime) + '\r\n.', 250);
      await customerSecuritySmtpCommand(socket, 'QUIT', [221, 250]);
      return { ok: true, provider: 'smtp' };
    } catch (_) {
      return { ok: false, status: 502, code: 'RECOVERY_SMTP_DELIVERY_FAILED', message: 'Gagal mengirim link recovery lewat SMTP.' };
    } finally {
      try { if (socket) socket.end(); } catch (_) {}
    }
  }

  if (process.env.RESEND_API_KEY) {
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to: email, subject, text, html })
      });
      if (response.ok) return { ok: true, provider: 'resend' };
      return { ok: false, status: 502, code: 'RESEND_RECOVERY_DELIVERY_FAILED', message: 'Gagal mengirim link recovery dari Resend.' };
    } catch (_) {
      return { ok: false, status: 502, code: 'RESEND_RECOVERY_DELIVERY_FAILED', message: 'Gagal menghubungi layanan email recovery.' };
    }
  }

  if (process.env.BREVO_API_KEY) {
    try {
      const senderEmail = String(process.env.BREVO_SENDER_EMAIL || process.env.DIRAC_RECOVERY_SENDER_EMAIL || '').trim();
      const senderName = String(process.env.BREVO_SENDER_NAME || 'Dirac Secure').trim();
      if (!senderEmail) return { ok: false, status: 503, code: 'BREVO_SENDER_MISSING', message: 'BREVO_SENDER_EMAIL belum diatur.' };
      const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ sender: { name: senderName, email: senderEmail }, to: [{ email }], subject, htmlContent: html, textContent: text })
      });
      if (response.ok) return { ok: true, provider: 'brevo' };
      return { ok: false, status: 502, code: 'BREVO_RECOVERY_DELIVERY_FAILED', message: 'Gagal mengirim link recovery dari Brevo.' };
    } catch (_) {
      return { ok: false, status: 502, code: 'BREVO_RECOVERY_DELIVERY_FAILED', message: 'Gagal menghubungi layanan email recovery.' };
    }
  }

  return { ok: false, status: 503, code: 'RECOVERY_EMAIL_PROVIDER_NOT_CONFIGURED', message: 'Provider email recovery belum dikonfigurasi.' };
}

/* source 10316-10469 */
async function customerSecurityGenerateRecoveryCodesViaWorker(req, res, action, access, owner, activePasskeys, bindings, workerOptions = {}) {
  // Vercel 2 is a receiver-only recovery worker. Keep the inherited sender
  // implementation unreachable even if a future configuration is incorrect.
  return res.status(403).json({
    ok: false,
    code: 'RECOVERY_WORKER_SERVER2_OUTBOUND_FORBIDDEN',
    message: 'Recovery worker Vercel 2 tidak diizinkan mengirim payload recovery.'
  });

  const workerEnvDiagnostics = customerSecurityRecoveryWorkerMainEnvDiagnostics();
  if (!workerEnvDiagnostics.ok) {
    try { console.error('[recovery-worker-main-env-invalid]', JSON.stringify(workerEnvDiagnostics)); } catch (_) {}
    return res.status(503).json({
      ok: false,
      code: 'RECOVERY_WORKER_ENV_INVALID',
      message: 'Konfigurasi recovery worker di Vercel 1 belum valid.',
      worker_env: workerEnvDiagnostics
    });
  }

  const workerUrl = customerSecurityRecoveryWorkerUrl();
  const secret = customerSecurityRecoveryWorkerSecret();
  const caller = customerSecurityRecoveryWorkerCaller();
  if (!workerUrl || !secret || !caller) {
    return res.status(503).json({
      ok: false,
      code: 'RECOVERY_WORKER_REQUIRED',
      message: 'Recovery worker belum dikonfigurasi. Generate recovery tidak dijalankan di backend utama.'
    });
  }

  const payload = {
    action: DIRAC_RECOVERY_WORKER_ACTION,
    worker_action: DIRAC_RECOVERY_WORKER_TASK_GENERATE,
    caller_id: caller,
    nonce: crypto.randomBytes(32).toString('base64url'),
    auth_user_id: owner.authUserId,
    customer_id: owner.customerId,
    email: owner.email,
    email_binding_hash: bindings.emailBindingHash,
    customer_binding_hash: bindings.customerBindingHash,
    auth_user_binding_hash: bindings.authUserBindingHash,
    device_binding_hash: bindings.deviceBindingHash,
    session_hash: bindings.sessionHash || customerSecurityLostPasskeyHashHex('session-binding', String(access && access.sessionId || 'server1-session')),
    ip_hash: bindings.ipHash,
    user_agent_hash: bindings.userAgentHash,
    active_passkey_count: Math.max(0, activePasskeys.length),
    requested_at: diracNowIso(),
    password_latest_material: String(workerOptions.passwordLatestMaterial || workerOptions.password_latest_material || workerOptions.accountPassword || workerOptions.account_password || '')
  };
  const canonical = customerSecurityLostPasskeyCanonical(payload);
  const timestamp = String(Date.now());
  const signature = customerSecurityRecoveryWorkerSign(caller, timestamp, canonical);
  const target = new URL(workerUrl);
  target.searchParams.set('action', DIRAC_RECOVERY_WORKER_ACTION);
  const timeoutMs = Math.max(5000, Math.min(290000, Number(process.env.DIRAC_RECOVERY_WORKER_TIMEOUT_MS || 280000)));
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  const workerDebugEnabled = String(process.env.DIRAC_RECOVERY_WORKER_DEBUG || '').trim().toLowerCase() === 'true';

  try {
    const response = await fetch(target.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Dirac-Worker-Caller': caller,
        'X-Dirac-Worker-Timestamp': timestamp,
        'X-Dirac-Worker-Signature': signature
      },
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined
    });
    const workerResponseText = await diracRecoveryReadResponseLimitedV201(response, 2 * 1024 * 1024).catch(() => '');
    let data = {};
    try { data = workerResponseText ? JSON.parse(workerResponseText) : {}; } catch (_) { data = {}; }
    if (!response.ok || !data || data.ok !== true) {
      const workerFailureBody = {
        ok: false,
        code: data && data.code || 'RECOVERY_WORKER_FAILED',
        message: data && data.message || 'Recovery worker belum dapat memproses permintaan.'
      };
      try {
        console.error('[recovery-worker-response-failed]', JSON.stringify({
          status: response.status,
          statusText: response.statusText,
          code: workerFailureBody.code,
          message: String(workerFailureBody.message || '').slice(0, 200),
          workerHost: target.hostname,
          workerPath: target.pathname
        }));
      } catch (_) {}
      if (workerDebugEnabled) {
        workerFailureBody.worker_status = response.status;
        workerFailureBody.worker_status_text = String(response.statusText || '').slice(0, 80);
        workerFailureBody.worker_body_preview = String(workerResponseText || '').replace(/[<>]/g, '').slice(0, 800);
      }
      return res.status(response.status || data.status || 502).json(workerFailureBody);
    }
    const workerSuccessPayload = customerSecurityLostPasskeyGenerateSuccessPayloadV182({
      requestId: data.request_id,
      expiresAt: data.expires_at,
      websiteRecoveryCode: data.website_recovery_code,
      message: data.message,
      time: data.time
    });
    if (!workerSuccessPayload) {
      try {
        console.error('[recovery-worker-dual-delivery-contract-invalid]', JSON.stringify({
          patch: DIRAC_RECOVERY_DUAL_DELIVERY_PATCH_V182,
          workerHost: target.hostname,
          workerPath: target.pathname,
          request_id_present: Boolean(data && data.request_id),
          expires_at_present: Boolean(data && data.expires_at),
          website_recovery_code_length: typeof (data && data.website_recovery_code) === 'string' ? data.website_recovery_code.length : -1
        }));
      } catch (_) {}
      return res.status(502).json({
        ok: false,
        code: 'RECOVERY_DUAL_DELIVERY_CONTRACT_INVALID',
        message: 'Permintaan recovery ditolak karena email dan kode website 100 karakter tidak lengkap.'
      });
    }
    return res.status(200).json(workerSuccessPayload);
  } catch (error) {
    const workerErrorName = String(error && error.name || '').slice(0, 80);
    const workerErrorMessage = customerSecurityLostPasskeyDiagnosticCodeV210(error && (error.code || error.name) || 'recovery_worker_error', 120);
    try {
      console.error('[recovery-worker-unreachable]', JSON.stringify({
        name: workerErrorName,
        message: workerErrorMessage,
        workerHost: target.hostname,
        workerPath: target.pathname,
        timeoutMs
      }));
    } catch (_) {}
    const unreachableBody = {
      ok: false,
      code: 'RECOVERY_WORKER_UNREACHABLE',
      message: 'Recovery worker belum bisa dihubungi.'
    };
    if (workerDebugEnabled) {
      unreachableBody.worker_error_name = workerErrorName;
      unreachableBody.worker_error_message = workerErrorMessage;
      unreachableBody.worker_host = target.hostname;
      unreachableBody.worker_path = target.pathname;
      unreachableBody.worker_timeout_ms = timeoutMs;
    }
    return res.status(502).json(unreachableBody);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/* source 10471-10784 */
async function customerSecurityGenerateRecoveryCodes(req, res, action, override = null) {
  const localWorker = Boolean(override && override.localWorker === true);
  const access = localWorker && override && override.access
    ? override.access
    : await customerSecurityRequireAccess(req, res, { action, requireMfa: false, rateLimit: { limit: 2, windowMs: 10 * 60_000 } });
  if (!access) return;

  const requestBody = localWorker ? {} : await readBody(req);
  const owner = localWorker && override && override.owner
    ? override.owner
    : await customerSecurityResolveLostPasskeyOwner(access);
  if (!owner.ok) return res.status(owner.status || 403).json({ ok: false, message: owner.message || 'Recovery passkey tidak dapat dibuat.' });

  const passwordMaterial = localWorker
    ? customerSecurityExtractPasswordMaterialV157({
        password_latest_material: override && (override.passwordLatestMaterial || override.password_latest_material || ''),
        password_latest_proof: override && (override.passwordLatestProof || override.password_latest_proof || ''),
        account_password: override && override.accountPassword || ''
      })
    : customerSecurityExtractPasswordMaterialV157(requestBody);
  if (!passwordMaterial) {
    return res.status(400).json({
      ok: false,
      code: 'PASSWORD_LATEST_MATERIAL_REQUIRED',
      message: 'Material password terbaru wajib ada.'
    });
  }

  const verifiedPassword = await customerSecurityVerifyAccountPasswordForPdfV156(owner.email, passwordMaterial);
  if (!verifiedPassword.ok) {
    await customerSecurityRegisterFailedVerification(req, action, 'recovery_account_password_invalid', access.customerId);
    return res.status(403).json({ ok: false, code: 'ACCOUNT_PASSWORD_INVALID', message: 'Password akun belum sesuai.' });
  }

  const activePasskeys = localWorker && override && Array.isArray(override.activePasskeys)
    ? override.activePasskeys
    : await customerSecurityLostPasskeyActivePasskeys(owner);
  if (!activePasskeys.length) {
    return res.status(409).json({ ok: false, code: 'ACTIVE_PASSKEY_NOT_FOUND', message: 'Passkey aktif untuk akun ini belum ditemukan. Gunakan flow pembuatan Passkey normal.' });
  }

  const bindings = localWorker && override && override.bindings
    ? override.bindings
    : customerSecurityLostPasskeyBindings(req, owner);

  if (!localWorker) {
    return customerSecurityGenerateRecoveryCodesViaWorker(req, res, action, access, owner, activePasskeys, bindings, { password_latest_material: passwordMaterial });
  }

  const vaultSecrets = customerSecurityLostPasskeyRequireVaultSecretsV157();
  if (!vaultSecrets.ok) {
    return res.status(503).json({ ok: false, code: vaultSecrets.code, message: vaultSecrets.message });
  }

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + LOST_PASSKEY_RECOVERY_TTL_MINUTES_V157 * 60 * 1000).toISOString();
  const requestId = customerSecurityLostPasskeyRequestId();
  const linkToken = crypto.randomBytes(LOST_PASSKEY_LINK_TOKEN_BYTES_V157).toString('base64url');
  const emailSecret100 = customerSecurityLostPasskeyExactSecret100V182(
    customerSecurityLostPasskeyRandomTextV157(LOST_PASSKEY_SECRET_100_CHAR_LENGTH_V157)
  );
  const websiteSecret100 = customerSecurityLostPasskeyExactSecret100V182(
    customerSecurityLostPasskeyRandomTextV157(LOST_PASSKEY_SECRET_100_CHAR_LENGTH_V157)
  );
  if (!emailSecret100 || !websiteSecret100) {
    return res.status(500).json({
      ok: false,
      code: 'RECOVERY_DUAL_DELIVERY_MATERIAL_INVALID',
      message: 'Permintaan recovery ditolak karena material email dan kode website 100 karakter tidak lengkap.'
    });
  }
  const recoveryCode = customerSecurityGenerateLostPasskeyRecoveryCode();
  let recoveryCryptoV2;
  try {
    const requiredArgon2Params = customerSecurityLostPasskeyArgon2ParamsV157(64);
    recoveryCryptoV2 = await DIRAC_RECOVERY_CRYPTO_V2.createVault({
      requestId,
      expiresAt,
      nowIso,
      officialOrigin: customerSecurityLostPasskeyOfficialBaseUrlV157(),
      passwordMaterial,
      emailSecret: emailSecret100,
      websiteSecret: websiteSecret100,
      recoveryCode,
      argon2Params: requiredArgon2Params,
      argon2RawFn: customerSecurityLostPasskeyArgon2Raw,
      vaultMaterialFn: (passwordValue, emailValue, websiteValue, saltValue, vaultIdValue) => Buffer.from(DIRAC_RECOVERY_CRYPTO_V2.jcs({
        version: DIRAC_RECOVERY_CRYPTO_V2.VERSION,
        password: customerSecurityLostPasskeyNormalizePasswordV157(passwordValue),
        email_secret: customerSecurityLostPasskeyNormalizeSecretV157(emailValue),
        website_secret: customerSecurityLostPasskeyNormalizeSecretV157(websiteValue),
        salt: DIRAC_RECOVERY_CRYPTO_V2.b64u(saltValue),
        vault_id: DIRAC_RECOVERY_CRYPTO_V2.b64u(vaultIdValue)
      }), 'utf8'),
      extraEntropyHashFn: (value) => customerSecurityLostPasskeyHmacHexV157(vaultSecrets.rootSecret, 'extra_nonce_entropy_v2', value),
      metadataSignatureFn: (value) => customerSecurityLostPasskeyHmacHexV157(vaultSecrets.rootSecret, 'metadata_signature_v2', DIRAC_RECOVERY_CRYPTO_V2.jcs(value))
    });
  } catch (error) {
    try {
      console.error('[dirac-recovery-crypto-v2-create-failed]', JSON.stringify({
        code: String(error && error.code || 'RECOVERY_CRYPTO_V2_CREATE_FAILED').slice(0, 100),
        request_id: requestId
      }));
    } catch (_) {}
    return res.status(503).json({
      ok: false,
      code: String(error && error.code || 'RECOVERY_CRYPTO_V2_CREATE_FAILED'),
      message: 'Layanan recovery maksimum belum siap.'
    });
  }
  const vaultSalt = recoveryCryptoV2.compatibility.vaultSalt;
  const vaultId = recoveryCryptoV2.compatibility.vaultId;
  const extraNonceEntropy = recoveryCryptoV2.compatibility.extraNonceEntropy;
  const argon2Params = recoveryCryptoV2.argon2Params;
  const metadataForAad = recoveryCryptoV2.metadataForAad;
  const aad = recoveryCryptoV2.aad;
  const encrypted = recoveryCryptoV2.compatibility.encrypted;

  const linkTokenSalt = crypto.randomBytes(LOST_PASSKEY_RECOVERY_SALT_BYTES_V157);
  const emailSecretSalt = crypto.randomBytes(LOST_PASSKEY_RECOVERY_SALT_BYTES_V157);
  const websiteSecretSalt = crypto.randomBytes(LOST_PASSKEY_RECOVERY_SALT_BYTES_V157);
  const recoveryCodeSalt = crypto.randomBytes(LOST_PASSKEY_RECOVERY_SALT_BYTES_V157);
  const bindingSalt = crypto.randomBytes(LOST_PASSKEY_RECOVERY_SALT_BYTES_V157);

  const bindingsCanonical = customerSecurityLostPasskeyCanonical(bindings);
  const linkTokenHash = await customerSecurityLostPasskeyArgon2EncodedHashLinkOpenV171('link_token', linkToken, linkTokenSalt, vaultSecrets.pepper, vaultSecrets.rootSecret);
  const linkTokenArgon2Params = customerSecurityLostPasskeyArgon2EncodedParamsV171(linkTokenHash) || customerSecurityLostPasskeyLinkOpenArgon2ParamsV171(64);
  const emailSecretHash = await customerSecurityLostPasskeyArgon2EncodedHashV157('email_secret', emailSecret100, emailSecretSalt, vaultSecrets.pepper, vaultSecrets.rootSecret);
  const websiteSecretHash = await customerSecurityLostPasskeyArgon2EncodedHashV157('website_secret', websiteSecret100, websiteSecretSalt, vaultSecrets.pepper, vaultSecrets.rootSecret);
  const recoveryCodeHash = await customerSecurityLostPasskeyArgon2EncodedHashV157('recovery_code', recoveryCode, recoveryCodeSalt, vaultSecrets.pepper, vaultSecrets.rootSecret);
  const bindingHashCommitment = await customerSecurityLostPasskeyArgon2EncodedHashV157('binding', bindingsCanonical, bindingSalt, vaultSecrets.pepper, vaultSecrets.rootSecret);
  if (override && override.argonQueueTicket && !customerSecurityLostPasskeyQueueLeaseHealthyV188(override.argonQueueTicket)) {
    return res.status(503).json({ ok: false, code: 'RECOVERY_ARGON2_LEASE_LOST', message: 'Antrean keamanan recovery perlu diulang.' });
  }

  // Recovery email opens the static recovery page; the page then validates the token through Central Guard.
  const recoveryLink = customerSecurityLostPasskeyOfficialBaseUrlV157()
    + '/lost-passkey.html#rid=' + encodeURIComponent(requestId)
    + '&token=' + encodeURIComponent(linkToken);
  const vaultBundle = recoveryCryptoV2.vaultBundle;
  const vaultBundleSha256 = customerSecurityLostPasskeySha256B64(Buffer.from(customerSecurityLostPasskeyCanonical(vaultBundle), 'utf8'));
  const aadHash = customerSecurityLostPasskeySha256B64(aad);
  const insertBody = [{
    request_id: requestId,
    customer_id: owner.customerId,
    auth_user_id: owner.authUserId,
    email_hash: bindings.emailBindingHash,
    customer_binding_hash: bindings.customerBindingHash,
    auth_user_binding_hash: bindings.authUserBindingHash,
    device_binding_hash: bindings.deviceBindingHash,
    ip_hash: bindings.ipHash,
    user_agent_hash: bindings.userAgentHash,
    recovery_code_hash: recoveryCodeHash,
    encrypted_file_key_text: vaultBundle.ciphertext,
    file_key_wrap_nonce: vaultBundle.aes_nonce,
    file_key_wrap_tag: vaultBundle.auth_tag,
    salt: vaultBundle.salt,
    owner_key_salt: customerSecurityLostPasskeyB64(recoveryCodeSalt),
    file_sha256: vaultBundleSha256,
    aad_hash: aadHash,
    server_signature: vaultBundle.metadata_signature,
    old_passkey_ids: activePasskeys.map((row) => row.id).filter(Boolean),
    status: 'pending',
    attempt_count: 0,
    created_at: nowIso,
    sent_at: null,
    expires_at: expiresAt,
    used_at: null,
    revoked_at: null,
    metadata: {
      source: 'lost_passkey_recovery',
      patch: DIRAC_RECOVERY_CRYPTO_V2.VERSION,
      delivery: 'official_recovery_html_link',
      file_format: 'aes256gcm_dek_a256kw_hybrid_pq_v2',
      html_template: 'deploy_once_on_server2_later',
      password_formula: 'password_plus_email100_plus_website100_to_argon2id_hkdf_sha512_kek',
      official_recovery_link_hash: customerSecurityLostPasskeyHmacHexV157(vaultSecrets.rootSecret, 'official_recovery_link', recoveryLink),
      link_token_hash: linkTokenHash,
      link_token_argon2id_params: linkTokenArgon2Params,
      link_token_argon2id_cost_source: 'DIRAC_LOST_PASSKEY_LINK_OPEN_ARGON2_*',
      email_secret_hash: emailSecretHash,
      website_secret_hash: websiteSecretHash,
      recovery_code_hash_label: 'recovery_code',
      binding_hash_commitment: bindingHashCommitment,
      binding_hashes: bindings,
      hash_salts: {
        link_token: customerSecurityLostPasskeyB64(linkTokenSalt),
        email_secret: customerSecurityLostPasskeyB64(emailSecretSalt),
        website_secret: customerSecurityLostPasskeyB64(websiteSecretSalt),
        recovery_code: customerSecurityLostPasskeyB64(recoveryCodeSalt),
        binding: customerSecurityLostPasskeyB64(bindingSalt)
      },
      vault_bundle: vaultBundle,
      crypto_profile: 'dirac-recovery-v2-max-2026',
      legacy_fallback_allowed: false,
      argon2id_params: argon2Params,
      root_secret_version: vaultSecrets.rootSecretVersion,
      passkey_count: activePasskeys.length,
      link_token_bits: LOST_PASSKEY_LINK_TOKEN_BYTES_V157 * 8,
      secret_email_length: LOST_PASSKEY_SECRET_100_CHAR_LENGTH_V157,
      secret_website_length: LOST_PASSKEY_SECRET_100_CHAR_LENGTH_V157,
      recovery_code_length: LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157,
      salt_bytes: LOST_PASSKEY_RECOVERY_SALT_BYTES_V157,
      vault_id_bytes: LOST_PASSKEY_RECOVERY_VAULT_ID_BYTES_V157,
      extra_nonce_entropy_bytes: LOST_PASSKEY_RECOVERY_EXTRA_NONCE_BYTES_V157,
      aes_gcm_nonce_bytes: 12,
      expires_minutes: LOST_PASSKEY_RECOVERY_TTL_MINUTES_V157
    }
  }];

  const created = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE, { method: 'POST', auth: 'service', prefer: 'return=representation', body: insertBody });
  if (!created.ok) {
    return res.status(created.status || 500).json({ ok: false, message: 'Gagal menyimpan lost passkey recovery request.' });
  }

  const successPayload = customerSecurityLostPasskeyGenerateSuccessPayloadV182({
    requestId,
    expiresAt,
    websiteRecoveryCode: websiteSecret100,
    message: 'Link recovery resmi sudah dikirim ke email resmi akun.',
    time: nowIso
  });
  if (!successPayload) {
    await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
      method: 'PATCH',
      auth: 'service',
      body: {
        status: 'revoked',
        revoked_at: diracNowIso(),
        metadata: {
          source: 'lost_passkey_recovery',
          patch: DIRAC_RECOVERY_DUAL_DELIVERY_PATCH_V182,
          dual_delivery_contract_invalid: true,
          dual_delivery_contract_invalid_at: diracNowIso()
        }
      }
    }).catch(() => null);
    return res.status(500).json({
      ok: false,
      code: 'RECOVERY_DUAL_DELIVERY_CONTRACT_INVALID',
      message: 'Permintaan recovery ditolak karena email dan kode website 100 karakter tidak lengkap.'
    });
  }

  const deliveryPrepared = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: { sent_at: nowIso }
  });
  if (!deliveryPrepared.ok) {
    await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
      method: 'PATCH',
      auth: 'service',
      body: {
        status: 'revoked',
        sent_at: null,
        revoked_at: diracNowIso(),
        metadata: {
          source: 'lost_passkey_recovery',
          patch: DIRAC_RECOVERY_DUAL_DELIVERY_PATCH_V182,
          delivery_precommit_failed: true,
          delivery_precommit_failed_at: diracNowIso()
        }
      }
    }).catch(() => null);
    return res.status(deliveryPrepared.status || 500).json({
      ok: false,
      code: 'RECOVERY_DUAL_DELIVERY_PRECOMMIT_FAILED',
      message: 'Permintaan recovery ditolak sebelum email dikirim karena kode website belum dapat dikomit.'
    });
  }

  const sent = await customerSecuritySendLostPasskeyRecoveryLinkEmailV157(owner.email, {
    requestId,
    expiresAt,
    recoveryLink,
    emailSecret: emailSecret100
  });
  if (!sent.ok) {
    await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
      method: 'PATCH',
      auth: 'service',
      body: {
        status: 'revoked',
        sent_at: null,
        revoked_at: diracNowIso(),
        metadata: {
          source: 'lost_passkey_recovery',
          patch: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157,
          delivery: 'official_recovery_html_link',
          delivery_failed: true,
          delivery_failed_at: diracNowIso()
        }
      }
    }).catch(() => null);
    return res.status(sent.status || 503).json({ ok: false, code: sent.code || 'RECOVERY_EMAIL_SEND_FAILED', message: sent.message || 'Link recovery belum bisa dikirim ke email resmi.' });
  }

  const committedResponse = res.status(200).json(successPayload);
  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'lost_passkey_recovery_link_sent',
    status: 'success',
    risk_level: 'high',
    description: 'Link recovery passkey resmi dan email secret dikirim ke email resmi customer.',
    req,
    metadata: { action, request_id: requestId, vault_bundle_sha256: vaultBundleSha256, delivery_provider: sent.provider || null, delivery: 'official_recovery_html_link' }
  }).catch(() => null);

  return committedResponse;
}

/* source 15089-15095 */
async function diracPasskeyA2FFetchCustomerById(customerId) {
  const cleanId = String(customerId || '').trim();
  if (!customerSecurityLooksLikeUuid(cleanId)) return { ok: false, status: 400, data: [] };
  const select = ['id', 'email', 'name', 'phone'].join(',');
  const path = '/rest/v1/customers?select=' + encodeURIComponent(select) + '&id=eq.' + encodeURIComponent(cleanId) + '&limit=1';
  return supabaseFetch(path, { method: 'GET', auth: 'service' });
}

/* source 15143-15155 */
function diracPasskeyA2FOwnerMatches(row, owner) {
  if (!row || !owner) return false;
  const rowCustomer = String(row.user_id || '').trim();
  const rowEmail = normalizeAuthEmail(row.email || '');
  const ownerCustomer = String(owner.customerId || '').trim();
  const ownerEmail = normalizeAuthEmail(owner.email || '');
  if (rowCustomer && rowEmail && ownerCustomer && ownerEmail) {
    return rowCustomer === ownerCustomer && rowEmail === ownerEmail;
  }
  if (rowCustomer && ownerCustomer) return rowCustomer === ownerCustomer;
  if (rowEmail && ownerEmail) return rowEmail === ownerEmail;
  return false;
}

/* source 15157-15188 */
async function diracPasskeyA2FListActivePasskeys(owner) {
  const select = ['id', 'user_id', 'email', 'credential_id', 'credential_json', 'transports', 'sign_count', 'is_active', 'created_at', 'last_used_at'].join(',');
  const seen = new Set();
  const rows = [];
  const fetchRows = async (filter) => {
    const path = '/rest/v1/domain_passkeys?select=' + encodeURIComponent(select) + '&is_active=eq.true&' + filter + '&order=created_at.desc&limit=20';
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok) return;
    for (const row of (Array.isArray(result.data) ? result.data : [])) {
      const key = String(row && (row.id || row.credential_id) || '');
      if (!key || seen.has(key) || !diracPasskeyA2FOwnerMatches(row, owner)) continue;
      seen.add(key);
      rows.push(row);
    }
  };

  if (owner && owner.customerId && customerSecurityLooksLikeUuid(owner.customerId)) {
    await fetchRows('user_id=eq.' + encodeURIComponent(owner.customerId));
  }

  let isRecoveryWorkerContext = false;
  try {
    const ctx = typeof diracCentralCurrentContextV149 === 'function' ? diracCentralCurrentContextV149() : null;
    isRecoveryWorkerContext = Boolean(ctx && ctx.action === DIRAC_RECOVERY_WORKER_ACTION);
  } catch (_) {}

  if (!isRecoveryWorkerContext && owner && owner.email && isValidAuthEmail(owner.email)) {
    await fetchRows('email=eq.' + encodeURIComponent(owner.email));
  }

  return rows;
}

/* source 15735-15753 */
function diracUniversalPesananPaymentNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    create_payment: 'create_payment',
    create_payment_order: 'create_payment',
    pay_order: 'create_payment',
    order_payment: 'create_payment',
    bayar_pesanan: 'create_payment',
    checkout_payment: 'create_payment',
    my_orders: 'my_orders',
    pesanan: 'my_orders',
    pesanan_saya: 'my_orders',
    customer_orders: 'my_orders',
    orders_saya: 'my_orders',
    my_invoices: 'my_orders',
    invoice_saya: 'my_orders'
  };
  return aliases[clean] || clean;
}

/* source 18835-18880 */
function diracUltraNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    'domain_health': 'domain_health',
    'hostinger_check': 'hostinger_check',
    'domain_hostinger_check': 'hostinger_check',
    'check_domain': 'domain_check',
    'domain_check': 'domain_check',
    'create_order': 'domain_checkout',
    'domain_create_order': 'domain_checkout',
    'domain_checkout': 'domain_checkout',
    'get_orders': 'domain_orders',
    'domain_get_orders': 'domain_orders',
    'domain_orders': 'domain_orders',
    'domain_login': 'domain_login',
    'login_domain': 'domain_login',
    'domain_register': 'domain_register',
    'register_domain': 'domain_register',
    'domain_logout': 'domain_logout',
    'domain_me': 'domain_me',
    'domain_dashboard_me': 'domain_dashboard_me',
    'dashboard_me': 'domain_dashboard_me',
    'dashboard_summary': 'domain_dashboard_me',
    'customer_summary': 'customer_security_overview',
    'domain_mfa_status': 'domain_mfa_status',
    'dashboard_mfa_status': 'domain_mfa_status',
    'create_payment': 'create_payment',
    'pay_order': 'create_payment',
    'order_payment': 'create_payment',
    'midtrans_webhook': 'midtrans_webhook',
    'midtrans_notification': 'midtrans_webhook',
    'midtrans_callback': 'midtrans_webhook',
    'payment_webhook': 'midtrans_webhook',
    'payment_callback': 'midtrans_webhook',
    'midtrans_health': 'midtrans_health',
    'ipaymu_webhook': 'ipaymu_webhook',
    'ipaymu_callback': 'ipaymu_webhook',
    'ipaymu_notification': 'ipaymu_webhook',
    'ipaymu_health': 'ipaymu_health',
    'dirac_mfa_passkey_start': 'dirac_mfa_passkey_start',
    'domain_mfa_passkey_start': 'dirac_mfa_passkey_start',
    'dirac_mfa_passkey_verify': 'dirac_mfa_passkey_verify',
    'domain_mfa_passkey_verify': 'dirac_mfa_passkey_verify'
  };
  return aliases[clean] || clean;
}

/* source 19130-19130 */
const DIRAC_ULTRA_SQLMAP_GUARD_PATCH = 'dirac-ultra-sqlmap-guard-v101';

/* source 19132-19132 */
const DIRAC_ULTRA_SQLMAP_MEMORY_STORE = globalThis.__DIRAC_ULTRA_SQLMAP_MEMORY_STORE__ || new Map();

/* source 19133-19133 */
globalThis.__DIRAC_ULTRA_SQLMAP_MEMORY_STORE__ = DIRAC_ULTRA_SQLMAP_MEMORY_STORE;

/* source 19173-19178 */
function diracV101NormalizeAction(action) {
  try {
    if (typeof diracUltraNormalizeAction === 'function') return diracUltraNormalizeAction(action);
  } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 19372-19374 */
function diracV101SecurityHmacSecret() {
  return diracCentralDeriveSecretV146('v101-security-hmac').toString('base64url');
}

/* source 19376-19382 */
function diracV101Fingerprint(value) {
  const secret = diracV101SecurityHmacSecret();
  const raw = String(value || '');
  if (secret) return crypto.createHmac('sha256', secret).update(raw).digest('hex');
  if (typeof loginSecurityHash === 'function') return loginSecurityHash(raw);
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/* source 19384-19388 */
function diracV101RequestIp(req) {
  try { if (typeof getLoginSecurityIp === 'function') return getLoginSecurityIp(req); } catch (_) {}
  const headers = (req && req.headers) || {};
  return String(headers['x-forwarded-for'] || headers['x-real-ip'] || req && req.socket && req.socket.remoteAddress || 'unknown').split(',')[0].trim() || 'unknown';
}

/* source 19390-19395 */
function diracV101SqlmapSecurityKey(req, action, method) {
  const headers = (req && req.headers) || {};
  const ua = String(headers['user-agent'] || '').slice(0, 240);
  const ip = diracV101RequestIp(req);
  return 'sqlmap-ban:' + diracV101Fingerprint(['v101', method || '', action || '', ip, ua].join('|'));
}

/* source 19414-19441 */
async function diracV101RegisterSqlmapAttack(req, action, method, threat) {
  const key = diracV101SqlmapSecurityKey(req, action, method);
  const now = Date.now();
  const years = Math.max(1, Number(process.env.DIRAC_SQLMAP_BLOCK_YEARS || 10));
  const blockMs = Math.min(years, 25) * 365 * 24 * 60 * 60 * 1000;
  const blockedUntilMs = now + blockMs;
  DIRAC_ULTRA_SQLMAP_MEMORY_STORE.set(key, { blockedUntilMs, updatedAtMs: now });

  if (!LOGIN_SECURITY_PERSIST_TABLE || typeof writePersistentSecurityJson !== 'function') return false;

  const headers = (req && req.headers) || {};
  const record = {
    event_type: 'sqlmap_or_sqli_block',
    patch: DIRAC_ULTRA_SQLMAP_GUARD_PATCH,
    status: 'blocked',
    risk_level: threat && threat.risk || 'critical',
    threat_kind: threat && threat.kind || 'unknown',
    threat_source: threat && threat.source || 'unknown',
    action: String(action || '').slice(0, 80),
    method: String(method || '').toUpperCase(),
    ip_hash: diracV101Fingerprint(diracV101RequestIp(req)),
    user_agent_hash: diracV101Fingerprint(String(headers['user-agent'] || '').slice(0, 240)),
    blockedUntilMs,
    blocked_until_ms: blockedUntilMs,
    updated_at: new Date(now).toISOString()
  };
  return writePersistentSecurityJson(key, record, blockedUntilMs, Math.ceil(blockMs / 1000)).catch(() => false);
}

/* source 19663-19663 */
const DIRAC_GLOBAL_HARD_BAN_STABLE_PATCH_V107 = 'dirac-global-hard-ban-stable-v107';

/* source 19665-19665 */
const DIRAC_GLOBAL_HARD_BAN_STORE_V107 = globalThis.__DIRAC_GLOBAL_HARD_BAN_STORE_V107__ || new Map();

/* source 19666-19666 */
globalThis.__DIRAC_GLOBAL_HARD_BAN_STORE_V107__ = DIRAC_GLOBAL_HARD_BAN_STORE_V107;

/* source 19702-19712 */
try {
  if (typeof diracV101RegisterSqlmapAttack === 'function' && !diracV101RegisterSqlmapAttack.__diracV107StableWrapped) {
    const __diracV107OriginalRegisterSqlmapAttack = diracV101RegisterSqlmapAttack;
    diracV101RegisterSqlmapAttack = async function diracV101RegisterSqlmapAttackV107Stable(req, action, method, threat) {
      const result = await __diracV107OriginalRegisterSqlmapAttack(req, action, method, threat);
      await diracV107RegisterHardBan(req, null, action, method, threat || { detected: true, kind: 'body_sql_injection' }).catch(() => null);
      return result;
    };
    Object.defineProperty(diracV101RegisterSqlmapAttack, '__diracV107StableWrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 19714-19718 */
function diracV107NormalizeAction(action) {
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(action); } catch (_) {}
  try { if (typeof diracV101NormalizeAction === 'function') return diracV101NormalizeAction(action); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 19803-19834 */
async function diracV107CheckActiveBan(req) {
  const now = Date.now();
  const keys = diracV107BuildKeys(req);
  for (const item of keys) {
    const memory = DIRAC_GLOBAL_HARD_BAN_STORE_V107.get(item.key);
    if (memory && Number(memory.blockedUntilMs || 0) > now) {
      return {
        blocked: true,
        keyType: item.type,
        retryAfterSeconds: Math.max(1, Math.ceil((Number(memory.blockedUntilMs) - now) / 1000))
      };
    }
  }

  const rows = await diracV107ReadRows(keys.map((item) => item.key));
  for (const row of rows) {
    const record = row && row.record_json && typeof row.record_json === 'object' ? row.record_json : {};
    // Narrow cleanup for the previous post-handler misclassification only.
    // Real attack bans keep their original reasons and remain fully enforced.
    if (/^recovery_action_http_\d{3}$/.test(String(record.reason || ''))) continue;
    const blockedUntilMs = Number(row && row.blocked_until_ms || 0);
    if (blockedUntilMs > now) {
      return {
        blocked: true,
        keyType: String(row.security_key || '').split(':').slice(0, 2).join(':'),
        retryAfterSeconds: Math.max(1, Math.ceil((blockedUntilMs - now) / 1000))
      };
    }
  }

  return { blocked: false };
}

/* source 19836-19878 */
async function diracV107RegisterHardBan(req, res, action, method, threat) {
  const now = Date.now();
  const blockedUntilMs = now + diracV107BlockYears() * 365 * 24 * 60 * 60 * 1000;
  const expiresAt = new Date(blockedUntilMs).toISOString();
  const keys = diracV107BuildKeys(req);

  // Pasang cookie hard-ban untuk browser yang melakukan attack; membantu tetap blokir bila IP/VPN berubah tetapi cookie masih sama.
  try {
    if (res && typeof res.setHeader === 'function') {
      const cookieValue = diracV107Hmac('cookie|' + String(now) + '|' + crypto.randomBytes(32).toString('base64url')).slice(0, 64);
      const maxAge = Math.max(60, Math.min(Math.floor((blockedUntilMs - now) / 1000), 2147483647));
      res.setHeader('Set-Cookie', 'dirac_global_hard_ban=' + cookieValue + '; Path=/; Max-Age=' + maxAge + '; HttpOnly; Secure; SameSite=Lax');
      keys.push(...diracV107KeysForValue('cookie', 'cookie|' + cookieValue));
    }
  } catch (_) {}

  const safeRecord = {
    type: 'global_hard_ban_v107',
    patch: DIRAC_GLOBAL_HARD_BAN_STABLE_PATCH_V107,
    action: String(action || '').slice(0, 80),
    method: String(method || '').slice(0, 12),
    reason: String(threat && (threat.kind || threat.reason) || 'security_threat').slice(0, 80),
    source: String(threat && threat.source || 'guard').slice(0, 80),
    risk: String(threat && threat.risk || 'critical').slice(0, 40),
    blocked_until_ms: blockedUntilMs,
    created_at: new Date(now).toISOString()
  };

  for (const item of keys) {
    DIRAC_GLOBAL_HARD_BAN_STORE_V107.set(item.key, { blockedUntilMs, updatedAtMs: now, type: item.type });
  }

  const rows = keys.map((item) => ({
    security_key: item.key,
    record_json: { ...safeRecord, key_type: item.type },
    blocked_until_ms: blockedUntilMs,
    updated_at: new Date(now).toISOString(),
    expires_at: expiresAt
  }));

  const write = await diracV107WriteRows(rows);
  return { ok: !!(write && write.ok), wrote: write && write.wrote || 0, total: rows.length, blockedUntilMs };
}

/* source 19880-19899 */
function diracV107BuildKeys(req) {
  const headers = (req && req.headers) || {};
  const keys = [];
  const ip = diracV107Ip(req);
  const ua = String(headers['user-agent'] || headers['User-Agent'] || '').slice(0, 500);
  const acceptLanguage = String(headers['accept-language'] || '').slice(0, 120);
  const accept = String(headers.accept || '').slice(0, 200);
  const platform = String(headers['sec-ch-ua-platform'] || '').slice(0, 80);
  const mobile = String(headers['sec-ch-ua-mobile'] || '').slice(0, 40);
  const cookie = diracV107Cookie(req, 'dirac_global_hard_ban');

  keys.push(...diracV107KeysForValue('ip', 'ip|' + ip));
  if (cookie) keys.push(...diracV107KeysForValue('cookie', 'cookie|' + cookie));
  if (ua) keys.push(...diracV107KeysForValue('ua', 'ua|' + ua));
  if (ua || acceptLanguage || accept || platform || mobile) {
    keys.push(...diracV107KeysForValue('fingerprint', ['fp', ua, acceptLanguage, accept, platform, mobile].join('|')));
  }

  return Array.from(new Map(keys.map((item) => [item.key, item])).values());
}

/* source 19901-19907 */
function diracV107KeysForValue(type, value) {
  const digest = diracV107Hmac(value);
  return [
    { type, key: 'global-ban-active:' + type + ':' + digest },
    { type, key: 'global-ban:' + type + ':' + digest }
  ];
}

/* source 19909-19913 */
function diracV107Ip(req) {
  return typeof diracCentralTrustedClientIpV183 === 'function' ? diracCentralTrustedClientIpV183(req) : 'unknown';
}

/* source 19915-19920 */
function diracV107Cookie(req, name) {
  const raw = String(req && req.headers && req.headers.cookie || '');
  const target = String(name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = raw.match(new RegExp('(?:^|;\\s*)' + target + '=([^;]+)'));
  return match ? String(match[1] || '').slice(0, 200) : '';
}

/* source 19922-19927 */
function diracV107BlockYears() {
  const raw = String(process.env.DIRAC_SQLMAP_BLOCK_YEARS || '10').trim();
  const years = Number(raw);
  if (!Number.isFinite(years) || years <= 0) return 10;
  return Math.min(Math.max(years, 1), 100);
}

/* source 19929-19937 */
function diracV107Hmac(value) {
  const secret = diracCentralDeriveSecretV146('v107-hard-ban-hmac');
  if (!Buffer.isBuffer(secret) || secret.length < 64) {
    const error = new Error('DIRAC_V107_HMAC_SECRET_INVALID');
    error.code = 'DIRAC_V107_HMAC_SECRET_INVALID';
    throw error;
  }
  return crypto.createHmac('sha256', secret).update(String(value || '')).digest('hex');
}

/* source 19985-20003 */
async function diracV107DirectFetch(method, suffix, body) {
  const table = diracV107Table();
  const supabaseUrl = String(process.env.DIRAC_SECURITY_SUPABASE_URL || '').replace(/\/$/, '');
  const serviceKey = String(process.env.DIRAC_SECURITY_SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!table || !supabaseUrl || !serviceKey || typeof fetch !== 'function') return { ok: false, data: null };

  const url = supabaseUrl + '/rest/v1/' + encodeURIComponent(table) + String(suffix || '');
  const headers = {
    apikey: serviceKey,
    Authorization: 'Bearer ' + serviceKey,
    'Content-Type': 'application/json',
    Accept: 'application/json'
  };
  if (method === 'POST') headers.Prefer = 'resolution=merge-duplicates';
  const response = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let data = null;
  try {
    const text = await diracRecoveryReadResponseLimitedV201(response, 2 * 1024 * 1024);
    data = text ? JSON.parse(text) : null;
  } catch (_) {}
  return { ok: response.ok, status: response.status, data };
}

/* source 20005-20007 */
function diracV107Table() {
  return DIRAC_PERSISTENT_BAN_TABLE;
}

/* source 20367-20367 */
const DIRAC_AUTH_HARDENING_SAFE_PATCH_V110 = 'dirac-auth-hardening-safe-v110';

/* source 20398-20417 */
try {
  const __diracV110OriginalSetSessionCookies = typeof setSessionCookies === 'function' ? setSessionCookies : null;
  if (__diracV110OriginalSetSessionCookies && !__diracV110OriginalSetSessionCookies.__diracV110Wrapped) {
    setSessionCookies = function setSessionCookiesV110Tightened(res, session) {
      if (!hasValidDomainSessionTokens(session)) {
        clearSessionCookies(res);
        return false;
      }

      const maxAge = diracV110SessionMaxAgeSeconds();
      appendSetCookie(res, [
        ...makeTokenCookieSet(ACCESS_COOKIE, session.access_token, { maxAge }),
        ...makeTokenCookieSet(REFRESH_COOKIE, session.refresh_token, { maxAge }),
        ...makeSignedDomainSessionCookieSet(session, { maxAge })
      ]);
      return true;
    };
    Object.defineProperty(setSessionCookies, '__diracV110Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 20419-20432 */
try {
  const __diracV110OriginalBuildSessionFingerprint = typeof customerSecurityBuildSessionFingerprint === 'function' ? customerSecurityBuildSessionFingerprint : null;
  if (__diracV110OriginalBuildSessionFingerprint && !__diracV110OriginalBuildSessionFingerprint.__diracV110Wrapped) {
    customerSecurityBuildSessionFingerprint = function customerSecurityBuildSessionFingerprintV110(req, customerId) {
      const fingerprint = __diracV110OriginalBuildSessionFingerprint(req, customerId);
      if (fingerprint && typeof fingerprint === 'object') {
        fingerprint.expires_at = new Date(Date.now() + diracV110SessionMaxAgeSeconds() * 1000).toISOString();
        fingerprint.session_hardening = DIRAC_AUTH_HARDENING_SAFE_PATCH_V110;
      }
      return fingerprint;
    };
    Object.defineProperty(customerSecurityBuildSessionFingerprint, '__diracV110Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 20611-20613 */
function diracV110SessionMaxAgeSeconds() {
  return diracV110NumberFromEnv(['DIRAC_SESSION_COOKIE_MAX_AGE_SECONDS', 'DOMAIN_SESSION_MAX_AGE_SECONDS'], 24 * 60 * 60, 30 * 60, 7 * 24 * 60 * 60);
}

/* source 20735-20743 */
function diracV110NumberFromEnv(names, fallback, min, max) {
  for (const name of names) {
    const raw = String(process.env[name] || '').trim();
    if (!raw) continue;
    const value = Number(raw);
    if (Number.isFinite(value)) return Math.min(Math.max(Math.floor(value), min), max);
  }
  return fallback;
}

/* source 21724-21724 */
const DIRAC_SQLMAP_Sqli_PRECISION_PATCH_V108 = 'dirac-sqlmap-sqli-hard-ban-precision-v108';

/* source 21726-21781 */
try {
  if (typeof diracV107BuildKeys === 'function' && !diracV107BuildKeys.__diracSqlPrecisionV108Wrapped) {
    const __diracSqlPrecisionV108OriginalBuildKeys = diracV107BuildKeys;
    diracV107BuildKeys = function diracV107BuildKeysSqlPrecisionV108(req) {
      const headers = (req && req.headers) || {};
      const keys = [];

      let ip = 'unknown';
      try { ip = typeof diracV107Ip === 'function' ? diracV107Ip(req) : String(headers['x-forwarded-for'] || headers['x-real-ip'] || (req && req.socket && req.socket.remoteAddress) || 'unknown').split(',')[0].trim(); } catch (_) {}
      ip = String(ip || 'unknown').trim() || 'unknown';

      const ua = String(headers['user-agent'] || headers['User-Agent'] || '').slice(0, 500);
      const acceptLanguage = String(headers['accept-language'] || '').slice(0, 120);
      const accept = String(headers.accept || '').slice(0, 200);
      const platform = String(headers['sec-ch-ua-platform'] || '').slice(0, 80);
      const mobile = String(headers['sec-ch-ua-mobile'] || '').slice(0, 40);
      const forwardedHost = String(headers['x-forwarded-host'] || headers.host || '').slice(0, 160);
      const cookie = typeof diracV107Cookie === 'function' ? diracV107Cookie(req, 'dirac_global_hard_ban') : '';

      const pushKeys = (type, value) => {
        try {
          if (typeof diracV107KeysForValue === 'function') {
            keys.push(...diracV107KeysForValue(type, value));
          } else if (typeof diracV107Hmac === 'function') {
            const digest = diracV107Hmac(value);
            keys.push({ type, key: 'global-ban-active:' + type + ':' + digest });
            keys.push({ type, key: 'global-ban:' + type + ':' + digest });
          }
        } catch (_) {}
      };

      // Permanent-ban utama: IP hash. Tidak menyimpan IP mentah pada security_key.
      // Jika IP tidak tersedia dari platform, jangan membuat key global 'unknown' agar user normal tidak ikut terkena ban luas.
      const ipScope = ip && ip !== 'unknown' ? ip : 'no-ip';
      if (ip && ip !== 'unknown') pushKeys('ip', 'ip|' + ip);

      // Jika browser sudah pernah menerima cookie hard-ban, cookie menjadi bukti kuat untuk blokir ulang.
      if (cookie) pushKeys('cookie', 'cookie|' + cookie);

      // Fingerprint tidak boleh hanya User-Agent. Gabungkan dengan IP + header umum agar tidak memblokir
      // semua pengguna Chrome/Safari yang kebetulan punya User-Agent mirip.
      if (ua || acceptLanguage || accept || platform || mobile || forwardedHost) {
        pushKeys('fingerprint', ['fp-v108', ipScope, ua, acceptLanguage, accept, platform, mobile, forwardedHost].join('|'));
      }

      // Kompatibilitas fail-safe: jika entah kenapa tidak ada key, fallback ke builder lama.
      // Normalnya tidak dipakai karena IP selalu tersedia atau menjadi 'unknown'.
      if (!keys.length) {
        try { return __diracSqlPrecisionV108OriginalBuildKeys(req); } catch (_) { return []; }
      }

      return Array.from(new Map(keys.map((item) => [item.key, item])).values());
    };
    Object.defineProperty(diracV107BuildKeys, '__diracSqlPrecisionV108Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 21783-21795 */
try {
  if (typeof diracV107RegisterHardBan === 'function' && !diracV107RegisterHardBan.__diracSqlPrecisionV108Wrapped) {
    const __diracSqlPrecisionV108OriginalRegisterHardBan = diracV107RegisterHardBan;
    diracV107RegisterHardBan = async function diracV107RegisterHardBanSqlPrecisionV108(req, res, action, method, threat) {
      const enrichedThreat = Object.assign({}, threat || {}, {
        identity_policy: 'ip_cookie_fingerprint_no_ua_only',
        precision_patch: DIRAC_SQLMAP_Sqli_PRECISION_PATCH_V108
      });
      return __diracSqlPrecisionV108OriginalRegisterHardBan(req, res, action, method, enrichedThreat);
    };
    Object.defineProperty(diracV107RegisterHardBan, '__diracSqlPrecisionV108Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 21818-21833 */
try {
  if (typeof diracV107BuildKeys === 'function' && !diracV107BuildKeys.__diracCrossDeployV151Wrapped) {
    const __diracCrossDeployV151OriginalBuildKeys = diracV107BuildKeys;
    diracV107BuildKeys = function diracV107BuildKeysCrossDeployV151(req) {
      const keys = __diracCrossDeployV151OriginalBuildKeys(req) || [];
      try {
        const ip = typeof diracV107Ip === 'function' ? String(diracV107Ip(req) || '').trim() : '';
        if (ip && ip !== 'unknown' && typeof diracV107KeysForValue === 'function') {
          keys.push(...diracV107KeysForValue('stable_ip', 'stable-ip-v151|' + ip));
        }
      } catch (_) {}
      return Array.from(new Map(keys.map((item) => [String(item && item.key || ''), item])).values()).filter((item) => item && item.key);
    };
    Object.defineProperty(diracV107BuildKeys, '__diracCrossDeployV151Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 22361-22361 */
const DIRAC_CSRF_COOKIE = process.env.DIRAC_CSRF_COOKIE || '__Host-dirac_csrf_hmac';

/* source 22363-22363 */
const DIRAC_CSRF_RESPONSE_HEADER = 'X-Dirac-CSRF-Token';

/* source 22364-22364 */
const DIRAC_CSRF_TOKEN_TYPE = 'dirac-csrf-hmac-v1';

/* source 22365-22365 */
const DIRAC_CSRF_MAX_AGE_SECONDS = Math.max(300, Math.min(24 * 60 * 60, Number(process.env.DIRAC_CSRF_MAX_AGE_SECONDS || 2 * 60 * 60)));

/* source 22366-22366 */
const DIRAC_CSRF_CLOCK_SKEW_SECONDS = 60;

/* source 22570-22581 */
function diracCsrfIssueToken(req, res, action) {
  const secret = diracCsrfSecret();
  if (!secret || !res || typeof res.setHeader !== 'function') return '';

  const token = diracCsrfCreateToken(req, secret);
  if (!token) return '';

  try { res.setHeader(DIRAC_CSRF_RESPONSE_HEADER, token); } catch (_) {}
  try { res.setHeader('X-Dirac-CSRF-Ready', '1'); } catch (_) {}
  try { appendSetCookie(res, diracCsrfCookie(token)); } catch (_) {}
  return token;
}

/* source 22583-22597 */
function diracCsrfCreateToken(req, secret) {
  const now = Math.floor(Date.now() / 1000);
  const binding = diracCsrfRequestBinding(req);
  const payload = {
    typ: DIRAC_CSRF_TOKEN_TYPE,
    iat: now,
    exp: now + DIRAC_CSRF_MAX_AGE_SECONDS,
    n: crypto.randomBytes(18).toString('base64url'),
    sid: binding.sid || '',
    oh: binding.oh || ''
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + sig;
}

/* source 22599-22610 */
function diracCsrfDecodeToken(token, secret) {
  const raw = String(token || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
  if (!safeEqual(parts[1], expected)) return null;
  try {
    return { payload: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) };
  } catch (_) {
    return null;
  }
}

/* source 22612-22645 */
function diracCsrfRequestBinding(req) {
  const cookies = parseCookies(req);
  let signedUser = null;
  try {
    const values = typeof readCookieTokenCandidates === 'function'
      ? readCookieTokenCandidates(cookies, DOMAIN_SIGNED_SESSION_COOKIE)
      : [cookies[DOMAIN_SIGNED_SESSION_COOKIE]].filter(Boolean);
    for (const value of values) {
      const payload = verifyDomainSessionCookieValue(value);
      if (payload && payload.id && payload.email) {
        signedUser = payload;
        break;
      }
    }
  } catch (_) {}

  const tokenMaterial = [];
  if (signedUser) {
    tokenMaterial.push('signed-user', signedUser.id, normalizeAuthEmail(signedUser.email || ''));
  } else {
    try {
      tokenMaterial.push(
        ...readCookieTokenCandidates(cookies, ACCESS_COOKIE),
        ...readCookieTokenCandidates(cookies, REFRESH_COOKIE),
        ...readCookieTokenCandidates(cookies, DOMAIN_SIGNED_SESSION_COOKIE)
      );
    } catch (_) {}
  }

  const sid = diracCsrfSha256(tokenMaterial.filter(Boolean).join('|')).slice(0, 64);
  const origin = diracCsrfRequestOrigin(req);
  const oh = origin ? diracCsrfSha256('origin|' + origin).slice(0, 64) : '';
  return { sid, oh, origin };
}

/* source 22647-22656 */
function diracCsrfRequestOrigin(req) {
  try {
    if (typeof requestOrigin === 'function') {
      const value = requestOrigin(req);
      if (value) return diracCsrfNormalizeOrigin(value);
    }
  } catch (_) {}
  const headers = (req && req.headers) || {};
  return diracCsrfNormalizeOrigin(headers.origin || headers.Origin || headers.referer || headers.Referer || '');
}

/* source 22658-22665 */
function diracCsrfNormalizeOrigin(value) {
  try {
    const url = new URL(String(value || '').trim());
    return url.origin;
  } catch (_) {
    return '';
  }
}

/* source 22667-22669 */
function diracCsrfSecret() {
  return diracCentralDeriveSecretV146('csrf-v119').toString('base64url');
}

/* source 22671-22682 */
function diracCsrfCookie(token) {
  const maxAge = Math.floor(DIRAC_CSRF_MAX_AGE_SECONDS);
  return [
    DIRAC_CSRF_COOKIE + '=' + encodeURIComponent(String(token || '')),
    'Path=/',
    'Max-Age=' + maxAge,
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Priority=High'
  ].join('; ');
}

/* source 22712-22747 */
function diracCsrfNormalizeAction(action) {
  const clean = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  const aliases = {
    create_order: 'domain_checkout',
    domain_create_order: 'domain_checkout',
    checkout_domain: 'domain_checkout',
    customer_security_revoke_session: 'customer_security_revoke_session',
    customer_security_revoke_other_sessions: 'customer_security_revoke_other_sessions',
    customer_security_account_request: 'customer_security_account_request',
    customer_security_recovery_codes_generate: 'customer_security_recovery_codes_generate',
    customer_security_recovery_code_verify: 'customer_security_recovery_code_verify',
    customer_security_trust_current_device: 'customer_security_trust_current_device',
    customer_security_untrust_device: 'customer_security_untrust_device',
    customer_security_prune_login_history: 'customer_security_prune_login_history',
    create_payment: 'create_payment',
    pay_order: 'create_payment',
    order_payment: 'create_payment',
    checkout_payment: 'create_payment',
    domain_logout: 'domain_logout',
    domain_login: 'domain_login',
    domain_register: 'domain_register',
    dirac_mfa_passkey_start: 'dirac_mfa_passkey_start',
    dirac_mfa_passkey_verify: 'dirac_mfa_passkey_verify',
    domain_mfa_passkey_start: 'dirac_mfa_passkey_start',
    domain_mfa_passkey_verify: 'dirac_mfa_passkey_verify',
    midtrans_webhook: 'midtrans_webhook',
    midtrans_notification: 'midtrans_webhook',
    midtrans_callback: 'midtrans_webhook',
    payment_webhook: 'midtrans_webhook',
    payment_callback: 'midtrans_webhook',
    ipaymu_webhook: 'ipaymu_webhook',
    ipaymu_callback: 'ipaymu_webhook',
    ipaymu_notification: 'ipaymu_webhook'
  };
  return aliases[clean] || clean;
}

/* source 22749-22751 */
function diracCsrfSha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

/* source 23451-23451 */
const DIRAC_BOLA_IDOR_SERVICE_SCOPE_PATCH_V121 = 'bola-idor-service-scope-monitor-v121';

/* source 23453-23453 */
let diracBolaIdorAsyncLocalV121 = null;

/* source 23504-23516 */
function diracBolaIdorV121BuildRequestContext(req) {
  const query = req && req.query && typeof req.query === 'object' ? req.query : {};
  const rawAction = String(query.action || '').trim();
  return {
    patch: DIRAC_BOLA_IDOR_SERVICE_SCOPE_PATCH_V121,
    action: diracBolaIdorV121NormalizeAction(rawAction),
    raw_action: rawAction.slice(0, 120),
    method: String(req && req.method || '').toUpperCase().slice(0, 12),
    origin: diracBolaIdorV121Small(String(req && req.headers && req.headers.origin || ''), 160),
    user_agent_hash: diracBolaIdorV121HashSmall(String(req && req.headers && req.headers['user-agent'] || '')),
    started_at: Date.now()
  };
}

/* source 23518-23526 */
function diracBolaIdorV121CurrentContext() {
  try {
    if (diracBolaIdorAsyncLocalV121 && typeof diracBolaIdorAsyncLocalV121.getStore === 'function') {
      const store = diracBolaIdorAsyncLocalV121.getStore();
      if (store && typeof store === 'object') return store;
    }
  } catch (_) {}
  return null;
}

/* source 23528-23566 */
function diracBolaIdorV121InspectServiceScope(path, options = {}) {
  if (!options || options.auth !== 'service') return { ok: true };
  if (diracBolaIdorV121EnvTrue('DIRAC_BOLA_IDOR_SERVICE_SCOPE_DISABLED', false)) return { ok: true };

  const rawPath = String(path || '').trim();
  if (!rawPath || !rawPath.startsWith('/rest/v1/')) return { ok: true };

  const table = diracBolaIdorV121ExtractRestTable(rawPath);
  if (!table) return { ok: true };

  const policy = diracBolaIdorV121OwnedTablePolicy(table);
  if (!policy) return { ok: true };

  const method = String(options.method || 'GET').toUpperCase();
  const ctx = diracBolaIdorV121CurrentContext() || {};
  const action = diracBolaIdorV121NormalizeAction(ctx.action || '');

  const hasOwnerScope = diracBolaIdorV121HasOwnerScope(rawPath, options.body, policy.ownerColumns);
  const hasObjectScope = diracBolaIdorV121HasObjectScope(rawPath, options.body, policy.objectColumns);
  const safeInsert = method === 'POST' && policy.insertMayUseBodyOwner && diracBolaIdorV121BodyHasAllOwners(options.body, policy.requiredBodyOwners || policy.ownerColumns);
  const safeDeleteByUser = method === 'DELETE' && hasOwnerScope;
  const scoped = hasOwnerScope || safeInsert || (policy.allowObjectScopedRead && method === 'GET' && hasObjectScope) || safeDeleteByUser;

  if (scoped) return { ok: true, table, method, action, scoped: true };

  const enforce = diracBolaIdorV121ShouldEnforce(action, table, method, policy);
  return {
    ok: false,
    warn: true,
    block: enforce,
    table,
    method,
    action,
    reason: 'service_role_owned_table_without_owner_scope',
    owner_columns: policy.ownerColumns,
    object_columns: policy.objectColumns || [],
    patch: DIRAC_BOLA_IDOR_SERVICE_SCOPE_PATCH_V121
  };
}

/* source 23568-23589 */
function diracBolaIdorV121OwnedTablePolicy(table) {
  const name = String(table || '').trim();
  const policies = {
    orders: { ownerColumns: ['customer_id'], objectColumns: ['id', 'order_id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    domain_orders: { ownerColumns: ['customer_id'], objectColumns: ['id', 'order_id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    order_items: { ownerColumns: ['customer_id'], objectColumns: ['id', 'order_id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    domain_order_items: { ownerColumns: ['customer_id'], objectColumns: ['id', 'order_id', 'domain_order_id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    payment_transactions: { ownerColumns: ['customer_id'], objectColumns: ['id', 'order_id', 'domain_order_id', 'gateway_reference'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    security_customer_sessions: { ownerColumns: ['customer_id'], objectColumns: ['id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    security_customer_settings: { ownerColumns: ['customer_id'], objectColumns: ['id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    security_customer_recovery_codes: { ownerColumns: ['customer_id'], objectColumns: ['id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['customer_id'] },
    domain_passkeys: { ownerColumns: ['customer_id', 'auth_user_id', 'user_id', 'email'], objectColumns: ['id', 'credential_id'], insertMayUseBodyOwner: true },
    security_customer_login_logs: { ownerColumns: ['customer_id', 'auth_user_id', 'email'], objectColumns: ['id'], insertMayUseBodyOwner: true },
    security_customer_account_requests: { ownerColumns: ['customer_id', 'auth_user_id', 'email'], objectColumns: ['id'], insertMayUseBodyOwner: true },
    payment_gateway_events: { ownerColumns: ['customer_id'], objectColumns: ['id', 'transaction_id', 'gateway_reference'], insertMayUseBodyOwner: true },
    security_customer_auth_links: { ownerColumns: ['auth_user_id', 'customer_id'], objectColumns: ['id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['auth_user_id', 'customer_id'] },
    security_customer_password_hashes: { ownerColumns: ['auth_user_id', 'customer_id'], objectColumns: ['id'], insertMayUseBodyOwner: true, requiredBodyOwners: ['auth_user_id', 'customer_id'] },
    customer_security_events: { ownerColumns: ['customer_id', 'auth_user_id'], objectColumns: ['id'], insertMayUseBodyOwner: true },
    customers: { ownerColumns: ['id'], objectColumns: ['id'], insertMayUseBodyOwner: false }
  };
  return policies[name] || null;
}

/* source 23591-23595 */
function diracBolaIdorV121HasOwnerScope(path, body, ownerColumns) {
  const cols = Array.isArray(ownerColumns) ? ownerColumns : [];
  if (!cols.length) return false;
  return cols.some((col) => diracBolaIdorV121PathHasColumnFilter(path, col) || diracBolaIdorV121BodyHasSafeColumn(body, col));
}

/* source 23597-23601 */
function diracBolaIdorV121HasObjectScope(path, body, objectColumns) {
  const cols = Array.isArray(objectColumns) ? objectColumns : [];
  if (!cols.length) return false;
  return cols.some((col) => diracBolaIdorV121PathHasColumnFilter(path, col) || diracBolaIdorV121BodyHasSafeColumn(body, col));
}

/* source 23603-23607 */
function diracBolaIdorV121BodyHasAllOwners(body, ownerColumns) {
  const cols = Array.isArray(ownerColumns) ? ownerColumns : [];
  if (!cols.length) return false;
  return cols.every((col) => diracBolaIdorV121BodyHasSafeColumn(body, col));
}

/* source 23609-23618 */
function diracBolaIdorV121PathHasColumnFilter(path, column) {
  const col = String(column || '').trim();
  if (!col) return false;
  const raw = String(path || '');
  const decoded = diracBolaIdorV121SafeDecode(raw).toLowerCase();
  const name = col.toLowerCase().replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
  const direct = new RegExp('(?:[?&])' + name + '=(?:eq|in|is|neq|not\\.|cs|cd|ov|fts|plfts|phfts|wfts)\\.', 'i');
  const selectOr = new RegExp('(?:[?&])or=\\([^)]*' + name + '\\.(?:eq|in)\\.', 'i');
  return direct.test(decoded) || selectOr.test(decoded);
}

/* source 23620-23637 */
function diracBolaIdorV121BodyHasSafeColumn(body, column) {
  const col = String(column || '').trim();
  if (!col || body === undefined || body === null) return false;
  const rows = Array.isArray(body) ? body : [body];
  if (!rows.length) return false;
  return rows.every((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    if (!Object.prototype.hasOwnProperty.call(row, col)) return false;
    const value = row[col];
    if (typeof value !== 'string') return false;
    const text = value.trim();
    if (!text || text.length > 160) return false;
    if (typeof customerSecurityLooksLikeUuid === 'function' && (col === 'customer_id' || col === 'auth_user_id' || col === 'id')) {
      return customerSecurityLooksLikeUuid(text);
    }
    return /^[a-zA-Z0-9._:@-]+$/.test(text);
  });
}

/* source 23639-23651 */
function diracBolaIdorV121ShouldEnforce(action, table, method, policy) {
  if (!diracBolaIdorV121EnvTrue('DIRAC_BOLA_IDOR_SERVICE_SCOPE_ENFORCE', false)) return false;
  const cleanAction = String(action || '').toLowerCase();
  if (diracBolaIdorV121EnvTrue('DIRAC_BOLA_IDOR_SERVICE_SCOPE_ENFORCE_ALL', false)) return true;

  // Default strict mode tetap menghindari alur yang user larang disentuh.
  if (/login|register|logout|payment|pay|midtrans|ipaymu|webhook|callback|notification|checkout|mfa|a2f|passkey|password|hash|email|mail|csrf|token|session|recovery|security|admin/i.test(cleanAction)) {
    return false;
  }

  if (method === 'GET' && /orders|dashboard|me|profile|account/i.test(cleanAction)) return true;
  return false;
}

/* source 23653-23663 */
function diracBolaIdorV121ExtractRestTable(path) {
  try {
    const raw = String(path || '');
    if (!raw.startsWith('/rest/v1/')) return '';
    const part = raw.slice('/rest/v1/'.length).split('?')[0].split('/')[0];
    const decoded = decodeURIComponent(part || '').trim();
    return /^[a-zA-Z0-9_]+$/.test(decoded) ? decoded : '';
  } catch (_) {
    return '';
  }
}

/* source 23665-23677 */
function diracBolaIdorV121NormalizeAction(action) {
  const raw = String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_').slice(0, 120);
  try {
    if (typeof diracUniversalPesananPaymentNormalizeAction === 'function') return diracUniversalPesananPaymentNormalizeAction(raw);
  } catch (_) {}
  try {
    if (typeof diracCsrfNormalizeAction === 'function') return diracCsrfNormalizeAction(raw);
  } catch (_) {}
  try {
    if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(raw);
  } catch (_) {}
  return raw;
}

/* source 23679-23689 */
function diracBolaIdorV121SafeDecode(value) {
  let out = String(value || '');
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(out);
      if (decoded === out) break;
      out = decoded;
    } catch (_) { break; }
  }
  return out;
}

/* source 23691-23698 */
function diracBolaIdorV121EnvTrue(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || String(raw).trim() === '') return !!fallback;
  const value = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'block', 'enforce', 'strict'].includes(value)) return true;
  if (['0', 'false', 'no', 'off', 'monitor', 'disabled'].includes(value)) return false;
  return !!fallback;
}

/* source 23700-23720 */
function diracBolaIdorV121LogDecision(decision) {
  try {
    if (diracBolaIdorV121EnvTrue('DIRAC_BOLA_IDOR_SERVICE_SCOPE_SILENT', false)) return;
    const key = [decision.table, decision.method, decision.action, decision.reason, decision.block ? 'block' : 'warn'].join('|');
    const store = diracBolaIdorV121SeenStore();
    const current = Number(store.get(key) || 0);
    const max = Math.max(1, Number(process.env.DIRAC_BOLA_IDOR_SERVICE_SCOPE_LOG_LIMIT || 5) || 5);
    if (current >= max) return;
    store.set(key, current + 1);
    console.warn('[dirac-bola-idor-service-scope]', {
      patch: DIRAC_BOLA_IDOR_SERVICE_SCOPE_PATCH_V121,
      mode: decision.block ? 'blocked' : 'monitor',
      reason: decision.reason,
      table: decision.table,
      method: decision.method,
      action: decision.action || null,
      owner_columns: decision.owner_columns,
      object_columns: decision.object_columns
    });
  } catch (_) {}
}

/* source 23722-23731 */
function diracBolaIdorV121SeenStore() {
  try {
    if (!globalThis.__DIRAC_BOLA_IDOR_V121_SEEN || !(globalThis.__DIRAC_BOLA_IDOR_V121_SEEN instanceof Map)) {
      globalThis.__DIRAC_BOLA_IDOR_V121_SEEN = new Map();
    }
    return globalThis.__DIRAC_BOLA_IDOR_V121_SEEN;
  } catch (_) {
    return new Map();
  }
}

/* source 23733-23739 */
function diracBolaIdorV121HashSmall(value) {
  try {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex').slice(0, 16);
  } catch (_) {
    return '';
  }
}

/* source 23741-23743 */
function diracBolaIdorV121Small(value, max) {
  return String(value || '').replace(/[\u0000-\u001f\u007f<>]/g, '').slice(0, Math.max(1, Number(max || 120)));
}

/* source 23951-23962 */
function diracBolaIdorV122ExtractRestTable(path) {
  try {
    if (typeof diracBolaIdorV121ExtractRestTable === 'function') return diracBolaIdorV121ExtractRestTable(path);
  } catch (_) {}
  try {
    const raw = String(path || '');
    if (!raw.startsWith('/rest/v1/')) return '';
    const part = raw.slice('/rest/v1/'.length).split('?')[0].split('/')[0];
    const decoded = decodeURIComponent(part || '').trim();
    return /^[a-zA-Z0-9_]+$/.test(decoded) ? decoded : '';
  } catch (_) { return ''; }
}

/* source 23964-23969 */
function diracBolaIdorV122NormalizeAction(action) {
  try {
    if (typeof diracBolaIdorV121NormalizeAction === 'function') return diracBolaIdorV121NormalizeAction(action);
  } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_').slice(0, 120);
}

/* source 23986-23996 */
function diracBolaIdorV122EnvTrue(name, fallback = false) {
  try {
    if (typeof diracBolaIdorV121EnvTrue === 'function') return diracBolaIdorV121EnvTrue(name, fallback);
  } catch (_) {}
  const raw = process.env[name];
  if (raw === undefined || raw === null || String(raw).trim() === '') return !!fallback;
  const value = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'block', 'enforce', 'strict'].includes(value)) return true;
  if (['0', 'false', 'no', 'off', 'monitor', 'disabled'].includes(value)) return false;
  return !!fallback;
}

/* source 24209-24214 */
function diracBolaIdorV126AllowedCustomerIds(ctx) {
  try {
    const ids = Array.isArray(ctx && ctx.allowedCustomerIdsV126) ? ctx.allowedCustomerIdsV126 : [];
    return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(diracBolaIdorV126LooksLikeUuid))).slice(0, 25);
  } catch (_) { return []; }
}

/* source 24251-24256 */
function diracBolaIdorV126CurrentContext() {
  try {
    if (typeof diracBolaIdorV121CurrentContext === 'function') return diracBolaIdorV121CurrentContext();
  } catch (_) {}
  return null;
}

/* source 24258-24269 */
function diracBolaIdorV126ExtractRestTable(path) {
  try {
    if (typeof diracBolaIdorV122ExtractRestTable === 'function') return diracBolaIdorV122ExtractRestTable(path);
  } catch (_) {}
  try {
    const raw = String(path || '');
    if (!raw.startsWith('/rest/v1/')) return '';
    const part = raw.slice('/rest/v1/'.length).split('?')[0].split('/')[0];
    const decoded = decodeURIComponent(part || '').trim();
    return /^[a-zA-Z0-9_]+$/.test(decoded) ? decoded : '';
  } catch (_) { return ''; }
}

/* source 24278-24283 */
function diracBolaIdorV126NormalizeAction(action) {
  try {
    if (typeof diracBolaIdorV122NormalizeAction === 'function') return diracBolaIdorV122NormalizeAction(action);
  } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_').slice(0, 120);
}

/* source 24285-24290 */
function diracBolaIdorV126LooksLikeUuid(value) {
  try {
    if (typeof customerSecurityLooksLikeUuid === 'function') return customerSecurityLooksLikeUuid(value);
  } catch (_) {}
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

/* source 24307-24317 */
function diracBolaIdorV126EnvTrue(name, fallback = false) {
  try {
    if (typeof diracBolaIdorV122EnvTrue === 'function') return diracBolaIdorV122EnvTrue(name, fallback);
  } catch (_) {}
  const raw = process.env[name];
  if (raw === undefined || raw === null || String(raw).trim() === '') return !!fallback;
  const value = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'block', 'enforce', 'strict'].includes(value)) return true;
  if (['0', 'false', 'no', 'off', 'monitor', 'disabled'].includes(value)) return false;
  return !!fallback;
}

/* source 24363-24363 */
const DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128 = 'dirac-bola-idor-global-hard-ban-v128';

/* source 24364-24364 */
const DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128 = globalThis.__DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128__ || new Map();

/* source 24365-24365 */
globalThis.__DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128__ = DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128;

/* source 24367-24367 */
let diracBolaIdorAsyncLocalV128 = null;

/* source 24420-24433 */
function diracBolaIdorV128BuildRequestContext(req) {
  const query = req && req.query && typeof req.query === 'object' ? req.query : {};
  const rawAction = String(query.action || '').trim();
  const action = diracBolaIdorV128NormalizeAction(rawAction);
  return {
    patch: DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128,
    req,
    action,
    raw_action: rawAction.slice(0, 120),
    method: String(req && req.method || 'GET').toUpperCase().slice(0, 12),
    started_at: Date.now(),
    allowedCustomerIdsV128: []
  };
}

/* source 24435-24447 */
function diracBolaIdorV128CurrentContext() {
  try {
    if (diracBolaIdorAsyncLocalV128 && typeof diracBolaIdorAsyncLocalV128.getStore === 'function') {
      const store = diracBolaIdorAsyncLocalV128.getStore();
      if (store && typeof store === 'object') return store;
    }
  } catch (_) {}
  try {
    const ctx126 = typeof diracBolaIdorV126CurrentContext === 'function' ? diracBolaIdorV126CurrentContext() : null;
    if (ctx126 && typeof ctx126 === 'object') return ctx126;
  } catch (_) {}
  return null;
}

/* source 24449-24499 */
async function diracBolaIdorV128InspectHttpRequest(req) {
  const method = String(req && req.method || 'GET').toUpperCase();
  const action = diracBolaIdorV128NormalizeAction(String(req && req.query && req.query.action || ''));
  if (diracBolaIdorV128ShouldSkipAction(action, method, req)) return { ok: true };
  if (!diracBolaIdorV128IsProtectedUserObjectAction(action)) return { ok: true };

  const ids = diracBolaIdorV128CollectIds(req && req.query, 'query');
  if (!ids.length) return { ok: true };

  const owner = await diracBolaIdorV128ResolveRequestOwner(req).catch(() => null);
  if (!owner || !owner.ok) return { ok: true, reason: 'request_owner_unavailable_fail_safe' };

  const customerMismatch = diracBolaIdorV128FindCustomerMismatch(ids, owner.customerIds);
  if (customerMismatch) {
    return diracBolaIdorV128BuildBlockDecision('http_query_customer_id_mismatch', {
      source: 'query',
      action,
      method,
      requested_count: customerMismatch.requestedCount,
      allowed_count: owner.customerIds.length
    });
  }

  const authUserMismatch = diracBolaIdorV128FindAuthUserMismatch(ids, owner.authUserId);
  if (authUserMismatch) {
    return diracBolaIdorV128BuildBlockDecision('http_query_auth_user_id_mismatch', {
      source: 'query',
      action,
      method,
      requested_count: authUserMismatch.requestedCount
    });
  }

  const objectIds = diracBolaIdorV128ObjectIdsFromCollected(ids);
  if (objectIds.length && owner.customerIds.length) {
    const owned = await diracBolaIdorV128ResolveKnownObjectOwners(objectIds).catch(() => []);
    const foreign = owned.filter((row) => row && row.customer_id && !owner.customerIds.includes(String(row.customer_id)));
    if (foreign.length) {
      return diracBolaIdorV128BuildBlockDecision('http_query_foreign_object_id', {
        source: 'query',
        action,
        method,
        requested_count: objectIds.length,
        foreign_count: foreign.length,
        tables: Array.from(new Set(foreign.map((row) => row.table).filter(Boolean))).join(',')
      });
    }
  }

  return { ok: true };
}

/* source 24501-24568 */
async function diracBolaIdorV128InspectSupabaseAccess(path, options = {}) {
  if (!options || options.auth !== 'service') return { ok: true };
  if (diracBolaIdorV128EnvTrue('DIRAC_BOLA_IDOR_GLOBAL_BAN_DISABLED', false)) return { ok: true };

  const rawPath = String(path || '').trim();
  if (!rawPath || !rawPath.startsWith('/rest/v1/')) return { ok: true };

  const table = diracBolaIdorV128ExtractRestTable(rawPath);
  if (!diracBolaIdorV128IsOwnedTable(table)) return { ok: true };

  const method = String(options.method || 'GET').toUpperCase();
  const ctx = diracBolaIdorV128CurrentContext() || {};
  const action = diracBolaIdorV128NormalizeAction(ctx.action || '');
  if (!action || diracBolaIdorV128ShouldSkipAction(action, method, ctx.req)) return { ok: true };
  if (!diracBolaIdorV128IsProtectedUserObjectAction(action)) return { ok: true };

  const allowed = diracBolaIdorV128AllowedCustomerIds(ctx);
  if (!allowed.length) return { ok: true, reason: 'trusted_owner_not_yet_available' };

  const ids = diracBolaIdorV128CollectIdsFromSupabase(rawPath, options.body);
  const customerMismatch = diracBolaIdorV128FindCustomerMismatch(ids, allowed);
  if (customerMismatch) {
    return diracBolaIdorV128BuildBlockDecision('supabase_customer_id_not_bound_to_authenticated_owner', {
      source: 'supabase',
      table,
      method,
      action,
      requested_count: customerMismatch.requestedCount,
      allowed_count: allowed.length
    });
  }

  const directObjectIds = diracBolaIdorV128DirectObjectIdsForTable(table, ids);
  if (directObjectIds.length && /^(GET|HEAD|PATCH|PUT|DELETE)$/i.test(method)) {
    const owners = await diracBolaIdorV128ResolveKnownObjectOwners(directObjectIds, table).catch(() => []);
    const foreign = owners.filter((row) => row && row.customer_id && !allowed.includes(String(row.customer_id)));
    if (foreign.length) {
      return diracBolaIdorV128BuildBlockDecision('supabase_object_id_not_bound_to_authenticated_owner', {
        source: 'supabase',
        table,
        method,
        action,
        requested_count: directObjectIds.length,
        foreign_count: foreign.length
      });
    }
  }

  if (diracBolaIdorV128IsChildOrderTable(table) && /^(GET|HEAD|PATCH|PUT|DELETE)$/i.test(method)) {
    const parentIds = diracBolaIdorV128ChildOrderIds(table, ids);
    if (parentIds.length) {
      const owners = await diracBolaIdorV128ResolveChildParentOwners(table, parentIds).catch(() => []);
      const foreign = owners.filter((row) => row && row.customer_id && !allowed.includes(String(row.customer_id)));
      if (foreign.length) {
        return diracBolaIdorV128BuildBlockDecision('child_order_parent_not_bound_to_authenticated_owner', {
          source: 'supabase',
          table,
          method,
          action,
          requested_count: parentIds.length,
          foreign_count: foreign.length
        });
      }
    }
  }

  return { ok: true };
}

/* source 24570-24579 */
function diracBolaIdorV128BuildBlockDecision(reason, extra = {}) {
  return {
    ok: false,
    warn: true,
    block: true,
    reason: String(reason || 'bola_idor_blocked').slice(0, 120),
    patch: DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128,
    ...extra
  };
}

/* source 24581-24592 */
function diracBolaIdorV128ShouldSkipAction(action, method, req) {
  if (String(method || '').toUpperCase() === 'OPTIONS') return true;
  const url = String(req && req.url || '');
  if (/\.(?:html?|css|js|mjs|map|png|jpe?g|webp|gif|svg|ico|woff2?|ttf|otf)(?:\?|$)/i.test(url) && !/\/api\/health/i.test(url)) return true;

  const clean = String(action || '').toLowerCase();
  if (!clean) return false;
  if (/^(domain_health|hostinger_check|domain_check|midtrans_health)$/i.test(clean)) return true;
  if (/login|register|logout|midtrans|ipaymu|webhook|callback|notification|payment_gateway|payment_notification|a2f|mfa|passkey|password|hash|email|mail|csrf|token/i.test(clean)) return true;
  if (/^(create_payment|pay_order|order_payment|create_payment_order)$/i.test(clean)) return true;
  return false;
}

/* source 24594-24600 */
function diracBolaIdorV128IsProtectedUserObjectAction(action) {
  const clean = String(action || '').toLowerCase();
  if (!clean) return false;
  if (/^(domain_me|domain_dashboard_me|domain_orders|my_orders|pesanan_saya|customer_orders|customer_security_status|customer_security_overview)$/i.test(clean)) return true;
  if (/customer_security|security_customer|orders|order|dashboard|profile|account|customer|customers|session|recovery|invoice|invoices|pesanan/i.test(clean)) return true;
  return false;
}

/* source 24602-24626 */
function diracBolaIdorV128CollectIds(source, sourceName) {
  const out = [];
  const walk = (value, key, depth) => {
    if (depth > 4 || value === undefined || value === null) return;
    const cleanKey = diracBolaIdorV128NormalizeKey(key);
    if (Array.isArray(value)) {
      value.forEach((item) => walk(item, key, depth + 1));
      return;
    }
    if (typeof value === 'object') {
      Object.entries(value).forEach(([childKey, childValue]) => walk(childValue, childKey, depth + 1));
      return;
    }
    if (!diracBolaIdorV128IsIdentifierKey(cleanKey)) return;
    const values = diracBolaIdorV128ExtractPossibleValues(value).filter(Boolean).slice(0, 20);
    values.forEach((item) => out.push({ key: cleanKey, value: item, source: sourceName || 'unknown' }));
  };
  if (source && typeof source === 'object') {
    Object.entries(source).forEach(([key, value]) => {
      if (diracBolaIdorV128NormalizeKey(key) === 'action') return;
      walk(value, key, 0);
    });
  }
  return out.slice(0, 80);
}

/* source 24628-24641 */
function diracBolaIdorV128CollectIdsFromSupabase(path, body) {
  const out = [];
  const columns = [
    'customer_id', 'auth_user_id', 'user_id', 'owner_user_id', 'profile_id', 'account_id',
    'id', 'order_id', 'domain_order_id', 'session_id', 'recovery_code_id', 'transaction_id', 'payment_transaction_id'
  ];
  for (const col of columns) {
    const pathValues = diracBolaIdorV128ExtractColumnValuesFromPath(path, col);
    pathValues.forEach((value) => out.push({ key: diracBolaIdorV128NormalizeKey(col), value, source: 'supabase_path' }));
    const bodyValues = diracBolaIdorV128ExtractColumnValuesFromBody(body, col);
    bodyValues.forEach((value) => out.push({ key: diracBolaIdorV128NormalizeKey(col), value, source: 'supabase_body' }));
  }
  return out.filter((item) => item && item.value).slice(0, 120);
}

/* source 24643-24645 */
function diracBolaIdorV128NormalizeKey(key) {
  return String(key || '').trim().replace(/[A-Z]/g, (m) => '_' + m.toLowerCase()).replace(/[-\s]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase();
}

/* source 24647-24650 */
function diracBolaIdorV128IsIdentifierKey(key) {
  const clean = String(key || '').toLowerCase();
  return /^(id|customer_id|auth_user_id|user_id|owner_user_id|profile_id|account_id|order_id|domain_order_id|session_id|recovery_code_id|invoice_id|transaction_id|payment_transaction_id|gateway_reference)$/.test(clean);
}

/* source 24652-24665 */
function diracBolaIdorV128ExtractPossibleValues(value) {
  const raw = String(value || '').trim();
  if (!raw) return [];
  const decoded = diracBolaIdorV128SafeDecode(raw);
  const samples = [raw, decoded];
  const out = [];
  for (const sample of samples) {
    String(sample || '').split(/[\s,|]+/).forEach((part) => {
      const clean = part.replace(/^(?:eq|in|is)\./i, '').replace(/^\(/, '').replace(/\)$/, '').replace(/^['"]|['"]$/g, '').trim();
      if (clean) out.push(clean.slice(0, 180));
    });
  }
  return Array.from(new Set(out));
}

/* source 24667-24676 */
function diracBolaIdorV128FindCustomerMismatch(ids, allowedCustomerIds) {
  const allowed = new Set((allowedCustomerIds || []).map((id) => String(id || '').trim()).filter(diracBolaIdorV128LooksLikeUuid));
  if (!allowed.size) return null;
  const requested = ids
    .filter((item) => item && item.key === 'customer_id')
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV128LooksLikeUuid);
  const denied = requested.filter((id) => !allowed.has(id));
  return denied.length ? { requestedCount: requested.length, denied } : null;
}

/* source 24678-24687 */
function diracBolaIdorV128FindAuthUserMismatch(ids, authUserId) {
  const expected = String(authUserId || '').trim();
  if (!diracBolaIdorV128LooksLikeUuid(expected)) return null;
  const requested = ids
    .filter((item) => item && /^(auth_user_id|user_id|owner_user_id)$/i.test(item.key))
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV128LooksLikeUuid);
  const denied = requested.filter((id) => id !== expected);
  return denied.length ? { requestedCount: requested.length, denied } : null;
}

/* source 24689-24695 */
function diracBolaIdorV128ObjectIdsFromCollected(ids) {
  const objectKeys = /^(id|order_id|domain_order_id|session_id|recovery_code_id|invoice_id|transaction_id|payment_transaction_id)$/i;
  return Array.from(new Set((ids || [])
    .filter((item) => item && objectKeys.test(item.key))
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 40);
}

/* source 24697-24706 */
function diracBolaIdorV128DirectObjectIdsForTable(table, ids) {
  const cleanTable = String(table || '').toLowerCase();
  const directKeys = diracBolaIdorV128IsChildOrderTable(cleanTable)
    ? /^(id)$/i
    : /^(id|order_id|domain_order_id|session_id|recovery_code_id|transaction_id|payment_transaction_id)$/i;
  return Array.from(new Set((ids || [])
    .filter((item) => item && directKeys.test(item.key))
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 40);
}

/* source 24708-24715 */
function diracBolaIdorV128ChildOrderIds(table, ids) {
  const cleanTable = String(table || '').toLowerCase();
  const wanted = cleanTable === 'domain_order_items' ? /^(order_id|domain_order_id)$/i : /^order_id$/i;
  return Array.from(new Set((ids || [])
    .filter((item) => item && wanted.test(item.key))
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 80);
}

/* source 24717-24739 */
async function diracBolaIdorV128ResolveRequestOwner(req) {
  const ctx = diracBolaIdorV128CurrentContext();
  if (ctx && ctx.ownerResolvedV128) return ctx.ownerResolvedV128;

  if (typeof requireDomainUser !== 'function' || typeof customerSecurityFetchAuthLink !== 'function') return { ok: false };
  const fakeRes = diracBolaIdorV128FakeResponse();
  const user = await requireDomainUser(req, fakeRes).catch(() => null);
  const authUserId = String(user && user.id || '').trim();
  if (!authUserId || !diracBolaIdorV128LooksLikeUuid(authUserId)) return { ok: false };

  const linkResult = await customerSecurityFetchAuthLink(authUserId).catch(() => null);
  const rows = linkResult && linkResult.ok && Array.isArray(linkResult.data) ? linkResult.data : [];
  const customerIds = Array.from(new Set(rows
    .filter((row) => row && String(row.link_status || '').toLowerCase() === 'active')
    .map((row) => String(row.customer_id || '').trim())
    .filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 25);
  const owner = { ok: true, authUserId, customerIds };
  if (ctx && typeof ctx === 'object') {
    ctx.ownerResolvedV128 = owner;
    ctx.allowedCustomerIdsV128 = Array.from(new Set((ctx.allowedCustomerIdsV128 || []).concat(customerIds))).slice(0, 25);
  }
  return owner;
}

/* source 24741-24752 */
function diracBolaIdorV128FakeResponse() {
  const headers = {};
  return {
    statusCode: 200,
    headers,
    setHeader(name, value) { headers[String(name).toLowerCase()] = value; },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    status(code) { this.statusCode = Number(code || 200); return this; },
    json(payload) { this.payload = payload; return this; },
    end() { return this; }
  };
}

/* source 24754-24765 */
function diracBolaIdorV128AllowedCustomerIds(ctx) {
  const out = [];
  try { if (Array.isArray(ctx && ctx.allowedCustomerIdsV128)) out.push(...ctx.allowedCustomerIdsV128); } catch (_) {}
  try { if (Array.isArray(ctx && ctx.allowedCustomerIdsV126)) out.push(...ctx.allowedCustomerIdsV126); } catch (_) {}
  try { if (ctx && ctx.ownerResolvedV128 && Array.isArray(ctx.ownerResolvedV128.customerIds)) out.push(...ctx.ownerResolvedV128.customerIds); } catch (_) {}
  try {
    if (typeof diracBolaIdorV126AllowedCustomerIds === 'function') {
      out.push(...diracBolaIdorV126AllowedCustomerIds(ctx));
    }
  } catch (_) {}
  return Array.from(new Set(out.map((id) => String(id || '').trim()).filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 25);
}

/* source 24767-24783 */
function diracBolaIdorV128LearnTrustedOwners(path, options = {}, result) {
  try {
    if (!options || options.auth !== 'service' || !result || !result.ok) return;
    const table = diracBolaIdorV128ExtractRestTable(String(path || ''));
    if (table !== 'security_customer_auth_links') return;
    if (String(options.method || 'GET').toUpperCase() !== 'GET') return;
    if (!diracBolaIdorV128PathHasColumnFilter(path, 'auth_user_id')) return;
    const ctx = diracBolaIdorV128CurrentContext();
    if (!ctx || typeof ctx !== 'object') return;
    const ids = (Array.isArray(result.data) ? result.data : [])
      .filter((row) => row && String(row.link_status || '').toLowerCase() === 'active')
      .map((row) => String(row.customer_id || '').trim())
      .filter(diracBolaIdorV128LooksLikeUuid);
    if (!ids.length) return;
    ctx.allowedCustomerIdsV128 = Array.from(new Set((ctx.allowedCustomerIdsV128 || []).concat(ids))).slice(0, 25);
  } catch (_) {}
}

/* source 24785-24790 */
async function diracBolaIdorV128ResolveChildParentOwners(childTable, parentIds) {
  const ids = Array.from(new Set((parentIds || []).filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 80);
  if (!ids.length) return [];
  const parentTable = String(childTable || '').toLowerCase() === 'domain_order_items' ? 'domain_orders' : 'orders';
  return diracBolaIdorV128FetchOwnerRows(parentTable, ids, 'id');
}

/* source 24792-24807 */
async function diracBolaIdorV128ResolveKnownObjectOwners(objectIds, preferredTable) {
  const ids = Array.from(new Set((objectIds || []).filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 40);
  if (!ids.length) return [];
  const tables = [];
  const preferred = String(preferredTable || '').toLowerCase();
  if (preferred && diracBolaIdorV128DirectOwnerTable(preferred)) tables.push(preferred);
  ['orders', 'domain_orders', 'security_customer_sessions', 'security_customer_settings', 'security_customer_recovery_codes', 'payment_transactions']
    .forEach((table) => { if (!tables.includes(table)) tables.push(table); });

  const rows = [];
  for (const table of tables.slice(0, 6)) {
    const fetched = await diracBolaIdorV128FetchOwnerRows(table, ids, 'id').catch(() => []);
    rows.push(...fetched);
  }
  return rows;
}

/* source 24809-24811 */
function diracBolaIdorV128DirectOwnerTable(table) {
  return /^(orders|domain_orders|security_customer_sessions|security_customer_settings|security_customer_recovery_codes|payment_transactions)$/i.test(String(table || ''));
}

/* source 24813-24825 */
async function diracBolaIdorV128FetchOwnerRows(table, ids, column) {
  const cleanTable = String(table || '').trim();
  const col = String(column || 'id').trim();
  const cleanIds = Array.from(new Set((ids || []).map((id) => String(id || '').trim()).filter(diracBolaIdorV128LooksLikeUuid))).slice(0, 100);
  if (!cleanTable || !cleanIds.length || !/^[a-zA-Z0-9_]+$/.test(cleanTable) || !/^[a-zA-Z0-9_]+$/.test(col)) return [];
  const select = encodeURIComponent('id,customer_id');
  const path = '/rest/v1/' + encodeURIComponent(cleanTable) + '?select=' + select + '&' + encodeURIComponent(col) + '=in.(' + cleanIds.map(encodeURIComponent).join(',') + ')&limit=' + String(cleanIds.length);
  const result = await diracBolaIdorV128DirectSupabaseServiceGet(path).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data)) return [];
  return result.data
    .filter((row) => row && row.customer_id)
    .map((row) => ({ table: cleanTable, id: String(row.id || ''), customer_id: String(row.customer_id || '') }));
}

/* source 24827-24882 */
async function diracBolaIdorV128DirectSupabaseServiceGet(path) {
  if (typeof fetch !== 'function') return { ok: false, status: 0, data: null };
  let target = null;
  try {
    const targetKey = typeof resolveDiracSupabaseTargetKey === 'function' ? resolveDiracSupabaseTargetKey(path, { auth: 'service' }) : 'legacy';
    target = typeof readDiracSupabaseCredentials === 'function' ? readDiracSupabaseCredentials(targetKey) : null;
  } catch (_) { target = null; }

  const fallbackUrl = String(process.env.DOMAIN_SUPABASE_URL || process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const fallbackKey = String(process.env.DOMAIN_SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY || '').trim();
  const url = target && target.url ? String(target.url).replace(/\/$/, '') : fallbackUrl;
  const serviceKey = target && target.serviceKey ? String(target.serviceKey) : fallbackKey;
  if (!url || !serviceKey) return { ok: false, status: 0, data: null };

  const timeoutMs = Math.max(1000, Number(process.env.DIRAC_BOLA_IDOR_DIRECT_FETCH_TIMEOUT_MS || process.env.DIRAC_SUPABASE_FETCH_TIMEOUT_MS || 6500) || 6500);
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  let timer = null;
  const fetchOptions = {
    method: 'GET',
    headers: {
      apikey: serviceKey,
      Authorization: 'Bearer ' + serviceKey,
      Accept: 'application/json',
      'Content-Type': 'application/json'
    }
  };
  if (controller) {
    fetchOptions.signal = controller.signal;
    timer = setTimeout(() => {
      try { controller.abort(); } catch (_) {}
    }, timeoutMs);
  }

  let response = null;
  let text = '';
  try {
    response = await fetch(url + String(path || ''), fetchOptions);
    text = await diracRecoveryReadResponseLimitedV201(response, 2 * 1024 * 1024);
  } catch (error) {
    return {
      ok: false,
      status: error && error.name === 'AbortError' ? 504 : 502,
      data: {
        ok: false,
        code: error && error.name === 'AbortError' ? 'BOLA_IDOR_DIRECT_SUPABASE_TIMEOUT' : 'BOLA_IDOR_DIRECT_SUPABASE_FAILED'
      },
      error: error && (error.code || error.name || error.message) || 'BOLA_IDOR_DIRECT_SUPABASE_FAILED'
    };
  } finally {
    if (timer) clearTimeout(timer);
  }

  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
  return { ok: response.ok, status: response.status, data };
}

/* source 24884-24887 */
async function diracBolaIdorV128RegisterGlobalHardBanFromContext(decision) {
  const ctx = diracBolaIdorV128CurrentContext() || {};
  return diracBolaIdorV128RegisterGlobalHardBan(ctx.req, ctx.action || decision.action, ctx.method || decision.method, decision);
}

/* source 24889-24922 */
async function diracBolaIdorV128RegisterGlobalHardBan(req, action, method, decision) {
  const threat = {
    detected: true,
    kind: 'bola_idor_owner_mismatch',
    source: decision && decision.source || 'bola_idor_guard',
    risk: 'critical',
    patch: DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128
  };
  try {
    if (req && typeof diracV107RegisterHardBan === 'function') {
      await diracV107RegisterHardBan(req, null, action || 'bola_idor', method || 'GET', threat);
      return { ok: true, source: 'v107_global_hard_ban' };
    }
  } catch (_) {}

  try {
    const key = diracBolaIdorV128RequestBanKey(req || {}, action, method);
    const until = Date.now() + diracBolaIdorV128BlockYears() * 365 * 24 * 60 * 60 * 1000;
    DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128.set(key, { blockedUntilMs: until, reason: decision && decision.reason || 'bola_idor' });
    if (typeof writePersistentSecurityJson === 'function') {
      await writePersistentSecurityJson('bola-idor-global-ban:' + key, {
        event_type: 'bola_idor_global_hard_ban',
        patch: DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128,
        action: String(action || '').slice(0, 80),
        method: String(method || '').slice(0, 12),
        reason: String(decision && decision.reason || 'bola_idor').slice(0, 120),
        created_at: new Date().toISOString()
      }, until, diracBolaIdorV128BlockYears() * 365 * 24 * 60 * 60);
    }
    return { ok: true, source: 'v128_memory_persistent_fallback' };
  } catch (_) {
    return { ok: false };
  }
}

/* source 24924-24930 */
function diracBolaIdorV128RequestBanKey(req, action, method) {
  const headers = req && req.headers || {};
  const ip = typeof getLoginSecurityIp === 'function' ? getLoginSecurityIp(req) : String(headers['x-forwarded-for'] || headers['x-real-ip'] || 'unknown');
  const ua = String(headers['user-agent'] || '').slice(0, 240);
  const base = [String(ip || 'unknown'), ua, String(action || ''), String(method || '')].join('|');
  return diracBolaIdorV128Hash(base);
}

/* source 24932-24941 */
function diracBolaIdorV128BlockedHttpResponse(res, reason) {
  try { if (typeof diracApplySecurityResponseHeaders === 'function') diracApplySecurityResponseHeaders(res); } catch (_) {}
  try { if (res && typeof res.setHeader === 'function') res.setHeader('Cache-Control', 'no-store'); } catch (_) {}
  return res.status(403).json({
    ok: false,
    code: 'BOLA_IDOR_GLOBAL_HARD_BAN',
    message: 'Akses dibatasi oleh sistem keamanan.',
    reason: String(reason || 'BOLA_IDOR_BLOCKED').slice(0, 80)
  });
}

/* source 24943-24964 */
function diracBolaIdorV128BlockedSupabaseResult(decision) {
  return {
    ok: false,
    status: 403,
    statusText: 'Forbidden',
    data: {
      ok: false,
      code: 'BOLA_IDOR_GLOBAL_HARD_BAN',
      message: 'Permintaan ditolak oleh sistem keamanan.',
      reason: 'owner_not_bound_to_authenticated_session'
    },
    error: 'BOLA_IDOR_GLOBAL_HARD_BAN',
    diracSecurityThreat: {
      detected: true,
      kind: 'bola_idor_global_hard_ban',
      table: decision && decision.table || null,
      method: decision && decision.method || null,
      action: decision && decision.action || null,
      patch: DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128
    }
  };
}

/* source 24966-24982 */
function diracBolaIdorV128ExtractColumnValuesFromPath(path, column) {
  const col = String(column || '').trim().toLowerCase();
  if (!col) return [];
  const decoded = diracBolaIdorV128SafeDecode(path);
  const query = decoded.split('?')[1] || '';
  if (!query) return [];
  const out = [];
  for (const part of query.split('&')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = decodeURIComponent(part.slice(0, idx)).toLowerCase();
    const value = part.slice(idx + 1);
    if (key === col) out.push(...diracBolaIdorV128ParsePostgrestFilterValue(value));
    if (key === 'or') out.push(...diracBolaIdorV128ParseOrFilterValues(value, col));
  }
  return Array.from(new Set(out.map((item) => String(item || '').trim()).filter(Boolean))).slice(0, 80);
}

/* source 24984-24997 */
function diracBolaIdorV128ExtractColumnValuesFromBody(body, column) {
  const col = String(column || '').trim();
  if (!col || body === undefined || body === null) return [];
  const rows = Array.isArray(body) ? body : [body];
  const out = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    if (!Object.prototype.hasOwnProperty.call(row, col)) continue;
    const value = row[col];
    if (Array.isArray(value)) value.forEach((item) => out.push(String(item || '').trim()));
    else out.push(String(value || '').trim());
  }
  return Array.from(new Set(out.filter(Boolean))).slice(0, 80);
}

/* source 24999-25009 */
function diracBolaIdorV128ParsePostgrestFilterValue(value) {
  const raw = diracBolaIdorV128SafeDecode(String(value || '').trim());
  if (!raw) return [];
  const lower = raw.toLowerCase();
  if (lower.startsWith('eq.')) return [raw.slice(3)];
  if (lower.startsWith('in.')) {
    const inner = raw.slice(3).replace(/^\(/, '').replace(/\)$/, '');
    return inner.split(',').map((item) => item.replace(/^"|"$/g, '').trim()).filter(Boolean);
  }
  return [];
}

/* source 25011-25022 */
function diracBolaIdorV128ParseOrFilterValues(value, column) {
  const raw = diracBolaIdorV128SafeDecode(String(value || '')).replace(/^\(/, '').replace(/\)$/, '');
  const col = String(column || '').toLowerCase();
  const out = [];
  for (const item of raw.split(',')) {
    const text = item.trim();
    const lower = text.toLowerCase();
    if (lower.startsWith(col + '.eq.')) out.push(text.slice(col.length + 4));
    if (lower.startsWith(col + '.in.')) out.push(...diracBolaIdorV128ParsePostgrestFilterValue(text.slice(col.length + 1)));
  }
  return out;
}

/* source 25024-25026 */
function diracBolaIdorV128PathHasColumnFilter(path, column) {
  return diracBolaIdorV128ExtractColumnValuesFromPath(path, column).length > 0;
}

/* source 25028-25030 */
function diracBolaIdorV128IsOwnedTable(table) {
  return /^(orders|order_items|domain_orders|domain_order_items|payment_transactions|security_customer_sessions|security_customer_settings|security_customer_recovery_codes|security_customer_auth_links|security_customer_password_hashes|customer_security_events|domain_passkeys|security_customer_login_logs|security_customer_account_requests|customers)$/i.test(String(table || ''));
}

/* source 25032-25034 */
function diracBolaIdorV128IsChildOrderTable(table) {
  return /^(order_items|domain_order_items)$/i.test(String(table || ''));
}

/* source 25036-25047 */
function diracBolaIdorV128ExtractRestTable(path) {
  try {
    if (typeof diracBolaIdorV126ExtractRestTable === 'function') return diracBolaIdorV126ExtractRestTable(path);
  } catch (_) {}
  try {
    const raw = String(path || '');
    if (!raw.startsWith('/rest/v1/')) return '';
    const part = raw.slice('/rest/v1/'.length).split('?')[0].split('/')[0];
    const decoded = decodeURIComponent(part || '').trim();
    return /^[a-zA-Z0-9_]+$/.test(decoded) ? decoded : '';
  } catch (_) { return ''; }
}

/* source 25049-25054 */
function diracBolaIdorV128NormalizeAction(action) {
  try { if (typeof diracBolaIdorV126NormalizeAction === 'function') return diracBolaIdorV126NormalizeAction(action); } catch (_) {}
  try { if (typeof diracV107NormalizeAction === 'function') return diracV107NormalizeAction(action); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(action); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_').slice(0, 120);
}

/* source 25056-25059 */
function diracBolaIdorV128LooksLikeUuid(value) {
  try { if (typeof customerSecurityLooksLikeUuid === 'function') return customerSecurityLooksLikeUuid(value); } catch (_) {}
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

/* source 25061-25071 */
function diracBolaIdorV128SafeDecode(value) {
  let out = String(value || '');
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(out);
      if (decoded === out) break;
      out = decoded;
    } catch (_) { break; }
  }
  return out;
}

/* source 25073-25079 */
function diracBolaIdorV128Hash(value) {
  try {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
  } catch (_) {
    return String(value || '').slice(0, 64);
  }
}

/* source 25081-25085 */
function diracBolaIdorV128BlockYears() {
  const raw = Number(process.env.DIRAC_BOLA_IDOR_BLOCK_YEARS || process.env.DIRAC_SQLMAP_BLOCK_YEARS || 10);
  if (!Number.isFinite(raw) || raw <= 0) return 10;
  return Math.min(Math.max(Math.trunc(raw), 1), 100);
}

/* source 25087-25095 */
function diracBolaIdorV128EnvTrue(name, fallback = false) {
  try { if (typeof diracBolaIdorV126EnvTrue === 'function') return diracBolaIdorV126EnvTrue(name, fallback); } catch (_) {}
  const raw = process.env[name];
  if (raw === undefined || raw === null || String(raw).trim() === '') return !!fallback;
  const value = String(raw).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on', 'block', 'enforce', 'strict'].includes(value)) return true;
  if (['0', 'false', 'no', 'off', 'monitor', 'disabled'].includes(value)) return false;
  return !!fallback;
}

/* source 25097-25118 */
function diracBolaIdorV128LogDecision(decision) {
  try {
    if (diracBolaIdorV128EnvTrue('DIRAC_BOLA_IDOR_GLOBAL_BAN_SILENT', false)) return;
    const key = [decision.source, decision.table, decision.method, decision.action, decision.reason].join('|');
    const current = Number(DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128.get('log:' + key) || 0);
    const max = Math.max(1, Number(process.env.DIRAC_BOLA_IDOR_GLOBAL_BAN_LOG_LIMIT || 5) || 5);
    if (current >= max) return;
    DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_STORE_V128.set('log:' + key, current + 1);
    console.warn('[dirac-bola-idor-global-hard-ban]', {
      patch: DIRAC_BOLA_IDOR_GLOBAL_HARD_BAN_PATCH_V128,
      mode: decision.block ? 'blocked_and_banned' : 'monitor',
      reason: decision.reason,
      source: decision.source || null,
      table: decision.table || null,
      method: decision.method || null,
      action: decision.action || null,
      requested_count: decision.requested_count || 0,
      foreign_count: decision.foreign_count || 0,
      allowed_count: decision.allowed_count || 0
    });
  } catch (_) {}
}

/* source 25558-25558 */
const DIRAC_AUTH_REGISTER_SAFE_BOLA_REPAIR_PATCH_V131 = 'auth-register-safe-bola-repair-v131';

/* source 25560-25563 */
function diracV131NormalizeAction(action) {
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(action); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 25597-25639 */
function readDiracSupabaseCredentials(targetKey) {
  const key = DIRAC_SUPABASE_TARGET_ENVS[targetKey] ? targetKey : 'legacy';
  const envs = DIRAC_SUPABASE_TARGET_ENVS[key];

  if (key === 'legacy') {
    return {
      targetKey: 'legacy',
      url: requiredEnv(envs.url).replace(/\/$/, ''),
      anonKey: requiredEnv(envs.anonKey),
      serviceKey: requiredEnv(envs.serviceKey),
      authRepairPatch: DIRAC_AUTH_REGISTER_SAFE_BOLA_REPAIR_PATCH_V131
    };
  }

  const url = String(process.env[envs.url] || '').trim();
  const anonKey = String(process.env[envs.anonKey] || '').trim();
  const serviceKey = String(process.env[envs.serviceKey] || '').trim();

  if (key === 'security' && (!url || !anonKey || !serviceKey)) {
    throw new Error(`Missing dedicated security Supabase ENV: ${envs.url}, ${envs.anonKey}, ${envs.serviceKey}`);
  }

  if (url && anonKey && serviceKey) {
    return {
      targetKey: key,
      url: url.replace(/\/$/, ''),
      anonKey,
      serviceKey,
      authRepairPatch: DIRAC_AUTH_REGISTER_SAFE_BOLA_REPAIR_PATCH_V131
    };
  }

  if (shouldUseStrictDiracMultiDbRouter()) {
    throw new Error(`Missing Supabase ENV for ${key}: ${envs.url}, ${envs.anonKey}, ${envs.serviceKey}`);
  }

  const legacy = DIRAC_SUPABASE_TARGET_ENVS.legacy;
  return {
    targetKey: 'legacy',
    requestedTargetKey: key,
    fallback: true,
    url: requiredEnv(legacy.url).replace(/\/$/, ''),
    anonKey: requiredEnv(legacy.anonKey),
    serviceKey: requiredEnv(legacy.serviceKey),
    authRepairPatch: DIRAC_AUTH_REGISTER_SAFE_BOLA_REPAIR_PATCH_V131
  };
}

/* source 25859-25864 */
function diracBolaIdorV132CurrentContext() {
  try { if (typeof diracBolaIdorV128CurrentContext === 'function') return diracBolaIdorV128CurrentContext(); } catch (_) {}
  try { if (typeof diracBolaIdorV126CurrentContext === 'function') return diracBolaIdorV126CurrentContext(); } catch (_) {}
  try { if (typeof diracBolaIdorV121CurrentContext === 'function') return diracBolaIdorV121CurrentContext(); } catch (_) {}
  return null;
}

/* source 25960-25972 */
function diracBolaIdorV132CollectIds(source, sourceName) {
  try { if (typeof diracBolaIdorV128CollectIds === 'function') return diracBolaIdorV128CollectIds(source, sourceName); } catch (_) {}
  const out = [];
  if (source && typeof source === 'object') {
    Object.entries(source).forEach(([key, value]) => {
      const cleanKey = diracBolaIdorV132NormalizeKey(key);
      if (cleanKey === 'action') return;
      if (!diracBolaIdorV132IsIdentifierKey(cleanKey)) return;
      diracBolaIdorV132ExtractPossibleValues(value).forEach((item) => out.push({ key: cleanKey, value: item, source: sourceName || 'unknown' }));
    });
  }
  return out.slice(0, 80);
}

/* source 26064-26068 */
function diracBolaIdorV132NormalizeAction(action) {
  try { if (typeof diracV131NormalizeAction === 'function') return diracV131NormalizeAction(action); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(action); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_').slice(0, 120);
}

/* source 26070-26072 */
function diracBolaIdorV132NormalizeKey(key) {
  return String(key || '').trim().replace(/[A-Z]/g, (m) => '_' + m.toLowerCase()).replace(/[-\s]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase();
}

/* source 26074-26076 */
function diracBolaIdorV132IsIdentifierKey(key) {
  return /^(id|customer_id|auth_user_id|user_id|owner_user_id|profile_id|account_id|order_id|domain_order_id|session_id|recovery_code_id|invoice_id|transaction_id|payment_transaction_id|gateway_reference)$/.test(String(key || '').toLowerCase());
}

/* source 26078-26083 */
function diracBolaIdorV132ExtractPossibleValues(value) {
  try { if (typeof diracBolaIdorV128ExtractPossibleValues === 'function') return diracBolaIdorV128ExtractPossibleValues(value); } catch (_) {}
  const raw = String(value || '').trim();
  if (!raw) return [];
  return Array.from(new Set(diracBolaIdorV132SafeDecode(raw).split(/[\s,|]+/).map((part) => part.replace(/^(?:eq|in|is)\./i, '').replace(/^\(/, '').replace(/\)$/, '').replace(/^['"]|['"]$/g, '').trim()).filter(Boolean))).slice(0, 20);
}

/* source 26090-26100 */
function diracBolaIdorV132SafeDecode(value) {
  let out = String(value || '');
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(out);
      if (decoded === out) break;
      out = decoded;
    } catch (_) { break; }
  }
  return out;
}

/* source 26166-26166 */
const DIRAC_BOLA_IDOR_CUSTOMER_LINK_HARD_BINDING_PATCH_V133 = 'dirac-bola-idor-customer-link-hard-binding-v135-pesanan-fast-safe';

/* source 26168-26168 */
let diracBolaIdorAsyncLocalV133 = null;

/* source 26211-26223 */
function diracBolaIdorV133BuildRequestContext(req) {
  const query = req && req.query && typeof req.query === 'object' ? req.query : {};
  const rawAction = String(query.action || '').trim();
  return {
    patch: DIRAC_BOLA_IDOR_CUSTOMER_LINK_HARD_BINDING_PATCH_V133,
    req,
    action: diracBolaIdorV133NormalizeAction(rawAction),
    method: String(req && req.method || 'GET').toUpperCase().slice(0, 12),
    ownerResolvedV133: null,
    allowedCustomerIdsV133: [],
    started_at: Date.now()
  };
}

/* source 26225-26237 */
function diracBolaIdorV133CurrentContext() {
  try {
    if (diracBolaIdorAsyncLocalV133 && typeof diracBolaIdorAsyncLocalV133.getStore === 'function') {
      const store = diracBolaIdorAsyncLocalV133.getStore();
      if (store && typeof store === 'object') return store;
    }
  } catch (_) {}
  try {
    const ctx132 = typeof diracBolaIdorV132CurrentContext === 'function' ? diracBolaIdorV132CurrentContext() : null;
    if (ctx132 && typeof ctx132 === 'object') return ctx132;
  } catch (_) {}
  return null;
}

/* source 26239-26282 */
async function diracBolaIdorV133InspectHttpRequest(req) {
  const method = String(req && req.method || 'GET').toUpperCase();
  const action = diracBolaIdorV133NormalizeAction(req && req.query && req.query.action || '');
  if (!diracBolaIdorV133ShouldProtectDataAction(action, method)) return { ok: true };

  // v134 compatibility repair:
  // Do not hard-fail normal dashboard/bootstrap reads before the original handler
  // can settle the customer auth link and protected session. Only resolve/require
  // owner at HTTP layer when the request itself carries an object/owner id.
  // Service-role Supabase queries below remain owner-bound for protected tables.
  const ids = diracBolaIdorV133CollectIds(req && req.query, 'query');
  if (!ids.length) return { ok: true };

  const owner = await diracBolaIdorV133ResolveStrictOwner(req).catch(() => null);
  if (!owner || !owner.ok || !diracBolaIdorV133LooksLikeUuid(owner.authUserId) || !Array.isArray(owner.customerIds) || !owner.customerIds.length) {
    const status = owner && owner.reason === 'auth_user_unavailable' ? 401 : 403;
    return diracBolaIdorV133Decision('active_customer_link_required_for_protected_object_request', { action, method, status });
  }

  const customerMismatch = diracBolaIdorV133FindCustomerMismatch(ids, owner.customerIds);
  if (customerMismatch) {
    return diracBolaIdorV133Decision('query_customer_id_not_bound_to_authenticated_owner', {
      action,
      method,
      source: 'query',
      requested_count: customerMismatch.requestedCount,
      allowed_count: owner.customerIds.length,
      status: 403
    });
  }

  const authMismatch = diracBolaIdorV133FindAuthUserMismatch(ids, owner.authUserId);
  if (authMismatch) {
    return diracBolaIdorV133Decision('query_auth_user_id_not_bound_to_authenticated_user', {
      action,
      method,
      source: 'query',
      requested_count: authMismatch.requestedCount,
      status: 403
    });
  }

  return { ok: true };
}

/* source 26416-26445 */
async function diracBolaIdorV133ResolveStrictOwner(req) {
  const ctx = diracBolaIdorV133CurrentContext();
  if (ctx && ctx.ownerResolvedV133) return ctx.ownerResolvedV133;

  if (typeof requireDomainUser !== 'function') return { ok: false, reason: 'auth_user_unavailable' };
  const fakeRes = diracBolaIdorV133FakeResponse();
  const user = await requireDomainUser(req || {}, fakeRes).catch(() => null);
  const authUserId = String(user && user.id || '').trim();
  if (!diracBolaIdorV133LooksLikeUuid(authUserId)) return { ok: false, reason: 'auth_user_unavailable' };

  const linkResult = await diracBolaIdorV133FetchValidAuthLinks(authUserId).catch(() => null);
  const rows = linkResult && linkResult.ok && Array.isArray(linkResult.data) ? linkResult.data : [];
  const validRows = rows.filter(diracBolaIdorV133IsValidActiveAuthLinkRow);
  const customerIds = Array.from(new Set(validRows
    .map((row) => String(row.customer_id || '').trim())
    .filter(diracBolaIdorV133LooksLikeUuid)));
  if (validRows.length === 0 || customerIds.length === 0) return { ok: false, reason: 'owner_unavailable' };
  if (validRows.length > 1 || customerIds.length > 1) return { ok: false, reason: 'owner_ambiguous' };

  const owner = { ok: true, authUserId, customerIds, source: 'security_customer_auth_links.v133.active_not_disabled_not_revoked' };
  if (ctx && typeof ctx === 'object') {
    ctx.ownerResolvedV133 = owner;
    ctx.allowedCustomerIdsV133 = customerIds;
    try {
      ctx.ownerResolvedV128 = ctx.ownerResolvedV128 || { ok: true, authUserId, customerIds };
      ctx.allowedCustomerIdsV128 = Array.from(new Set([...(ctx.allowedCustomerIdsV128 || []), ...customerIds])).slice(0, 25);
    } catch (_) {}
  }
  return owner;
}

/* source 26447-26472 */
async function diracBolaIdorV133FetchValidAuthLinks(authUserId) {
  const uid = String(authUserId || '').trim();
  if (!diracBolaIdorV133LooksLikeUuid(uid)) return { ok: false, status: 400, data: [] };

  const select = 'id,auth_user_id,customer_id,link_status,match_confidence,verified_at,disabled_at,revoked_at,updated_at';
  const path = '/rest/v1/security_customer_auth_links?select=' + encodeURIComponent(select) +
    '&auth_user_id=eq.' + encodeURIComponent(uid) +
    '&link_status=eq.active' +
    '&disabled_at=is.null' +
    '&revoked_at=is.null' +
    '&order=updated_at.desc&limit=2';

  const result = await diracBolaIdorV133DirectSupabaseServiceGet(path).catch(() => null);
  if (result && result.ok && Array.isArray(result.data)) {
    return { ok: true, status: result.status || 200, data: result.data.filter(diracBolaIdorV133IsValidActiveAuthLinkRow) };
  }

  // Fallback kompatibilitas: jangan rusak deployment lama bila kolom extended belum ada.
  if (typeof customerSecurityFetchAuthLink === 'function') {
    const fallback = await customerSecurityFetchAuthLink(uid).catch(() => null);
    if (fallback && fallback.ok && Array.isArray(fallback.data)) {
      return { ok: true, status: fallback.status || 200, data: fallback.data.filter(diracBolaIdorV133IsLegacyAcceptableAuthLinkRow) };
    }
  }
  return { ok: false, status: result && result.status || 500, data: [] };
}

/* source 26474-26483 */
function diracBolaIdorV133IsValidActiveAuthLinkRow(row) {
  if (!row || typeof row !== 'object') return false;
  if (String(row.link_status || '').toLowerCase() !== 'active') return false;
  if (row.disabled_at || row.revoked_at) return false;
  if (!diracBolaIdorV133LooksLikeUuid(row.auth_user_id)) return false;
  if (!diracBolaIdorV133LooksLikeUuid(row.customer_id)) return false;
  const confidence = String(row.match_confidence || '').toLowerCase();
  if (confidence && !/^(verified|trusted|system|high|exact)$/i.test(confidence)) return false;
  return true;
}

/* source 26485-26491 */
function diracBolaIdorV133IsLegacyAcceptableAuthLinkRow(row) {
  if (!row || typeof row !== 'object') return false;
  if (String(row.link_status || '').toLowerCase() !== 'active') return false;
  if (!diracBolaIdorV133LooksLikeUuid(row.auth_user_id)) return false;
  if (!diracBolaIdorV133LooksLikeUuid(row.customer_id)) return false;
  return true;
}

/* source 26493-26510 */
function diracBolaIdorV133ShouldProtectDataAction(action, method) {
  const clean = String(action || '').toLowerCase();
  const upper = String(method || 'GET').toUpperCase();
  if (!clean || upper === 'OPTIONS') return false;
  if (diracBolaIdorV133NeverTouchAction(clean)) return false;

  // v135 performance repair:
  // my_orders/pesanan is already hard-bound inside the original endpoint via
  // requireDomainDashboardAccess() -> myOrdersResolveOwner() -> customer_id=in.(server-resolved ids).
  // Running this outer service-role inspector on the same list endpoint added redundant
  // auth-link reads and parent-owner lookups for every order item batch, causing pesanan.html to feel slow.
  // Keep payment/login/logout/A2F/hash untouched and keep object-level protection for other protected actions.
  if (/^(my_orders|pesanan|pesanan_saya|customer_orders|orders_saya|my_invoices|invoice_saya)$/i.test(clean) && upper === 'GET') return false;

  if (/^(domain_dashboard_me|domain_orders)$/i.test(clean)) return true;
  if (/^customer_security_(status|overview|features_bundle_v2|features_bundle_v3|sessions|devices|events|blocks)$/i.test(clean) && upper === 'GET') return true;
  return false;
}

/* source 26512-26517 */
function diracBolaIdorV133NeverTouchAction(action) {
  const clean = String(action || '').toLowerCase();
  if (/login|register|logout|payment|pay|midtrans|ipaymu|webhook|callback|notification|checkout|mfa|a2f|passkey|password|hash|email|mail|csrf|token/i.test(clean)) return true;
  if (/^(create_payment|pay_order|order_payment|create_payment_order|domain_checkout|domain_check|domain_health|hostinger_check|order_mail_health|order_email_health)$/i.test(clean)) return true;
  return false;
}

/* source 26534-26545 */
function diracBolaIdorV133CollectIds(source, sourceName) {
  try { if (typeof diracBolaIdorV132CollectIds === 'function') return diracBolaIdorV132CollectIds(source, sourceName); } catch (_) {}
  const out = [];
  if (source && typeof source === 'object') {
    Object.entries(source).forEach(([key, value]) => {
      const cleanKey = diracBolaIdorV133NormalizeKey(key);
      if (cleanKey === 'action' || !diracBolaIdorV133IsIdentifierKey(cleanKey)) return;
      diracBolaIdorV133ExtractPossibleValues(value).forEach((item) => out.push({ key: cleanKey, value: item, source: sourceName || 'unknown' }));
    });
  }
  return out.slice(0, 80);
}

/* source 26557-26566 */
function diracBolaIdorV133FindCustomerMismatch(ids, allowedCustomerIds) {
  const allowed = new Set((allowedCustomerIds || []).filter(diracBolaIdorV133LooksLikeUuid));
  if (!allowed.size) return null;
  const requested = (ids || [])
    .filter((item) => item && item.key === 'customer_id')
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV133LooksLikeUuid);
  const denied = requested.filter((id) => !allowed.has(id));
  return denied.length ? { requestedCount: requested.length, denied } : null;
}

/* source 26568-26577 */
function diracBolaIdorV133FindAuthUserMismatch(ids, authUserId) {
  const expected = String(authUserId || '').trim();
  if (!diracBolaIdorV133LooksLikeUuid(expected)) return null;
  const requested = (ids || [])
    .filter((item) => item && /^(auth_user_id|user_id|owner_user_id)$/i.test(item.key))
    .map((item) => String(item.value || '').trim())
    .filter(diracBolaIdorV133LooksLikeUuid);
  const denied = requested.filter((id) => id !== expected);
  return denied.length ? { requestedCount: requested.length, denied } : null;
}

/* source 26694-26697 */
function diracBolaIdorV133DirectSupabaseServiceGet(path) {
  if (typeof diracBolaIdorV128DirectSupabaseServiceGet === 'function') return diracBolaIdorV128DirectSupabaseServiceGet(path);
  return Promise.resolve({ ok: false, status: 0, data: null });
}

/* source 26699-26710 */
function diracBolaIdorV133FakeResponse() {
  const headers = {};
  return {
    statusCode: 200,
    headers,
    setHeader(name, value) { headers[String(name).toLowerCase()] = value; return this; },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    status(code) { this.statusCode = Number(code || 200); return this; },
    json(payload) { this.payload = payload; return this; },
    end() { return this; }
  };
}

/* source 26712-26716 */
function diracBolaIdorV133NormalizeAction(action) {
  try { if (typeof diracBolaIdorV132NormalizeAction === 'function') return diracBolaIdorV132NormalizeAction(action); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(action); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_').slice(0, 120);
}

/* source 26718-26720 */
function diracBolaIdorV133NormalizeKey(key) {
  return String(key || '').trim().replace(/[A-Z]/g, (m) => '_' + m.toLowerCase()).replace(/[-\s]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase();
}

/* source 26722-26724 */
function diracBolaIdorV133IsIdentifierKey(key) {
  return /^(id|customer_id|auth_user_id|user_id|owner_user_id|profile_id|account_id|order_id|domain_order_id|session_id|recovery_code_id|invoice_id|transaction_id|payment_transaction_id|gateway_reference)$/.test(String(key || '').toLowerCase());
}

/* source 26726-26730 */
function diracBolaIdorV133ExtractPossibleValues(value) {
  const raw = String(value || '').trim();
  if (!raw) return [];
  return Array.from(new Set(diracBolaIdorV133SafeDecode(raw).split(/[\s,|]+/).map((part) => part.replace(/^(?:eq|in|is)\./i, '').replace(/^\(/, '').replace(/\)$/, '').replace(/^[`'\"]|[`'\"]$/g, '').trim()).filter(Boolean))).slice(0, 20);
}

/* source 26732-26735 */
function diracBolaIdorV133LooksLikeUuid(value) {
  try { if (typeof customerSecurityLooksLikeUuid === 'function') return customerSecurityLooksLikeUuid(value); } catch (_) {}
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

/* source 26737-26747 */
function diracBolaIdorV133SafeDecode(value) {
  let out = String(value || '');
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(out);
      if (decoded === out) break;
      out = decoded;
    } catch (_) { break; }
  }
  return out;
}

/* source 26749-26757 */
function diracBolaIdorV133Decision(reason, extra = {}) {
  return {
    ok: false,
    block: true,
    reason: diracBolaIdorV133Small(reason || 'bola_idor_customer_link_binding_blocked', 120),
    patch: DIRAC_BOLA_IDOR_CUSTOMER_LINK_HARD_BINDING_PATCH_V133,
    ...extra
  };
}

/* source 26782-26794 */
function diracBolaIdorV133BlockedHttpResponse(res, decision) {
  try { if (typeof diracApplySecurityResponseHeaders === 'function') diracApplySecurityResponseHeaders(res); } catch (_) {}
  try { if (res && typeof res.setHeader === 'function') res.setHeader('Cache-Control', 'no-store'); } catch (_) {}
  const status = Number(decision && decision.status || 403);
  return res.status(status >= 400 && status <= 599 ? status : 403).json({
    ok: false,
    code: 'BOLA_IDOR_CUSTOMER_LINK_BINDING_BLOCKED',
    message: status === 401 ? 'Sesi tidak valid. Silakan login ulang.' : 'Akses ditolak oleh sistem keamanan.',
    ownership_locked: true,
    source: DIRAC_BOLA_IDOR_CUSTOMER_LINK_HARD_BINDING_PATCH_V133,
    reason: diracBolaIdorV133Small(decision && decision.reason || 'BOLA_IDOR_BLOCKED', 120)
  });
}

/* source 26796-26798 */
function diracBolaIdorV133Small(value, max) {
  return String(value || '').replace(/[\u0000-\u001f\u007f<>]/g, '').slice(0, Math.max(1, Number(max || 120)));
}

/* source 27032-27032 */
const DIRAC_CSRF_ALL_WEBSITE_ACTIONS_SAFE_V137 = 'dirac-csrf-all-website-actions-safe-v137';

/* source 27076-27085 */
function diracV137CsrfShouldForce(action, method) {
  const verb = String(method || '').toUpperCase();
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(verb)) return false;
  const clean = diracV137CsrfNormalizeAction(action);
  if (!clean) return false;
  if (diracV137CsrfNeverTouchAction(clean)) return false;
  if (diracV137CsrfServerOnlyAction(clean)) return false;
  if (diracV137CsrfExplicitlyDisabled(clean)) return false;
  return true;
}

/* source 27087-27105 */
function diracV137CsrfNeverTouchAction(action) {
  const clean = diracV137CsrfNormalizeAction(action);
  if (!clean) return true;

  // Bagian yang user minta tidak disentuh dan/atau harus tetap bisa berjalan
  // tanpa token browser: login/register/logout, MFA/A2F/passkey, payment gateway,
  // webhook/callback/notification, email/mail, hash/password core.
  if (clean === 'domain_login' || clean === 'domain_register' || clean === 'domain_logout') return true;
  if (/mfa|a2f|passkey|webauthn|otp|totp/i.test(clean)) return true;
  if (/payment_gateway|midtrans|ipaymu|webhook|callback|notification/i.test(clean)) return true;
  if (/email_template|mail_template|smtp|mailer/i.test(clean)) return true;
  if (/password_hash|argon|bcrypt|scrypt|pepper|hash_core/i.test(clean)) return true;

  // Aksi bayar/create_payment dibiarkan oleh patch ini karena berada di area
  // payment yang user larang disentuh. Origin guard lama tetap melindungi.
  if (clean === 'create_payment' || clean === 'pay_order' || clean === 'order_payment' || clean === 'checkout_payment' || clean === 'bayar_pesanan') return true;

  return false;
}

/* source 27107-27119 */
function diracV137CsrfServerOnlyAction(action) {
  const clean = diracV137CsrfNormalizeAction(action);
  return clean === 'domain_health'
    || clean === 'hostinger_check'
    || clean === 'domain_check'
    || clean === 'domain_me'
    || clean === 'domain_dashboard_me'
    || clean === 'domain_mfa_status'
    || clean === 'domain_orders'
    || clean === 'my_orders'
    || clean === 'pesanan_saya'
    || clean === 'get_orders';
}

/* source 27121-27125 */
function diracV137CsrfExplicitlyDisabled(action) {
  if (diracV137CsrfEnvTrue('DIRAC_CSRF_ALL_WEBSITE_ACTIONS_DISABLED')) return true;
  const key = 'DIRAC_CSRF_ALL_DISABLED_' + String(action || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  return diracV137CsrfEnvTrue(key);
}

/* source 27127-27175 */
function diracV137CsrfForceVerify(req, action) {
  const secret = typeof diracCsrfSecret === 'function' ? String(diracCsrfSecret() || '').trim() : '';
  if (!secret) return { ok: false, status: 503, code: 'CSRF_SECRET_MISSING' };

  const headers = (req && req.headers) || {};
  const headerToken = String(
    headers['x-csrf-token'] ||
    headers['X-CSRF-Token'] ||
    headers['x-dirac-csrf-token'] ||
    headers['X-Dirac-CSRF-Token'] ||
    ''
  ).trim();

  const cookies = typeof parseCookies === 'function' ? parseCookies(req) : {};
  const cookieName = typeof DIRAC_CSRF_COOKIE !== 'undefined' ? DIRAC_CSRF_COOKIE : '__Host-dirac_csrf_hmac';
  const cookieToken = String(cookies[cookieName] || '').trim();

  if (!headerToken) return { ok: false, status: 403, code: 'CSRF_HEADER_MISSING' };
  if (!cookieToken) return { ok: false, status: 403, code: 'CSRF_COOKIE_MISSING' };
  if (typeof safeEqual === 'function') {
    if (!safeEqual(headerToken, cookieToken)) return { ok: false, status: 403, code: 'CSRF_DOUBLE_SUBMIT_MISMATCH' };
  } else if (headerToken !== cookieToken) {
    return { ok: false, status: 403, code: 'CSRF_DOUBLE_SUBMIT_MISMATCH' };
  }

  const decoded = typeof diracCsrfDecodeToken === 'function' ? diracCsrfDecodeToken(headerToken, secret) : null;
  if (!decoded || !decoded.payload) return { ok: false, status: 403, code: 'CSRF_SIGNATURE_INVALID' };

  const payload = decoded.payload || {};
  const now = Math.floor(Date.now() / 1000);
  const expectedType = typeof DIRAC_CSRF_TOKEN_TYPE !== 'undefined' ? DIRAC_CSRF_TOKEN_TYPE : 'dirac-csrf-hmac-v1';
  const skew = typeof DIRAC_CSRF_CLOCK_SKEW_SECONDS !== 'undefined' ? Number(DIRAC_CSRF_CLOCK_SKEW_SECONDS) : 60;

  if (payload.typ !== expectedType) return { ok: false, status: 403, code: 'CSRF_TOKEN_TYPE_INVALID' };
  if (!payload.exp || Number(payload.exp) + skew < now) return { ok: false, status: 403, code: 'CSRF_TOKEN_EXPIRED' };
  if (payload.iat && Number(payload.iat) - skew > now) return { ok: false, status: 403, code: 'CSRF_TOKEN_IAT_INVALID' };

  try {
    const binding = typeof diracCsrfRequestBinding === 'function' ? diracCsrfRequestBinding(req) : null;
    if (binding && payload.sid && binding.sid && typeof safeEqual === 'function' && !safeEqual(String(payload.sid), String(binding.sid))) {
      return { ok: false, status: 403, code: 'CSRF_SESSION_BINDING_MISMATCH' };
    }
    if (binding && payload.oh && binding.oh && typeof safeEqual === 'function' && !safeEqual(String(payload.oh), String(binding.oh))) {
      return { ok: false, status: 403, code: 'CSRF_ORIGIN_BINDING_MISMATCH' };
    }
  } catch (_) {}

  return { ok: true, source: 'csrf_all_website_valid' };
}

/* source 27177-27182 */
function diracV137CsrfNormalizeAction(action) {
  const raw = String(action || '').trim();
  try { if (typeof diracCsrfNormalizeAction === 'function') return diracCsrfNormalizeAction(raw); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(raw); } catch (_) {}
  return raw.toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 27184-27189 */
function diracV137CsrfApplyHeaders(res) {
  if (!res || typeof res.setHeader !== 'function') return;
  try { res.setHeader('X-Dirac-CSRF-All-Website-Actions', DIRAC_CSRF_ALL_WEBSITE_ACTIONS_SAFE_V137); } catch (_) {}
  try { res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0'); } catch (_) {}
  try { if (typeof diracApplySecurityResponseHeaders === 'function') diracApplySecurityResponseHeaders(res); } catch (_) {}
}

/* source 27191-27193 */
function diracV137CsrfEnvTrue(name) {
  return String(process.env[name] || '').trim().toLowerCase() === 'true';
}

/* source 27195-27199 */
function diracV137CsrfSafeError(error) {
  const message = String(error && error.message ? error.message : error || 'unknown').slice(0, 160);
  if (/password|token|secret|cookie|authorization|service_role|apikey|csrf|hmac|hash/i.test(message)) return 'csrf_internal_error';
  return message;
}

/* source 27214-27214 */
const DIRAC_CSRF_EVERY_BROWSER_ACTION_STRICT_SAFE_V138 = 'dirac-csrf-every-browser-action-strict-safe-v138';

/* source 27261-27269 */
function diracV138CsrfShouldForce(action, method) {
  const verb = String(method || '').toUpperCase();
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(verb)) return false;
  const clean = diracV138CsrfNormalizeAction(action);
  if (!clean) return false;
  if (diracV138CsrfExternalServerToServerAction(clean)) return false;
  if (diracV138CsrfExplicitlyDisabled(clean)) return false;
  return true;
}

/* source 27271-27282 */
function diracV138CsrfExternalServerToServerAction(action) {
  const clean = diracV138CsrfNormalizeAction(action);
  if (!clean) return false;

  // Hanya callback/notifikasi/webhook eksternal. Ini bukan aksi browser user,
  // sehingga CSRF browser memang tidak berlaku. Signature payment gateway lama
  // tetap menjadi kontrol yang benar untuk jalur ini.
  if (/webhook|callback|notification/i.test(clean)) return true;
  if (/midtrans.*(?:notify|notif|webhook|callback)|ipaymu.*(?:notify|notif|webhook|callback)/i.test(clean)) return true;

  return false;
}

/* source 27284-27289 */
function diracV138CsrfExplicitlyDisabled(action) {
  // Tidak menyediakan global kill-switch baru. Hanya emergency per-action agar
  // produksi bisa rollback satu aksi spesifik tanpa menurunkan semua keamanan.
  const key = 'DIRAC_CSRF_EVERY_BROWSER_DISABLED_' + String(action || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  return diracV138CsrfEnvTrue(key);
}

/* source 27291-27340 */
function diracV138CsrfForceVerify(req, action) {
  const secret = typeof diracCsrfSecret === 'function' ? String(diracCsrfSecret() || '').trim() : '';
  if (!secret) return { ok: false, status: 503, code: 'CSRF_SECRET_MISSING' };

  const headers = (req && req.headers) || {};
  const headerToken = String(
    headers['x-csrf-token'] ||
    headers['X-CSRF-Token'] ||
    headers['x-dirac-csrf-token'] ||
    headers['X-Dirac-CSRF-Token'] ||
    ''
  ).trim();

  const cookies = typeof parseCookies === 'function' ? parseCookies(req) : {};
  const cookieName = typeof DIRAC_CSRF_COOKIE !== 'undefined' ? DIRAC_CSRF_COOKIE : '__Host-dirac_csrf_hmac';
  const cookieToken = String(cookies[cookieName] || '').trim();

  if (!headerToken) return { ok: false, status: 403, code: 'CSRF_HEADER_MISSING' };
  if (!cookieToken) return { ok: false, status: 403, code: 'CSRF_COOKIE_MISSING' };

  if (typeof safeEqual === 'function') {
    if (!safeEqual(headerToken, cookieToken)) return { ok: false, status: 403, code: 'CSRF_DOUBLE_SUBMIT_MISMATCH' };
  } else if (headerToken !== cookieToken) {
    return { ok: false, status: 403, code: 'CSRF_DOUBLE_SUBMIT_MISMATCH' };
  }

  const decoded = typeof diracCsrfDecodeToken === 'function' ? diracCsrfDecodeToken(headerToken, secret) : null;
  if (!decoded || !decoded.payload) return { ok: false, status: 403, code: 'CSRF_SIGNATURE_INVALID' };

  const payload = decoded.payload || {};
  const now = Math.floor(Date.now() / 1000);
  const expectedType = typeof DIRAC_CSRF_TOKEN_TYPE !== 'undefined' ? DIRAC_CSRF_TOKEN_TYPE : 'dirac-csrf-hmac-v1';
  const skew = typeof DIRAC_CSRF_CLOCK_SKEW_SECONDS !== 'undefined' ? Number(DIRAC_CSRF_CLOCK_SKEW_SECONDS) : 60;

  if (payload.typ !== expectedType) return { ok: false, status: 403, code: 'CSRF_TOKEN_TYPE_INVALID' };
  if (!payload.exp || Number(payload.exp) + skew < now) return { ok: false, status: 403, code: 'CSRF_TOKEN_EXPIRED' };
  if (payload.iat && Number(payload.iat) - skew > now) return { ok: false, status: 403, code: 'CSRF_TOKEN_IAT_INVALID' };

  try {
    const binding = typeof diracCsrfRequestBinding === 'function' ? diracCsrfRequestBinding(req) : null;
    if (binding && payload.sid && binding.sid && typeof safeEqual === 'function' && !safeEqual(String(payload.sid), String(binding.sid))) {
      return { ok: false, status: 403, code: 'CSRF_SESSION_BINDING_MISMATCH' };
    }
    if (binding && payload.oh && binding.oh && typeof safeEqual === 'function' && !safeEqual(String(payload.oh), String(binding.oh))) {
      return { ok: false, status: 403, code: 'CSRF_ORIGIN_BINDING_MISMATCH' };
    }
  } catch (_) {}

  return { ok: true, source: 'csrf_every_browser_action_valid' };
}

/* source 27342-27347 */
function diracV138CsrfNormalizeAction(action) {
  const raw = String(action || '').trim();
  try { if (typeof diracCsrfNormalizeAction === 'function') return diracCsrfNormalizeAction(raw); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(raw); } catch (_) {}
  return raw.toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 27349-27354 */
function diracV138CsrfApplyHeaders(res) {
  if (!res || typeof res.setHeader !== 'function') return;
  try { res.setHeader('X-Dirac-CSRF-Every-Browser-Action', DIRAC_CSRF_EVERY_BROWSER_ACTION_STRICT_SAFE_V138); } catch (_) {}
  try { res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0'); } catch (_) {}
  try { if (typeof diracApplySecurityResponseHeaders === 'function') diracApplySecurityResponseHeaders(res); } catch (_) {}
}

/* source 27356-27358 */
function diracV138CsrfEnvTrue(name) {
  return String(process.env[name] || '').trim().toLowerCase() === 'true';
}

/* source 27360-27364 */
function diracV138CsrfSafeError(error) {
  const message = String(error && error.message ? error.message : error || 'unknown').slice(0, 160);
  if (/password|token|secret|cookie|authorization|service_role|apikey|csrf|hmac|hash/i.test(message)) return 'csrf_internal_error';
  return message;
}

/* source 27457-27462 */
function diracV141NormalizeAction(action) {
  try { if (typeof diracV138CsrfNormalizeAction === 'function') return diracV138CsrfNormalizeAction(String(action || '')); } catch (_) {}
  try { if (typeof diracCsrfNormalizeAction === 'function') return diracCsrfNormalizeAction(String(action || '')); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(String(action || '')); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 27559-27565 */
function diracV142NormalizeAction(action) {
  try { if (typeof diracV141NormalizeAction === 'function') return diracV141NormalizeAction(String(action || '')); } catch (_) {}
  try { if (typeof diracV138CsrfNormalizeAction === 'function') return diracV138CsrfNormalizeAction(String(action || '')); } catch (_) {}
  try { if (typeof diracCsrfNormalizeAction === 'function') return diracCsrfNormalizeAction(String(action || '')); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(String(action || '')); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 27581-27581 */
const DIRAC_GLOBAL_API_THREAT_GUARD_V143 = 'dirac-global-api-threat-guard-v143';

/* source 27582-27582 */
const DIRAC_GLOBAL_API_THREAT_STORE_V143 = globalThis.__DIRAC_GLOBAL_API_THREAT_STORE_V143__ || new Map();

/* source 27583-27583 */
globalThis.__DIRAC_GLOBAL_API_THREAT_STORE_V143__ = DIRAC_GLOBAL_API_THREAT_STORE_V143;

/* source 27689-27730 */
function diracV143DetectRequestThreat(req, action, method) {
  if (diracV143EnvTrue('DIRAC_GLOBAL_API_THREAT_GUARD_DISABLED')) return { detected: false };
  if (String(method || '').toUpperCase() === 'OPTIONS') return { detected: false };

  const headers = (req && req.headers) || {};
  const ua = String(headers['user-agent'] || headers['User-Agent'] || '').slice(0, 700);
  const scanner = diracV143DetectScanner(ua);
  if (scanner.detected) return scanner;

  const methodThreat = diracV143DetectMethod(method);
  if (methodThreat.detected) return methodThreat;

  const originThreat = diracV143DetectOriginThreat(req, action, method);
  if (originThreat.detected) return originThreat;

  const samples = [];
  diracV143PushSamples(samples, action);
  diracV143PushSamples(samples, method);
  diracV143PushSamples(samples, req && req.url);

  const query = (req && req.query) || {};
  if (query && typeof query === 'object') {
    Object.entries(query).forEach(([key, value]) => {
      diracV143PushSamples(samples, key);
      if (Array.isArray(value)) value.forEach((item) => diracV143PushSamples(samples, item));
      else diracV143PushSamples(samples, value);
    });
  }

  [
    headers.host,
    headers['x-forwarded-host'],
    headers.origin,
    headers.referer,
    headers.referrer,
    headers['sec-fetch-site'],
    headers['sec-fetch-mode'],
    headers['content-type']
  ].forEach((value) => diracV143PushSamples(samples, value));

  return diracV143FindThreat(samples, 'request');
}

/* source 27738-27776 */
function diracV143FindThreat(values, source) {
  const samples = [];
  for (const value of values || []) {
    diracV143ExpandedSamples(value).forEach((sample) => samples.push(sample));
  }

  const patterns = [
    { kind: 'sqlmap_marker', risk: 'critical', pattern: /\b(?:sqlmap|sqlmapoutput|sqlmapproject)\b/i },
    { kind: 'sql_union_select', risk: 'critical', pattern: /\bunion\s+(?:all\s+)?select\b/i },
    { kind: 'sql_boolean_bypass', risk: 'critical', pattern: /(?:^|[\s'"`)(])(?:or|and)\s+(?:1\s*=\s*1|true\s*=\s*true)(?:$|[\s'"`)(])/i },
    { kind: 'sql_time_based', risk: 'critical', pattern: /\b(?:pg_sleep|sleep|benchmark|waitfor\s+delay)\s*\(?/i },
    { kind: 'sql_schema_probe', risk: 'critical', pattern: /\b(?:information_schema|pg_catalog|sqlite_master|mysql\.user|sysobjects|syscolumns)\b/i },
    { kind: 'sql_dangerous_function', risk: 'critical', pattern: /\b(?:load_file|into\s+outfile|xp_cmdshell|utl_http|dbms_pipe|extractvalue|updatexml)\b/i },
    { kind: 'sql_stacked_statement', risk: 'critical', pattern: /;\s*(?:select|insert|update|delete|drop|alter|truncate|create|grant|revoke|execute)\b/i },
    { kind: 'xss_script_tag', risk: 'critical', pattern: /<\s*script\b/i },
    { kind: 'xss_event_handler', risk: 'critical', pattern: /\bon[a-z]{3,30}\s*=/i },
    { kind: 'xss_javascript_uri', risk: 'critical', pattern: /\bjavascript\s*:/i },
    { kind: 'xss_svg_html_payload', risk: 'high', pattern: /<\s*(?:svg|iframe|object|embed|img|video|body|meta|link)\b/i },
    { kind: 'path_traversal', risk: 'critical', pattern: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f)/i },
    { kind: 'command_injection', risk: 'critical', pattern: /(?:^|[\s;&|`$()])(?:curl|wget|bash|sh|cmd|powershell|pwsh|nc|netcat|perl|python|php|ruby)\b/i },
    { kind: 'command_separator', risk: 'high', pattern: /(?:;|\|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|env|printenv|chmod|chown|rm|mv|cp)\b/i },
    { kind: 'ssrf_private_url', risk: 'critical', pattern: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.169\.254|\[?::1\]?)/i },
    { kind: 'ssrf_file_scheme', risk: 'critical', pattern: /\b(?:file|gopher|dict|ftp|ldap):\/\//i },
    { kind: 'prototype_pollution', risk: 'critical', pattern: /(?:^|[?&.\[\]"'])__(?:proto)__|(?:constructor|prototype)\s*(?:\[|\.|=|:)/i },
    { kind: 'sql_comment_probe', risk: 'high', pattern: /(?:--\s|#\s|\/\*|\*\/)/i }
  ];

  for (const sample of samples) {
    const text = String(sample || '').slice(0, 3000);
    if (!text) continue;
    for (const item of patterns) {
      if (item.pattern.test(text)) {
        return { detected: true, kind: item.kind, source, risk: item.risk, status: 403 };
      }
    }
  }

  return { detected: false };
}

/* source 27778-27785 */
function diracV143DetectScanner(userAgent) {
  const ua = String(userAgent || '').toLowerCase();
  if (!ua) return { detected: true, kind: 'missing_user_agent', source: 'header', risk: 'high', status: 403 };
  if (/\b(?:sqlmap|havij|acunetix|netsparker|nikto|w3af|nessus|openvas|nuclei|masscan|zgrab|dirbuster|dirb|gobuster|ffuf|whatweb|jaeles|commix|arachni|skipfish|appscan|webinspect|burp\s*suite|portswigger|owasp\s*zap|zap\s*scanner|postmanruntime|python-requests|httpie|curl|wget|libwww-perl|go-http-client|java\/|okhttp|axios|node-fetch)\b/i.test(ua)) {
    return { detected: true, kind: 'non_browser_or_scanner_user_agent', source: 'user_agent', risk: 'critical', status: 403 };
  }
  return { detected: false };
}

/* source 27787-27793 */
function diracV143DetectMethod(method) {
  const clean = String(method || '').toUpperCase();
  if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(clean)) {
    return { detected: true, kind: 'method_not_allowed_global_guard', source: 'method', risk: 'high', status: 403 };
  }
  return { detected: false };
}

/* source 27795-27816 */
function diracV143DetectOriginThreat(req, action, method) {
  const cleanAction = diracV143NormalizeAction(action);
  const cleanMethod = String(method || '').toUpperCase();
  if (diracV143ServerOnlyAction(cleanAction)) return { detected: false };

  const headers = (req && req.headers) || {};
  const origin = diracV143NormalizeOrigin(headers.origin || headers.Origin || '');
  const refererOrigin = diracV143NormalizeOrigin(headers.referer || headers.Referer || headers.referrer || '');
  const effectiveOrigin = origin || refererOrigin;
  const allowed = diracV143AllowedOrigins();

  if (effectiveOrigin && !allowed.has(effectiveOrigin)) {
    return { detected: true, kind: 'origin_not_allowed', source: 'origin', risk: 'critical', status: 403 };
  }

  const secFetchSite = String(headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite === 'cross-site' && cleanMethod !== 'GET' && cleanMethod !== 'HEAD') {
    return { detected: true, kind: 'cross_site_unsafe_request', source: 'sec_fetch', risk: 'critical', status: 403 };
  }

  return { detected: false };
}

/* source 27818-27849 */
async function diracV143InspectOwnership(req, body) {
  const action = diracV143NormalizeAction((req && req.query && req.query.action) || (body && (body.action || body.mode)) || '');
  const method = String((req && req.method) || 'GET').toUpperCase();
  if (diracV143NeverTouchAction(action) || diracV143ServerOnlyAction(action) || method === 'OPTIONS') return { ok: true };

  const ids = diracV143CollectRequestIds(req, body);
  if (!ids.length) return { ok: true };

  const owner = await diracV143ResolveOwner(req).catch(() => null);
  if (!owner || !owner.ok || !Array.isArray(owner.customerIds) || !owner.customerIds.length) {
    return { ok: true };
  }

  const allowed = new Set(owner.customerIds.map((id) => String(id || '').trim()).filter(diracV143LooksLikeUuid));
  if (!allowed.size) return { ok: true };

  const requestedCustomers = ids
    .filter((item) => item && item.key === 'customer_id')
    .map((item) => String(item.value || '').trim())
    .filter(diracV143LooksLikeUuid);
  if (requestedCustomers.some((id) => !allowed.has(id))) {
    return { ok: false, block: true, reason: 'frontend_customer_id_not_bound_to_session', source: 'customer_id' };
  }

  const ownerRows = await diracV143ResolveOwnerRowsForIds(ids).catch(() => []);
  const foreign = ownerRows.filter((row) => row && row.customer_id && !allowed.has(String(row.customer_id)));
  if (foreign.length) {
    return { ok: false, block: true, reason: 'requested_object_not_owned_by_session', source: 'object_owner_lookup' };
  }

  return { ok: true };
}

/* source 27851-27874 */
async function diracV143ResolveOwner(req) {
  try {
    if (typeof diracBolaIdorV133ResolveStrictOwner === 'function') {
      const owner = await diracBolaIdorV133ResolveStrictOwner(req);
      if (owner && owner.ok) return owner;
    }
  } catch (_) {}

  if (typeof requireDomainUser !== 'function' || typeof customerSecurityFetchAuthLink !== 'function') return { ok: false };
  const fakeRes = typeof diracBolaIdorV133FakeResponse === 'function'
    ? diracBolaIdorV133FakeResponse()
    : { status() { return this; }, json() { return this; }, end() { return this; }, setHeader() {} };
  const user = await requireDomainUser(req, fakeRes).catch(() => null);
  const authUserId = String(user && user.id || '').trim();
  if (!diracV143LooksLikeUuid(authUserId)) return { ok: false };

  const linkResult = await customerSecurityFetchAuthLink(authUserId).catch(() => null);
  const rows = linkResult && linkResult.ok && Array.isArray(linkResult.data) ? linkResult.data : [];
  const customerIds = Array.from(new Set(rows
    .filter((row) => row && String(row.link_status || '').toLowerCase() === 'active')
    .map((row) => String(row.customer_id || '').trim())
    .filter(diracV143LooksLikeUuid))).slice(0, 25);
  return { ok: true, authUserId, customerIds, source: 'security_customer_auth_links.v143' };
}

/* source 27876-27886 */
async function diracV143ResolveOwnerRowsForIds(ids) {
  const rows = [];
  const orderIds = diracV143ValuesForKeys(ids, /^(order_id|order_code|id)$/i);
  const domainOrderIds = diracV143ValuesForKeys(ids, /^(domain_order_id|domain_order_code)$/i);
  const paymentIds = diracV143ValuesForKeys(ids, /^(payment_id|payment_transaction_id|transaction_id|gateway_reference|invoice_id)$/i);

  rows.push(...await diracV143FetchOwnerRows('orders', orderIds, ['id', 'order_id']).catch(() => []));
  rows.push(...await diracV143FetchOwnerRows('domain_orders', orderIds.concat(domainOrderIds), ['id']).catch(() => []));
  rows.push(...await diracV143FetchOwnerRows('payment_transactions', paymentIds, ['id', 'gateway_reference']).catch(() => []));
  return rows.slice(0, 120);
}

/* source 27888-27923 */
async function diracV143FetchOwnerRows(table, values, columns) {
  const safeTable = String(table || '').trim();
  const cleanValues = Array.from(new Set((values || []).map((item) => String(item || '').trim()).filter(Boolean))).slice(0, 30);
  const safeColumns = (columns || []).map((item) => String(item || '').trim()).filter((item) => /^[a-zA-Z0-9_]+$/.test(item)).slice(0, 3);
  if (!/^[a-zA-Z0-9_]+$/.test(safeTable) || !cleanValues.length || !safeColumns.length) return [];

  const select = table === 'payment_transactions'
    ? 'id,customer_id,order_id,domain_order_id,gateway_reference'
    : 'id,customer_id,order_id';
  const clauses = [];
  for (const column of safeColumns) {
    for (const value of cleanValues) {
      if (!diracV143SafeRestEqValue(value)) continue;
      clauses.push(column + '.eq.' + value);
    }
  }
  if (!clauses.length) return [];

  const path = '/rest/v1/' + encodeURIComponent(safeTable) +
    '?select=' + encodeURIComponent(select) +
    '&or=' + encodeURIComponent('(' + clauses.slice(0, 50).join(',') + ')') +
    '&limit=50';

  const result = await diracV143DirectSupabaseGet(path).catch(() => null);
  if (!result || !result.ok || !Array.isArray(result.data)) return [];
  return result.data
    .filter((row) => row && diracV143LooksLikeUuid(row.customer_id))
    .map((row) => ({
      table: safeTable,
      id: String(row.id || ''),
      customer_id: String(row.customer_id || ''),
      order_id: String(row.order_id || ''),
      domain_order_id: String(row.domain_order_id || ''),
      gateway_reference: String(row.gateway_reference || '')
    }));
}

/* source 27925-27933 */
function diracV143DirectSupabaseGet(path) {
  if (typeof diracBolaIdorV128DirectSupabaseServiceGet === 'function') {
    return diracBolaIdorV128DirectSupabaseServiceGet(path);
  }
  if (typeof diracBolaIdorV133DirectSupabaseServiceGet === 'function') {
    return diracBolaIdorV133DirectSupabaseServiceGet(path);
  }
  return Promise.resolve({ ok: false, status: 0, data: null });
}

/* source 27935-27952 */
function diracV143CollectRequestIds(req, body) {
  const out = [];
  const push = (key, value, source) => {
    const cleanKey = diracV143NormalizeKey(key);
    if (!diracV143IsTrackedIdKey(cleanKey)) return;
    diracV143ExtractValues(value).forEach((item) => out.push({ key: cleanKey, value: item, source }));
  };

  const query = (req && req.query) || {};
  if (query && typeof query === 'object') {
    Object.entries(query).forEach(([key, value]) => {
      if (key === 'action') return;
      push(key, value, 'query');
    });
  }
  diracV143WalkObjectIds(body, push, 'body', 0);
  return out.filter((item) => item && item.value).slice(0, 100);
}

/* source 27954-27964 */
function diracV143WalkObjectIds(value, push, source, depth) {
  if (!value || typeof value !== 'object' || depth > 5) return;
  if (Array.isArray(value)) {
    value.slice(0, 50).forEach((item) => diracV143WalkObjectIds(item, push, source, depth + 1));
    return;
  }
  Object.entries(value).slice(0, 100).forEach(([key, child]) => {
    push(key, child, source);
    if (child && typeof child === 'object') diracV143WalkObjectIds(child, push, source, depth + 1);
  });
}

/* source 27988-27992 */
function diracV143PushSamples(out, value) {
  const text = String(value === undefined || value === null ? '' : value);
  if (!text) return;
  out.push(text.slice(0, 3000));
}

/* source 27994-28017 */
function diracV143ExpandedSamples(value) {
  const raw = String(value || '');
  if (!raw) return [];
  const out = new Set();
  const add = (item) => {
    const text = String(item || '').slice(0, 3000);
    if (!text) return;
    out.add(text);
    out.add(text.toLowerCase());
    out.add(text.replace(/\+/g, ' '));
    out.add(text.replace(/\+/g, ' ').toLowerCase());
  };
  add(raw);
  let current = raw;
  for (let i = 0; i < 3; i += 1) {
    try {
      const decoded = decodeURIComponent(current);
      add(decoded);
      if (decoded === current) break;
      current = decoded;
    } catch (_) { break; }
  }
  return Array.from(out);
}

/* source 28019-28044 */
async function diracV143CheckActiveGlobalBan(req) {
  try {
    if (typeof diracV107CheckActiveBan === 'function') {
      const existing = await diracV107CheckActiveBan(req);
      if (existing && existing.blocked) return existing;
    }
  } catch (_) {}

  const now = Date.now();
  const key = diracV143RequestKey(req);
  const memory = DIRAC_GLOBAL_API_THREAT_STORE_V143.get(key);
  if (memory && Number(memory.blockedUntilMs || 0) > now) {
    return { blocked: true, retryAfterSeconds: Math.max(1, Math.ceil((Number(memory.blockedUntilMs) - now) / 1000)) };
  }

  if (typeof readPersistentSecurityJson === 'function') {
    const persisted = await readPersistentSecurityJson('global-api-threat-ban:' + key).catch(() => null);
    const blockedUntilMs = Number(persisted && (persisted.blockedUntilMs || persisted.blocked_until_ms) || 0);
    if (blockedUntilMs > now) {
      DIRAC_GLOBAL_API_THREAT_STORE_V143.set(key, { blockedUntilMs });
      return { blocked: true, retryAfterSeconds: Math.max(1, Math.ceil((blockedUntilMs - now) / 1000)) };
    }
  }

  return { blocked: false };
}

/* source 28046-28075 */
async function diracV143WriteGlobalBanOnce(req, res, action, method, threat) {
  try {
    if (typeof diracV107RegisterHardBan === 'function') {
      return await diracV107RegisterHardBan(req, res || null, action || 'global_api_threat', method || 'GET', threat || { detected: true, kind: 'global_api_threat' });
    }
  } catch (_) {}

  const now = Date.now();
  const years = Math.max(1, Math.min(100, Number(process.env.DIRAC_SQLMAP_BLOCK_YEARS || 10) || 10));
  const blockedUntilMs = now + years * 365 * 24 * 60 * 60 * 1000;
  const key = diracV143RequestKey(req);
  DIRAC_GLOBAL_API_THREAT_STORE_V143.set(key, { blockedUntilMs, updatedAtMs: now });

  if (typeof writePersistentSecurityJson === 'function') {
    await writePersistentSecurityJson('global-api-threat-ban:' + key, {
      type: 'global_api_threat_ban_v143',
      patch: DIRAC_GLOBAL_API_THREAT_GUARD_V143,
      action: String(action || '').slice(0, 80),
      method: String(method || '').slice(0, 12),
      reason: String(threat && (threat.reason || threat.kind) || 'global_api_threat').slice(0, 100),
      source: String(threat && threat.source || 'guard').slice(0, 80),
      risk: String(threat && threat.risk || 'critical').slice(0, 40),
      blockedUntilMs,
      blocked_until_ms: blockedUntilMs,
      created_at: new Date(now).toISOString()
    }, blockedUntilMs, Math.ceil((blockedUntilMs - now) / 1000)).catch(() => false);
  }

  return { ok: true, wrote: 1, blockedUntilMs };
}

/* source 28077-28085 */
function diracV143RequestKey(req) {
  const headers = (req && req.headers) || {};
  const ip = typeof getLoginSecurityIp === 'function' ? getLoginSecurityIp(req) : String(headers['x-forwarded-for'] || headers['x-real-ip'] || 'unknown').split(',')[0].trim();
  const ua = String(headers['user-agent'] || '').slice(0, 500);
  const lang = String(headers['accept-language'] || '').slice(0, 120);
  const accept = String(headers.accept || '').slice(0, 200);
  const platform = String(headers['sec-ch-ua-platform'] || '').slice(0, 80);
  return diracV143Hash(['v143', ip, ua, lang, accept, platform].join('|'));
}

/* source 28087-28094 */
function diracV143AllowedOrigins() {
  try {
    const values = typeof getAllowedOrigins === 'function' ? getAllowedOrigins() : [];
    return new Set((values || []).map(diracV143NormalizeOrigin).filter(Boolean));
  } catch (_) {
    return new Set();
  }
}

/* source 28096-28106 */
function diracV143NormalizeOrigin(value) {
  try {
    const raw = String(value || '').trim();
    if (!raw) return '';
    const url = new URL(raw);
    if (!/^https?:$/.test(url.protocol)) return '';
    return url.origin;
  } catch (_) {
    return '';
  }
}

/* source 28108-28112 */
function diracV143NormalizeAction(action) {
  try { if (typeof diracV142NormalizeAction === 'function') return diracV142NormalizeAction(String(action || '')); } catch (_) {}
  try { if (typeof normalizeDomainAction === 'function') return normalizeDomainAction(String(action || '')); } catch (_) {}
  return String(action || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/* source 28114-28123 */
function diracV143NeverTouchAction(action) {
  const clean = diracV143NormalizeAction(action);
  if (!clean) return false;
  if (/^(domain_logout|logout|logout_domain)$/i.test(clean)) return true;
  if (/webhook|callback|notification|midtrans|ipaymu|payment_gateway/i.test(clean)) return true;
  if (/mfa|a2f|passkey|webauthn|otp|totp/i.test(clean)) return true;
  if (/email_template|mail_template|smtp|mailer/i.test(clean)) return true;
  if (/password_hash|argon|bcrypt|scrypt|pepper|hash_core/i.test(clean)) return true;
  return false;
}

/* source 28125-28128 */
function diracV143ServerOnlyAction(action) {
  const clean = diracV143NormalizeAction(action);
  return /^(domain_health|hostinger_check|domain_check)$/i.test(clean);
}

/* source 28130-28132 */
function diracV143IsTrackedIdKey(key) {
  return /^(customer_id|order_id|order_code|domain_order_id|domain_order_code|payment_id|payment_transaction_id|transaction_id|gateway_reference|invoice_id|id)$/i.test(String(key || ''));
}

/* source 28134-28136 */
function diracV143NormalizeKey(key) {
  return String(key || '').trim().replace(/[A-Z]/g, (m) => '_' + m.toLowerCase()).replace(/[-\s]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase();
}

/* source 28138-28146 */
function diracV143ExtractValues(value) {
  if (Array.isArray(value)) return value.flatMap(diracV143ExtractValues).slice(0, 20);
  const raw = String(value === undefined || value === null ? '' : value).trim();
  if (!raw) return [];
  return Array.from(new Set(diracV143ExpandedSamples(raw)
    .flatMap((sample) => String(sample || '').split(/[\s,|]+/))
    .map((part) => part.replace(/^(?:eq|in|is)\./i, '').replace(/^\(/, '').replace(/\)$/, '').replace(/^[`'\"]|[`'\"]$/g, '').trim())
    .filter(Boolean))).slice(0, 20);
}

/* source 28148-28153 */
function diracV143ValuesForKeys(ids, regex) {
  return Array.from(new Set((ids || [])
    .filter((item) => item && regex.test(String(item.key || '')))
    .map((item) => String(item.value || '').trim())
    .filter(Boolean))).slice(0, 40);
}

/* source 28155-28159 */
function diracV143SafeRestEqValue(value) {
  const text = String(value || '').trim();
  if (!text || text.length > 160) return '';
  return /^[A-Za-z0-9._:@-]+$/.test(text) ? text : '';
}

/* source 28161-28164 */
function diracV143LooksLikeUuid(value) {
  try { if (typeof customerSecurityLooksLikeUuid === 'function') return customerSecurityLooksLikeUuid(value); } catch (_) {}
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

/* source 28166-28172 */
function diracV143ReportReason(req) {
  const query = (req && req.query) || {};
  const body = req && req.body && typeof req.body === 'object' ? req.body : {};
  return String(body.reason || query.reason || body.type || query.type || 'html_detected_attack')
    .replace(/[\u0000-\u001f\u007f<>]/g, '')
    .slice(0, 120);
}

/* source 28184-28194 */
function diracV143BlockedResponse(res, reason) {
  try { if (typeof diracApplySecurityResponseHeaders === 'function') diracApplySecurityResponseHeaders(res); } catch (_) {}
  try { if (res && typeof res.setHeader === 'function') res.setHeader('Cache-Control', 'no-store'); } catch (_) {}
  return res.status(403).json({
    ok: false,
    code: 'GLOBAL_API_THREAT_BLOCKED',
    message: 'Permintaan ditolak oleh sistem keamanan.',
    reason: String(reason || 'blocked').slice(0, 80),
    source: DIRAC_GLOBAL_API_THREAT_GUARD_V143
  });
}

/* source 28196-28201 */
function diracV143ApplyHeaders(res) {
  if (!res || typeof res.setHeader !== 'function') return;
  try { res.setHeader('X-Dirac-Global-Api-Threat-Guard', DIRAC_GLOBAL_API_THREAT_GUARD_V143); } catch (_) {}
  try { res.setHeader('X-Content-Type-Options', 'nosniff'); } catch (_) {}
  try { res.setHeader('Cache-Control', 'no-store'); } catch (_) {}
}

/* source 28203-28208 */
function diracV143Hash(value) {
  const secret = diracCentralDeriveSecretV146('v143-global-api-hash');
  try { return crypto.createHmac('sha256', secret).update(String(value || '')).digest('hex'); } catch (_) {}
  try { if (typeof loginSecurityHash === 'function') return loginSecurityHash(value); } catch (_) {}
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

/* source 28210-28213 */
function diracV143EnvTrue(name) {
  const value = String(process.env[name] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

/* source 28215-28219 */
function diracV143SafeError(error) {
  const message = String(error && (error.code || error.name || error.message) || error || 'security_error');
  if (/password|token|secret|cookie|authorization|service_role|apikey|csrf|hmac|hash/i.test(message)) return 'global_api_guard_internal_error';
  return message.slice(0, 160);
}

/* source 28236-28236 */
const DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144 = globalThis.__DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144__ || new Map();

/* source 28237-28237 */
globalThis.__DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144__ = DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144;

/* source 28239-28265 */
try {
  const __diracV144OriginalReadRows = typeof diracV107ReadRows === 'function' ? diracV107ReadRows : null;
  if (__diracV144OriginalReadRows && !__diracV144OriginalReadRows.__diracV144Wrapped) {
    diracV107ReadRows = async function diracV107ReadRowsBatchedNegativeCachedV144(keys) {
      const table = typeof diracV107Table === 'function' ? diracV107Table() : '';
      const cleanKeys = (Array.isArray(keys) ? keys : [])
        .map((item) => String(item || '').trim())
        .filter(Boolean)
        .slice(0, 12);
      if (!table || !cleanKeys.length) return [];

      const now = Date.now();
      const cacheKey = 'v107-read:' + diracV144Hash(cleanKeys.join('|'));
      const cached = DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144.get(cacheKey);
      if (cached && Number(cached.until || 0) > now) return [];

      const batchRows = await diracV144ReadSecurityRowsBatch(table, cleanKeys).catch(() => []);
      if (Array.isArray(batchRows) && batchRows.length) return batchRows;

      const ttl = diracV144NegativeCacheMs();
      DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144.set(cacheKey, { until: now + ttl });
      diracV144CleanupNegativeCache(now);
      return [];
    };
    Object.defineProperty(diracV107ReadRows, '__diracV144Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 28267-28282 */
try {
  const __diracV144OriginalCheckActiveGlobalBan = typeof diracV143CheckActiveGlobalBan === 'function' ? diracV143CheckActiveGlobalBan : null;
  if (__diracV144OriginalCheckActiveGlobalBan && !__diracV144OriginalCheckActiveGlobalBan.__diracV144Wrapped) {
    diracV143CheckActiveGlobalBan = async function diracV143CheckActiveGlobalBanNoExtraPersistentReadV144(req) {
      try {
        if (typeof diracV107CheckActiveBan === 'function') {
          const existing = await diracV107CheckActiveBan(req);
          if (existing && existing.blocked) return existing;
          if (!diracV144EnvTrue('DIRAC_V143_LEGACY_FALLBACK_READ')) return { blocked: false };
        }
      } catch (_) {}
      return __diracV144OriginalCheckActiveGlobalBan(req);
    };
    Object.defineProperty(diracV143CheckActiveGlobalBan, '__diracV144Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 28313-28317 */
function diracV144NegativeCacheMs() {
  const raw = Number(process.env.DIRAC_GLOBAL_BAN_NEGATIVE_CACHE_MS || 5000);
  if (!Number.isFinite(raw)) return 5000;
  return Math.max(1000, Math.min(30000, Math.floor(raw)));
}

/* source 28319-28325 */
function diracV144CleanupNegativeCache(now) {
  if (DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144.size < 5000) return;
  for (const [key, value] of DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144.entries()) {
    if (Number(value && value.until || 0) <= now) DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144.delete(key);
    if (DIRAC_SECURITY_NEGATIVE_BAN_CACHE_V144.size <= 3000) break;
  }
}

/* source 28327-28336 */
function diracV144Hash(value) {
  try {
    if (typeof diracV143Hash === 'function') return diracV143Hash(value);
  } catch (_) {}
  try {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
  } catch (_) {
    return String(value || '').slice(0, 64);
  }
}

/* source 28338-28341 */
function diracV144EnvTrue(name) {
  const value = String(process.env[name] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

/* source 28356-28356 */
const DIRAC_SECURITY_WRITE_CACHE_V145 = globalThis.__DIRAC_SECURITY_WRITE_CACHE_V145__ || new Map();

/* source 28357-28357 */
globalThis.__DIRAC_SECURITY_WRITE_CACHE_V145__ = DIRAC_SECURITY_WRITE_CACHE_V145;

/* source 28359-28398 */
try {
  const __diracV145OriginalRegisterHardBan = typeof diracV107RegisterHardBan === 'function' ? diracV107RegisterHardBan : null;
  if (__diracV145OriginalRegisterHardBan && !__diracV145OriginalRegisterHardBan.__diracV145Wrapped) {
    diracV107RegisterHardBan = async function diracV107RegisterHardBanCoalescedV145(req, res, action, method, threat) {
      if (diracV145EnvTrue('DIRAC_SECURITY_WRITE_COALESCER_DISABLED')) {
        return __diracV145OriginalRegisterHardBan(req, res, action, method, threat);
      }

      const now = Date.now();
      const keys = typeof diracV107BuildKeys === 'function' ? diracV107BuildKeys(req || {}) : [];
      const cleanKeys = keys.map((item) => String(item && item.key || '')).filter(Boolean).slice(0, 12);
      const cacheKey = 'hard-ban:' + diracV145Hash(cleanKeys.join('|') || diracV145FallbackRequestKey(req));
      const cached = DIRAC_SECURITY_WRITE_CACHE_V145.get(cacheKey);

      if (cached && Number(cached.until || 0) > now && (!res || cached.cookieSet)) {
        diracV145RefreshHardBanMemory(keys, Number(cached.blockedUntilMs || 0), now);
        return {
          ok: true,
          wrote: 0,
          total: cleanKeys.length,
          skipped: 'coalesced_recent_hard_ban_write_v145',
          blockedUntilMs: Number(cached.blockedUntilMs || 0)
        };
      }

      const result = await __diracV145OriginalRegisterHardBan(req, res, action, method, threat);
      const blockedUntilMs = Number(result && result.blockedUntilMs || 0);
      if (blockedUntilMs > now && result && result.ok && Number(result.wrote || 0) > 0) {
        DIRAC_SECURITY_WRITE_CACHE_V145.set(cacheKey, {
          until: now + diracV145WriteCoalesceMs(),
          blockedUntilMs,
          cookieSet: Boolean(res)
        });
        diracV145CleanupWriteCache(now);
      }
      return result;
    };
    Object.defineProperty(diracV107RegisterHardBan, '__diracV145Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 28400-28442 */
try {
  const __diracV145OriginalRegisterSqlmapAttack = typeof diracV101RegisterSqlmapAttack === 'function' ? diracV101RegisterSqlmapAttack : null;
  if (__diracV145OriginalRegisterSqlmapAttack && !__diracV145OriginalRegisterSqlmapAttack.__diracV145Wrapped) {
    diracV101RegisterSqlmapAttack = async function diracV101RegisterSqlmapAttackCoalescedV145(req, action, method, threat) {
      if (diracV145EnvTrue('DIRAC_SECURITY_WRITE_COALESCER_DISABLED')) {
        return __diracV145OriginalRegisterSqlmapAttack(req, action, method, threat);
      }

      const now = Date.now();
      const key = typeof diracV101SqlmapSecurityKey === 'function'
        ? diracV101SqlmapSecurityKey(req || {}, action, method)
        : 'sqlmap:' + diracV145FallbackRequestKey(req);
      const cacheKey = 'sqlmap:' + diracV145Hash(key);
      const cached = DIRAC_SECURITY_WRITE_CACHE_V145.get(cacheKey);
      if (cached && Number(cached.until || 0) > now) {
        try {
          if (typeof DIRAC_ULTRA_SQLMAP_MEMORY_STORE !== 'undefined' && DIRAC_ULTRA_SQLMAP_MEMORY_STORE && typeof DIRAC_ULTRA_SQLMAP_MEMORY_STORE.set === 'function') {
            DIRAC_ULTRA_SQLMAP_MEMORY_STORE.set(key, { blockedUntilMs: Number(cached.blockedUntilMs || 0), updatedAtMs: now });
          }
        } catch (_) {}
        return true;
      }

      const result = await __diracV145OriginalRegisterSqlmapAttack(req, action, method, threat);
      let blockedUntilMs = 0;
      try {
        const row = typeof DIRAC_ULTRA_SQLMAP_MEMORY_STORE !== 'undefined' && DIRAC_ULTRA_SQLMAP_MEMORY_STORE
          ? DIRAC_ULTRA_SQLMAP_MEMORY_STORE.get(key)
          : null;
        blockedUntilMs = Number(row && row.blockedUntilMs || 0);
      } catch (_) {}
      if (blockedUntilMs > now) {
        DIRAC_SECURITY_WRITE_CACHE_V145.set(cacheKey, {
          until: now + diracV145WriteCoalesceMs(),
          blockedUntilMs
        });
        diracV145CleanupWriteCache(now);
      }
      return result;
    };
    Object.defineProperty(diracV101RegisterSqlmapAttack, '__diracV145Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 28444-28457 */
try {
  const __diracV145OriginalInspectOwnership = typeof diracV143InspectOwnership === 'function' ? diracV143InspectOwnership : null;
  if (__diracV145OriginalInspectOwnership && !__diracV145OriginalInspectOwnership.__diracV145Wrapped) {
    diracV143InspectOwnership = async function diracV143InspectOwnershipSensitiveIdsOnlyV145(req, body) {
      if (diracV145EnvTrue('DIRAC_V143_OWNERSHIP_ALL_IDS')) {
        return __diracV145OriginalInspectOwnership(req, body);
      }
      const ids = typeof diracV143CollectRequestIds === 'function' ? diracV143CollectRequestIds(req, body) : [];
      if (!diracV145HasSensitiveOwnershipId(ids)) return { ok: true, skipped: 'no_sensitive_ownership_id_v145' };
      return __diracV145OriginalInspectOwnership(req, body);
    };
    Object.defineProperty(diracV143InspectOwnership, '__diracV145Wrapped', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 28459-28464 */
function diracV145HasSensitiveOwnershipId(ids) {
  return (ids || []).some((item) => {
    const key = String(item && item.key || '').toLowerCase();
    return /^(customer_id|order_id|order_code|domain_order_id|domain_order_code|payment_id|payment_transaction_id|transaction_id|gateway_reference|invoice_id)$/.test(key);
  });
}

/* source 28466-28479 */
function diracV145RefreshHardBanMemory(keys, blockedUntilMs, now) {
  if (!blockedUntilMs || blockedUntilMs <= now) return;
  try {
    if (typeof DIRAC_GLOBAL_HARD_BAN_STORE_V107 === 'undefined' || !DIRAC_GLOBAL_HARD_BAN_STORE_V107) return;
    for (const item of keys || []) {
      if (!item || !item.key) continue;
      DIRAC_GLOBAL_HARD_BAN_STORE_V107.set(String(item.key), {
        blockedUntilMs,
        updatedAtMs: now,
        type: String(item.type || 'coalesced')
      });
    }
  } catch (_) {}
}

/* source 28481-28485 */
function diracV145WriteCoalesceMs() {
  const raw = Number(process.env.DIRAC_SECURITY_WRITE_COALESCE_MS || 60 * 1000);
  if (!Number.isFinite(raw)) return 60 * 1000;
  return Math.max(5000, Math.min(10 * 60 * 1000, Math.floor(raw)));
}

/* source 28487-28493 */
function diracV145CleanupWriteCache(now) {
  if (DIRAC_SECURITY_WRITE_CACHE_V145.size < 5000) return;
  for (const [key, value] of DIRAC_SECURITY_WRITE_CACHE_V145.entries()) {
    if (Number(value && value.until || 0) <= now) DIRAC_SECURITY_WRITE_CACHE_V145.delete(key);
    if (DIRAC_SECURITY_WRITE_CACHE_V145.size <= 3000) break;
  }
}

/* source 28495-28501 */
function diracV145FallbackRequestKey(req) {
  const headers = (req && req.headers) || {};
  const ip = typeof getLoginSecurityIp === 'function'
    ? getLoginSecurityIp(req || {})
    : String(headers['x-forwarded-for'] || headers['x-real-ip'] || 'unknown').split(',')[0].trim();
  return [ip, String(headers['user-agent'] || '').slice(0, 500), String(headers.accept || '').slice(0, 200)].join('|');
}

/* source 28503-28512 */
function diracV145Hash(value) {
  try {
    if (typeof diracV143Hash === 'function') return diracV143Hash(value);
  } catch (_) {}
  try {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
  } catch (_) {
    return String(value || '').slice(0, 64);
  }
}

/* source 28514-28517 */
function diracV145EnvTrue(name) {
  const value = String(process.env[name] || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

/* source 28519-28522 */
function customerSecurityLostPasskeyWorkerHash(value) {
  const clean = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(clean) ? clean : '';
}

/* source 28524-28542 */
function customerSecurityLostPasskeyWorkerBindings(body, owner) {
  const bindings = {
    emailBindingHash: customerSecurityLostPasskeyWorkerHash(body && body.email_binding_hash),
    customerBindingHash: customerSecurityLostPasskeyWorkerHash(body && body.customer_binding_hash),
    authUserBindingHash: customerSecurityLostPasskeyWorkerHash(body && body.auth_user_binding_hash),
    deviceBindingHash: customerSecurityLostPasskeyWorkerHash(body && body.device_binding_hash),
    sessionHash: customerSecurityLostPasskeyWorkerHash(body && body.session_hash),
    ipHash: customerSecurityLostPasskeyWorkerHash(body && body.ip_hash),
    userAgentHash: customerSecurityLostPasskeyWorkerHash(body && body.user_agent_hash)
  };
  if (Object.values(bindings).some((value) => !value)) return null;
  const expectedEmail = customerSecurityLostPasskeyHashHex('email-binding', normalizeAuthEmail(owner && owner.email));
  const expectedCustomer = customerSecurityLostPasskeyHashHex('customer-binding', String(owner && owner.customerId || ''));
  const expectedAuthUser = customerSecurityLostPasskeyHashHex('auth-user-binding', String(owner && owner.authUserId || ''));
  if (!safeEqual(bindings.emailBindingHash, expectedEmail)) return null;
  if (!safeEqual(bindings.customerBindingHash, expectedCustomer)) return null;
  if (!safeEqual(bindings.authUserBindingHash, expectedAuthUser)) return null;
  return bindings;
}

/* source 28544-28565 */
async function customerSecurityResolveLostPasskeyWorkerOwner(body) {
  const authUserId = String(body && body.auth_user_id || '').trim();
  const customerId = String(body && body.customer_id || '').trim();
  const email = normalizeAuthEmail(body && body.email);
  if (!customerSecurityLooksLikeUuid(authUserId) || !customerSecurityLooksLikeUuid(customerId) || !isValidAuthEmail(email)) {
    return { ok: false, status: 400, message: 'Payload worker recovery tidak valid.' };
  }
  const linkResult = await customerSecurityFetchAuthLink(authUserId);
  if (!linkResult.ok) return { ok: false, status: linkResult.status || 500, message: 'Gagal membaca auth link recovery.' };
  const link = customerSecurityPickSingleActiveAuthLink(linkResult);
  if (!link || link.link_status !== 'active' || String(link.customer_id || '') !== customerId) {
    return { ok: false, status: 403, message: 'Auth link recovery tidak cocok.' };
  }
  const customerResult = await diracPasskeyA2FFetchCustomerById(customerId);
  if (!customerResult.ok) return { ok: false, status: customerResult.status || 500, message: 'Gagal membaca customer resmi.' };
  const customer = Array.isArray(customerResult.data) ? customerResult.data[0] : null;
  const customerEmail = normalizeAuthEmail(customer && customer.email);
  if (!customer || !isValidAuthEmail(customerEmail) || customerEmail !== email) {
    return { ok: false, status: 403, message: 'Email worker tidak cocok dengan customer resmi.' };
  }
  return { ok: true, authUserId, customerId, email: customerEmail, customer };
}

/* source 28567-28830 */
async function customerSecurityVerifyRecoveryCodeLocalWorker(req, res, action, override = {}) {
  const owner = override && override.owner;
  const bindings = override && override.bindings;
  const access = override && override.access || { customerId: owner && owner.customerId };
  const requestId = customerSecurityNormalizeLostPasskeyRequestId(override && override.requestId || '');
  const code = customerSecurityNormalizeRecoveryCodeInput(override && override.recoveryCode || '');

  if (!owner || !owner.ok || !bindings || !requestId) {
    await customerSecurityRegisterFailedVerification(req, action, 'invalid_recovery_worker_verify_payload', access && access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 400, 'invalid_recovery_worker_verify_payload', { request_id: requestId, customer_id: owner && owner.customerId, auth_user_id: owner && owner.authUserId, email: owner && owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }
  if (Array.from(code).length !== LOST_PASSKEY_RECOVERY_CODE_LENGTH_V157) {
    await customerSecurityRegisterFailedVerification(req, action, 'invalid_recovery_code_length', access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 400, 'invalid_recovery_code_length', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }

  const vaultSecrets = customerSecurityLostPasskeyRequireVaultSecretsV157();
  if (!vaultSecrets.ok) {
    customerSecurityLostPasskeyWorkerVerifyTraceV174('vault_secret_check_failed', vaultSecrets.code || 'vault_secret_invalid', {
      owner,
      bindings,
      requestId,
      code,
      workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
      httpStatus: 503,
      debugHint: 'Server 2 env Argon2id/root secret/pepper belum valid, jadi verify berhenti sebelum baca recovery request.'
    });
    return res.status(503).json({ ok: false, code: vaultSecrets.code, message: vaultSecrets.message });
  }

  const path = '/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?select=' +
    encodeURIComponent('id,request_id,customer_id,auth_user_id,email_hash,customer_binding_hash,auth_user_binding_hash,device_binding_hash,ip_hash,user_agent_hash,recovery_code_hash,status,attempt_count,expires_at,used_at,revoked_at,locked_at,old_passkey_ids,metadata') +
    '&request_id=eq.' + encodeURIComponent(requestId) +
    '&limit=1';

  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  if (!result.ok) return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 500, 'recovery_request_read_failed', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, supabaseStatus: result.status, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });

  const row = Array.isArray(result.data) ? result.data[0] : null;
  if (!row || !row.id) {
    await customerSecurityRegisterFailedVerification(req, action, 'recovery_request_not_found', access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 404, 'recovery_request_not_found', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, rowChecked: true, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }

  const nowMs = Date.now();
  const recoveryStatus = String(row.status || '');
  const recoveryExpiresMs = new Date(row.expires_at).getTime();
  if (row.used_at
    || row.revoked_at
    || row.locked_at
    || !Number.isFinite(recoveryExpiresMs)
    || recoveryExpiresMs <= nowMs
    || !['pending', 'verified'].includes(recoveryStatus)) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, recoveryStatus === 'used' || row.used_at ? 'used' : 'expired_or_inactive', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }
  const verifiedRetry = recoveryStatus === 'verified';

  if (String(owner.customerId) !== String(row.customer_id) || String(owner.authUserId) !== String(row.auth_user_id)) {
    await customerSecurityRegisterFailedVerification(req, action, 'recovery_owner_mismatch', access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_owner_mismatch', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }
  if (!safeEqual(String(row.email_hash || ''), bindings.emailBindingHash)
    || !safeEqual(String(row.customer_binding_hash || ''), bindings.customerBindingHash)
    || !safeEqual(String(row.auth_user_binding_hash || ''), bindings.authUserBindingHash)
    || !safeEqual(String(row.device_binding_hash || ''), bindings.deviceBindingHash)
    || !safeEqual(String(row.ip_hash || ''), bindings.ipHash)
    || !safeEqual(String(row.user_agent_hash || ''), bindings.userAgentHash)) {
    await customerSecurityRegisterFailedVerification(req, action, 'recovery_binding_mismatch', access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_binding_mismatch', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }

  const metadata = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
  const expectedBinding = await customerSecurityLostPasskeyArgon2VerifyHashV157('binding', customerSecurityLostPasskeyCanonical(bindings), metadata.binding_hash_commitment, vaultSecrets.pepper, vaultSecrets.rootSecret);
  if (!expectedBinding) {
    await customerSecurityRegisterFailedVerification(req, action, 'recovery_binding_commitment_mismatch', access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_binding_commitment_mismatch', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, metadata, bindingCommitmentOk: expectedBinding, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }

  const codeOk = await customerSecurityLostPasskeyArgon2VerifyHashV157('recovery_code', code, row.recovery_code_hash, vaultSecrets.pepper, vaultSecrets.rootSecret);
  if (!codeOk) {
    const nextAttempts = Number(row.attempt_count || 0) + 1;
    const lock = nextAttempts >= LOST_PASSKEY_RECOVERY_ATTEMPT_LIMIT;
    await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
      method: 'PATCH',
      auth: 'service',
      body: {
        attempt_count: nextAttempts,
        status: lock ? 'locked' : row.status,
        locked_at: lock ? diracNowIso() : row.locked_at || null,
        metadata: { ...metadata, last_failed_verify_at: diracNowIso(), failed_verify_source: action, patch: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157 }
      }
    }).catch(() => null);
    await customerSecurityRegisterFailedVerification(req, action, lock ? 'recovery_code_locked' : 'recovery_code_not_matched', access.customerId).catch(() => null);
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, lock ? 423 : 403, lock ? 'recovery_code_locked' : 'recovery_code_not_matched', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, metadata, bindingCommitmentOk: expectedBinding, recoveryCodeOk: codeOk, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }

  if (override && override.argonQueueTicket && !customerSecurityLostPasskeyQueueLeaseHealthyV188(override.argonQueueTicket)) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 503, 'recovery_argon2_lease_lost', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
  }

  const activePasskeys = await customerSecurityLostPasskeyActivePasskeys(owner);
  if (!activePasskeys.length) return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 409, 'active_passkey_not_found', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, metadata, bindingCommitmentOk: expectedBinding, recoveryCodeOk: codeOk, activePasskeyCount: 0, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });

  const now = diracNowIso();
  if (verifiedRetry) {
    const previousSessionRevoked = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_SESSION_TABLE
      + '?request_id=eq.' + encodeURIComponent(requestId)
      + '&customer_id=eq.' + encodeURIComponent(owner.customerId)
      + '&auth_user_id=eq.' + encodeURIComponent(owner.authUserId)
      + '&status=eq.verified'
      + '&used_at=is.null'
      + '&revoked_at=is.null', {
      method: 'PATCH',
      auth: 'service',
      prefer: 'return=representation',
      body: {
        status: 'revoked',
        revoked_at: now
      }
    });
    if (!previousSessionRevoked.ok) {
      return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 503, 'recovery_session_rotation_failed', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY }, { owner, bindings, requestId, code, row, metadata, bindingCommitmentOk: expectedBinding, recoveryCodeOk: codeOk, activePasskeyCount: activePasskeys.length, supabaseStatus: previousSessionRevoked.status, workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY });
    }
  }

  const recoverySessionToken = crypto.randomBytes(32).toString('base64url');
  const recoverySessionHash = customerSecurityLostPasskeyRecoverySessionHash(recoverySessionToken);
  const sessionExpiresAt = new Date(Date.now() + Math.max(5, Math.min(30, Number(process.env.DIRAC_LOST_PASSKEY_SESSION_MINUTES || 10))) * 60 * 1000).toISOString();
  const sessionCreated = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_SESSION_TABLE, {
    method: 'POST',
    auth: 'service',
    prefer: 'return=representation',
    body: [{
      request_id: requestId,
      customer_id: owner.customerId,
      auth_user_id: owner.authUserId,
      recovery_session_hash: recoverySessionHash,
      purpose: LOST_PASSKEY_RECOVERY_PURPOSE,
      status: 'verified',
      created_at: now,
      expires_at: sessionExpiresAt,
      metadata: {
        source: action,
        worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
        old_passkey_count: activePasskeys.length,
        patch: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157
      }
    }]
  });

  if (!sessionCreated.ok) {
    const failedBody = { ok: false, code: 'RECOVERY_SESSION_CREATE_FAILED', message: 'Gagal membuat recovery session.' };
    const failedTrace = customerSecurityLostPasskeyWorkerVerifyTraceV174('verify_session_create_failed', 'recovery_session_create_failed', {
      owner,
      bindings,
      requestId,
      code,
      row,
      metadata,
      bindingCommitmentOk: expectedBinding,
      recoveryCodeOk: codeOk,
      activePasskeyCount: activePasskeys.length,
      supabaseStatus: sessionCreated.status,
      workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
      httpStatus: sessionCreated.status || 500,
      responseBody: failedBody,
      sessionInsertAttempted: true,
      debugHint: 'Recovery code valid, tetapi insert security_lost_passkey_recovery_sessions gagal.'
    });
    if (customerSecurityLostPasskeyRootCauseDebugEnabledV173()) failedBody.worker_verify_debug = failedTrace;
    return res.status(sessionCreated.status || 500).json(failedBody);
  }

  const verifiedMetadata = {
    ...metadata,
    source: 'lost_passkey_recovery_code_verify',
    verified_by_endpoint: action,
    verified_by_worker_action: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
    verified_at: now,
    recovery_session_created_at: now,
    recovery_session_expires_at: sessionExpiresAt,
    patch: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157
  };

  const patched = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: {
      status: 'verified',
      metadata: verifiedMetadata
    }
  });

  if (!patched.ok) {
    const failedBody = { ok: false, code: 'RECOVERY_REQUEST_VERIFY_PATCH_FAILED', message: 'Gagal menandai recovery request sebagai verified.' };
    const failedTrace = customerSecurityLostPasskeyWorkerVerifyTraceV174('verify_request_patch_failed', 'recovery_request_verify_patch_failed', {
      owner,
      bindings,
      requestId,
      code,
      row,
      metadata,
      bindingCommitmentOk: expectedBinding,
      recoveryCodeOk: codeOk,
      activePasskeyCount: activePasskeys.length,
      supabaseStatus: patched.status,
      workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
      httpStatus: patched.status || 500,
      responseBody: failedBody,
      sessionInsertAttempted: true,
      debugHint: 'Recovery session berhasil dibuat, tetapi update status recovery request ke verified gagal.'
    });
    if (customerSecurityLostPasskeyRootCauseDebugEnabledV173()) failedBody.worker_verify_debug = failedTrace;
    return res.status(patched.status || 500).json(failedBody);
  }

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'lost_passkey_recovery_verified',
    status: 'success',
    risk_level: 'high',
    description: 'Server 2 memvalidasi recovery code lost passkey dari signed SERVER 1 payload dan membuat recovery session terbatas.',
    req,
    metadata: { action, request_id: requestId, patch: DIRAC_LOST_PASSKEY_VAULT_PATCH_V157 }
  });

  const responseBody = {
    ok: true,
    valid: true,
    active: true,
    method: 'recovery_code',
    purpose: LOST_PASSKEY_RECOVERY_PURPOSE,
    request_id: requestId,
    message: 'Recovery code valid. Recovery session terbatas untuk daftar Passkey baru sudah dibuat.',
    recovery_session_token: recoverySessionToken,
    recovery_session_expires_at: sessionExpiresAt,
    dashboard_access: false,
    recovery_code_verified: true,
    time: now
  };

  const verifyTrace = customerSecurityLostPasskeyWorkerVerifyTraceV174('verify_success_response_ready', 'verify_success_with_server2_recovery_session_token', {
    owner,
    bindings,
    requestId,
    code,
    row,
    metadata: verifiedMetadata,
    bindingCommitmentOk: expectedBinding,
    recoveryCodeOk: codeOk,
    activePasskeyCount: activePasskeys.length,
    workerAction: DIRAC_RECOVERY_WORKER_TASK_VERIFY,
    httpStatus: 200,
    responseBody,
    sessionInsertAttempted: true,
    debugHint: 'Server 2 memvalidasi recovery code, membuat recovery_session_token, dan response sudah bisa membuka tahap daftar Passkey baru.'
  });

  if (customerSecurityLostPasskeyRootCauseDebugEnabledV173()) {
    responseBody.worker_verify_debug = verifyTrace;
  }

  return res.status(200).json(responseBody);
}

/* source 28833-28902 */
async function customerSecurityFinalizeRecoveryLocalWorkerV162(req, res, action, override = {}) {
  const owner = override && override.owner;
  const bindings = override && override.bindings;
  const access = override && override.access || { customerId: owner && owner.customerId };
  const requestId = customerSecurityNormalizeLostPasskeyRequestId(override && override.requestId || '');
  if (!owner || !owner.ok || !bindings || !requestId) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 400, 'invalid_recovery_worker_finalize_payload', { request_id: requestId, customer_id: owner && owner.customerId, auth_user_id: owner && owner.authUserId, email: owner && owner.email });
  }
  const vaultSecrets = customerSecurityLostPasskeyRequireVaultSecretsV157();
  if (!vaultSecrets.ok) return res.status(503).json({ ok: false, code: vaultSecrets.code, message: vaultSecrets.message });

  const select = 'id,request_id,customer_id,auth_user_id,email_hash,customer_binding_hash,auth_user_binding_hash,device_binding_hash,ip_hash,user_agent_hash,status,expires_at,used_at,revoked_at,locked_at,metadata';
  const result = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?select=' + encodeURIComponent(select) + '&request_id=eq.' + encodeURIComponent(requestId) + '&limit=1', { method: 'GET', auth: 'service' });
  if (!result.ok) return res.status(result.status || 500).json({ ok: false, message: 'Gagal membaca recovery request.' });
  const row = Array.isArray(result.data) ? result.data[0] : null;
  if (!row || !row.id) return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 404, 'recovery_request_not_found', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email });

  const expiresMs = new Date(row.expires_at).getTime();
  if (row.used_at || row.revoked_at || row.locked_at || !Number.isFinite(expiresMs) || expiresMs <= Date.now() || !['pending', 'verified'].includes(String(row.status || ''))) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_finalize_inactive', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email });
  }
  if (String(owner.customerId) !== String(row.customer_id) || String(owner.authUserId) !== String(row.auth_user_id)) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_finalize_owner_mismatch', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email });
  }
  if (!safeEqual(String(row.email_hash || ''), bindings.emailBindingHash)
    || !safeEqual(String(row.customer_binding_hash || ''), bindings.customerBindingHash)
    || !safeEqual(String(row.auth_user_binding_hash || ''), bindings.authUserBindingHash)
    || !safeEqual(String(row.device_binding_hash || ''), bindings.deviceBindingHash)
    || !safeEqual(String(row.ip_hash || ''), bindings.ipHash)
    || !safeEqual(String(row.user_agent_hash || ''), bindings.userAgentHash)) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_finalize_binding_mismatch', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email });
  }

  const metadata = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
  const bindingOk = await customerSecurityLostPasskeyArgon2VerifyHashV157('binding', customerSecurityLostPasskeyCanonical(bindings), metadata.binding_hash_commitment, vaultSecrets.pepper, vaultSecrets.rootSecret).catch(() => false);
  if (!bindingOk) return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'recovery_finalize_binding_commitment_mismatch', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email });
  if (override && override.argonQueueTicket && !customerSecurityLostPasskeyQueueLeaseHealthyV188(override.argonQueueTicket)) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 503, 'recovery_argon2_lease_lost', { request_id: requestId, customer_id: owner.customerId, auth_user_id: owner.authUserId, email: owner.email, worker_action: DIRAC_RECOVERY_WORKER_TASK_FINALIZE });
  }

  const now = diracNowIso();
  const finalMetadata = {
    ...metadata,
    finalized_at: now,
    finalized_by: 'server1_signed_worker_payload',
    finalized_patch: 'lost-passkey-link-guard-finalize-v162',
    link_token_revoked: true,
    email_secret_revoked: true,
    website_secret_revoked: true,
    recovery_code_revoked: true
  };
  const patched = await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE + '?request_id=eq.' + encodeURIComponent(requestId), {
    method: 'PATCH',
    auth: 'service',
    prefer: 'return=representation',
    body: { status: 'used', used_at: now, revoked_at: now, metadata: finalMetadata }
  });
  if (!patched.ok) return res.status(patched.status || 500).json({ ok: false, message: 'Gagal finalisasi recovery request.' });

  await customerSecurityWriteGuardEvent(access.customerId, {
    event_type: 'lost_passkey_recovery_finalized',
    status: 'success',
    risk_level: 'high',
    description: 'Server 2 menandai recovery lost passkey sebagai used/revoked setelah signed SERVER 1 finalize payload.',
    req,
    metadata: { action, request_id: requestId, patch: 'lost-passkey-link-guard-finalize-v162' }
  }).catch(() => null);

  return res.status(200).json({ ok: true, finalized: true, request_id: requestId, status: 'used', used_at: now, revoked_at: now, message: 'Recovery request sudah difinalisasi.' });
}

/* source 28905-29008 */
async function customerSecurityHandleRecoveryWorkerGenerate(req, res, action) {
  if (!customerSecurityRecoveryWorkerLocalEnabled()) {
    return res.status(404).json({ ok: false, code: 'RECOVERY_WORKER_DISABLED', message: 'Recovery worker tidak aktif di deployment ini.' });
  }
  if (!diracCentralGuardPassedForHandlerV168(req)) {
    return res.status(403).json({ ok: false, code: 'CENTRAL_GUARD_REQUIRED', message: 'Permintaan wajib melewati Central Guard.' });
  }
  if (req.__diracRecoveryWorkerVerified !== true) {
    return res.status(403).json({ ok: false, code: 'RECOVERY_WORKER_SIGNATURE_REQUIRED', message: 'Worker signature tidak valid.' });
  }
  const body = await readBody(req);
  if (!body || body.action !== DIRAC_RECOVERY_WORKER_ACTION) {
    return res.status(404).json({ ok: false, code: 'RECOVERY_WORKER_ACTION_INVALID', message: 'Worker action tidak valid.' });
  }
  if (body.pdf_password !== undefined || body.website_recovery_code !== undefined || body.email_pdf_code !== undefined) {
    return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'legacy_pdf_payload_rejected', body);
  }

  const owner = await customerSecurityResolveLostPasskeyWorkerOwner(body);
  if (!owner.ok) return customerSecurityLostPasskeyGenericWorkerErrorV157(res, owner.status || 403, 'worker_owner_invalid', body, { body, owner, workerAction: String(body.worker_action || '') });
  const bindings = customerSecurityLostPasskeyWorkerBindings(body, owner);
  if (!bindings) return customerSecurityLostPasskeyGenericWorkerErrorV157(res, 403, 'worker_binding_invalid', body, { body, owner, bindings, requestId: String(body.request_id || ''), code: customerSecurityNormalizeRecoveryCodeInput(body.recovery_code || body.code || ''), workerAction: String(body.worker_action || '') });

  const workerTask = String(body.worker_action || '');
  if (workerTask === DIRAC_RECOVERY_WORKER_TASK_GENERATE) {
    const activePasskeys = await customerSecurityLostPasskeyActivePasskeys(owner);
    if (!activePasskeys.length) {
      return res.status(409).json({ ok: false, code: 'ACTIVE_PASSKEY_NOT_FOUND', message: 'Passkey aktif untuk akun ini belum ditemukan.' });
    }
    const queueTicket = await customerSecurityLostPasskeyQueueAcquireV164(req, body);
    if (!queueTicket || !queueTicket.ok) {
      return res.status(queueTicket && queueTicket.status || 503).json({
        ok: false,
        code: queueTicket && queueTicket.code || 'RECOVERY_GENERATE_QUEUE_BUSY',
        message: 'Recovery sedang diproses oleh antrean keamanan. Silakan tunggu sebentar.',
        queue: {
          status: 'busy',
          waited_ms: Number(queueTicket && queueTicket.waited_ms || 0),
          retry_after_seconds: Math.max(1, Math.ceil(customerSecurityLostPasskeyQueuePollMsV164() / 1000))
        }
      });
    }
    try {
      return await customerSecurityGenerateRecoveryCodes(req, res, 'customer_security_recovery_codes_generate', {
        localWorker: true,
        access: { customerId: owner.customerId },
        owner,
        activePasskeys,
        bindings,
        argonQueueTicket: queueTicket,
        passwordLatestMaterial: String(body.password_latest_material || body.password_latest_proof || body.account_password || '')
      });
    } finally {
      try { await queueTicket.release(); } catch (_) {}
    }
  }

  if (workerTask === DIRAC_RECOVERY_WORKER_TASK_VERIFY) {
    const queueTicket = await customerSecurityLostPasskeyQueueAcquireV164(req, body);
    if (!queueTicket || !queueTicket.ok) {
      return res.status(queueTicket && queueTicket.status || 503).json({
        ok: false,
        code: 'RECOVERY_ARGON2_BUSY',
        message: 'Verifikasi recovery sedang diproses. Silakan coba kembali.'
      });
    }
    try {
      return await customerSecurityVerifyRecoveryCodeLocalWorker(req, res, 'customer_security_recovery_code_verify', {
        access: { customerId: owner.customerId },
        owner,
        bindings,
        requestId: String(body.request_id || ''),
        recoveryCode: String(body.recovery_code || body.code || ''),
        argonQueueTicket: queueTicket
      });
    } finally {
      try { await queueTicket.release(); } catch (_) {}
    }
  }

  if (workerTask === DIRAC_RECOVERY_WORKER_TASK_FINALIZE) {
    const queueTicket = await customerSecurityLostPasskeyQueueAcquireV164(req, body);
    if (!queueTicket || !queueTicket.ok) {
      return res.status(queueTicket && queueTicket.status || 503).json({
        ok: false,
        code: 'RECOVERY_ARGON2_BUSY',
        message: 'Finalisasi recovery sedang diproses. Silakan coba kembali.'
      });
    }
    try {
      return await customerSecurityFinalizeRecoveryLocalWorkerV162(req, res, 'customer_security_recovery_code_finalize', {
        access: { customerId: owner.customerId },
        owner,
        bindings,
        requestId: String(body.request_id || ''),
        argonQueueTicket: queueTicket
      });
    } finally {
      try { await queueTicket.release(); } catch (_) {}
    }
  }

  return res.status(404).json({ ok: false, code: 'RECOVERY_WORKER_TASK_INVALID', message: 'Worker task recovery tidak valid.' });
}

/* source 29107-29107 */
const DIRAC_CENTRAL_SECURITY_GUARD_V146 = 'dirac-central-security-guard-v146';

/* source 29114-29114 */
const DIRAC_CENTRAL_CONTEXT_STACK_V146 = globalThis.__DIRAC_CENTRAL_CONTEXT_STACK_V146__ || [];

/* source 29115-29122 */
const DIRAC_CENTRAL_ASYNC_CONTEXT_V149 = globalThis.__DIRAC_CENTRAL_ASYNC_CONTEXT_V149__ || (() => {
  try {
    const { AsyncLocalStorage } = require('async_hooks');
    return new AsyncLocalStorage();
  } catch (_) {
    return null;
  }
})();

/* source 29123-29123 */
const DIRAC_CENTRAL_SECRET_CACHE_V146 = globalThis.__DIRAC_CENTRAL_SECRET_CACHE_V146__ || new Map();

/* source 29133-29133 */
globalThis.__DIRAC_CENTRAL_CONTEXT_STACK_V146__ = DIRAC_CENTRAL_CONTEXT_STACK_V146;

/* source 29134-29134 */
globalThis.__DIRAC_CENTRAL_ASYNC_CONTEXT_V149__ = DIRAC_CENTRAL_ASYNC_CONTEXT_V149;

/* source 29135-29135 */
globalThis.__DIRAC_CENTRAL_SECRET_CACHE_V146__ = DIRAC_CENTRAL_SECRET_CACHE_V146;

/* source 29184-29186 */
const DIRAC_CENTRAL_SERVER2_RECOVERY_ACTIONS_V157 = new Set([
  DIRAC_RECOVERY_WORKER_ACTION
]);

/* source 29188-29190 */
const DIRAC_CENTRAL_SERVER2_RECOVERY_LINK_ACTIONS_V165 = new Set([
  DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
]);

/* source 29192-29195 */
const DIRAC_CENTRAL_ENV_VERCEL2_ONLY_ACTIONS_V174 = new Set([
  ...diracCentralEnvCsvV150('DIRAC_CENTRAL_VERCEL2_ONLY_ACTIONS'),
  ...diracCentralEnvCsvV150('DIRAC_VERCEL2_ONLY_ACTIONS')
]);

/* source 29197-29201 */
const DIRAC_CENTRAL_COMPILED_VERCEL2_ACTIONS_V188 = new Set([
  DIRAC_RECOVERY_WORKER_ACTION,
  DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165,
  'customer_security_recovery_hpke_verify'
]);

/* source 29203-29203 */
const DIRAC_CENTRAL_ACTION_ALIASES_V146 = Object.freeze({});

/* source 29205-29205 */
const DIRAC_SECURITY_REPORT_ACTION_V186 = 'security_report';

/* source 29208-29213 */
const DIRAC_CENTRAL_ACTIVE_ACTIONS_V146 = new Set([
  ...DIRAC_CENTRAL_COMPILED_VERCEL2_ACTIONS_V188
]);

/* source 29215-29215 */
const DIRAC_CENTRAL_DISABLED_ACTIONS_V146 = new Set([]);

/* source 29224-29227 */
const DIRAC_CENTRAL_KNOWN_JS_ACTION_INPUTS_V146 = [
  DIRAC_RECOVERY_WORKER_ACTION,
  DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
];

/* source 29229-29235 */
const DIRAC_CENTRAL_KNOWN_ACTION_INPUTS_V146 = new Set([
  ...DIRAC_CENTRAL_KNOWN_JS_ACTION_INPUTS_V146,
  ...DIRAC_CENTRAL_ACTIVE_ACTIONS_V146,
  ...DIRAC_CENTRAL_DISABLED_ACTIONS_V146,
  ...Object.keys(DIRAC_CENTRAL_ACTION_ALIASES_V146),
  ...Object.values(DIRAC_CENTRAL_ACTION_ALIASES_V146)
]);

/* source 29279-29287 */
try {
  const __diracCentralPreviousV143ThreatV146 = typeof diracV143DetectRequestThreat === 'function' ? diracV143DetectRequestThreat : null;
  if (__diracCentralPreviousV143ThreatV146 && !__diracCentralPreviousV143ThreatV146.__diracCentralPassthroughV146) {
    diracV143DetectRequestThreat = function diracV143DetectRequestThreatCentralPassthroughV146(req, action, method) {
      return __diracCentralPreviousV143ThreatV146(req, action, method);
    };
    Object.defineProperty(diracV143DetectRequestThreat, '__diracCentralPassthroughV146', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 29289-29297 */
try {
  const __diracCentralPreviousV143InspectOwnershipV146 = typeof diracV143InspectOwnership === 'function' ? diracV143InspectOwnership : null;
  if (__diracCentralPreviousV143InspectOwnershipV146 && !__diracCentralPreviousV143InspectOwnershipV146.__diracCentralPassthroughV146) {
    diracV143InspectOwnership = async function diracV143InspectOwnershipCentralPassthroughV146(req, body) {
      return __diracCentralPreviousV143InspectOwnershipV146(req, body);
    };
    Object.defineProperty(diracV143InspectOwnership, '__diracCentralPassthroughV146', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 29386-29396 */
function diracCentralSupabaseRequestCacheKeyV151(path, options = {}) {
  const method = String(options && options.method || 'GET').toUpperCase();
  if (method !== 'GET') return '';

  const rawPath = String(path || '');
  if (!diracCentralIsRequestCacheableSupabaseReadV151(rawPath)) return '';

  const authMode = String(options && options.auth || 'anon');
  const bearerHash = loginSecurityHash(String(options && options.bearer || 'default'));
  return ['supabase-read-v151', method, authMode, bearerHash, rawPath].join('|');
}

/* source 29398-29405 */
function diracCentralIsRequestCacheableSupabaseReadV151(path) {
  const value = String(path || '');
  return /^\/auth\/v1\/user(?:$|[?#])/.test(value)
    || /^\/rest\/v1\/security_customer_auth_links(?:$|[?#])/.test(value)
    || /^\/rest\/v1\/security_customer_sessions(?:$|[?#])/.test(value)
    || /^\/rest\/v1\/products(?:$|[?#])/.test(value)
    || /^\/rest\/v1\/domain_tld_prices(?:$|[?#])/.test(value);
}

/* source 29407-29414 */
function diracCentralCloneSupabaseResultV151(result) {
  if (!result || typeof result !== 'object') return result;
  const cloned = { ...result };
  if (Object.prototype.hasOwnProperty.call(cloned, 'data')) {
    cloned.data = diracCentralJsonCloneV151(cloned.data);
  }
  return cloned;
}

/* source 29416-29423 */
function diracCentralJsonCloneV151(value) {
  if (value === null || value === undefined) return value;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (_) {
    return value;
  }
}

/* source 29438-29444 */
function diracCentralCurrentContextV149() {
  try {
    const store = DIRAC_CENTRAL_ASYNC_CONTEXT_V149 && DIRAC_CENTRAL_ASYNC_CONTEXT_V149.getStore();
    if (store && store.ctx) return store.ctx;
  } catch (_) {}
  return DIRAC_CENTRAL_CONTEXT_STACK_V146[DIRAC_CENTRAL_CONTEXT_STACK_V146.length - 1];
}

/* source 29965-29976 */
function diracCentralNormalizeTrustedIpV185(value) {
  let clean = String(value || '').split(',')[0].trim();
  if (!clean) return '';
  if (/^\[[0-9a-f:]+\](?::\d+)?$/i.test(clean)) clean = clean.slice(1, clean.indexOf(']'));
  if (/^::ffff:\d{1,3}(?:\.\d{1,3}){3}$/i.test(clean)) clean = clean.slice(7);
  try {
    const isIp = require('net').isIP(clean);
    return isIp ? clean.toLowerCase() : '';
  } catch (_) {
    return /^[0-9a-f:.]{3,64}$/i.test(clean) ? clean.toLowerCase() : '';
  }
}

/* source 29978-29989 */
function diracCentralTrustedClientIpV183(req) {
  const headers = req && req.headers || {};
  const vercelForwarded = diracCentralNormalizeTrustedIpV185(headers['x-vercel-forwarded-for']);
  if (vercelForwarded) return vercelForwarded;
  if (process.env.NODE_ENV === 'production') return 'unknown';
  const forwarded = diracCentralNormalizeTrustedIpV185(headers['x-forwarded-for']);
  if (forwarded) return forwarded;
  const realIp = diracCentralNormalizeTrustedIpV185(headers['x-real-ip']);
  if (realIp) return realIp;
  const socketIp = diracCentralNormalizeTrustedIpV185(req && req.socket && req.socket.remoteAddress);
  return socketIp || 'unknown';
}

/* source 30285-30290 */
function diracCentralEnvCsvV150(name) {
  return String(process.env[name] || '')
    .split(/[\s,]+/)
    .map((item) => item.trim().toLowerCase())
    .filter((item) => /^[a-z0-9_-]{1,80}$/.test(item));
}

/* source 30292-30294 */
function diracCentralEnvValueV150(name) {
  return String(process.env[name] || '').trim().toLowerCase();
}

/* source 30296-30298 */
function diracCentralEnvTrueV150(name) {
  return /^(1|true|yes|on|enabled|enable)$/i.test(String(process.env[name] || '').trim());
}

/* source 30636-30667 */
async function diracCentralRecoveryWorkerClaimNonceV183(caller, nonce, usedUntilMs) {
  const table = DIRAC_S2S_SECURITY_TABLE;
  if (table !== 'dirac_s2s_security') return { ok: false, reason: 'recovery_worker_nonce_table_missing' };
  const nonceDigest = customerSecurityLostPasskeySha256HexV157(String(caller || '') + ':' + String(nonce || ''));
  const securityKey = 'recovery-worker-nonce-v183:' + nonceDigest;
  const now = Date.now();
  const expiresAtMs = Math.max(now + 60_000, Number(usedUntilMs || 0));
  const payload = [{
    security_key: securityKey,
    record_json: {
      type: 'recovery_worker_nonce_claim_v183',
      caller_hash: customerSecurityLostPasskeySha256HexV157(String(caller || '')),
      nonce_hash: customerSecurityLostPasskeySha256HexV157(String(nonce || '')),
      claimed_at_ms: now,
      used_until_ms: expiresAtMs
    },
    blocked_until_ms: expiresAtMs,
    updated_at: new Date(now).toISOString(),
    expires_at: new Date(expiresAtMs + 24 * 60 * 60 * 1000).toISOString()
  }];
  const result = await supabaseFetch('/rest/v1/' + encodeURIComponent(table) + '?on_conflict=security_key', {
    method: 'POST',
    auth: 'service',
    prefer: 'resolution=ignore-duplicates,return=representation',
    body: payload
  }).catch(() => null);
  if (!result || !result.ok) return { ok: false, reason: 'recovery_worker_nonce_persist_failed' };
  if (!Array.isArray(result.data) || !result.data.some((row) => String(row && row.security_key || '') === securityKey)) {
    return { ok: false, reason: 'recovery_worker_nonce_replay' };
  }
  return { ok: true, key: securityKey };
}

/* source 31760-31786 */
async function diracCentralResolveOwnerV146(req) {
  try {
    if (typeof diracBolaIdorV133ResolveStrictOwner === 'function') {
      const owner = await diracBolaIdorV133ResolveStrictOwner(req);
      if (owner && owner.ok && owner.customerIds && owner.customerIds.length) return owner;
    }
  } catch (_) {}
  try {
    if (typeof diracBolaIdorV128ResolveRequestOwner === 'function') {
      const owner = await diracBolaIdorV128ResolveRequestOwner(req);
      if (owner && owner.ok && owner.customerIds && owner.customerIds.length) return owner;
    }
  } catch (_) {}
  if (typeof requireDomainUser !== 'function' || typeof customerSecurityFetchAuthLink !== 'function') return { ok: false };
  const fake = diracCentralFakeResponseV146();
  const user = await requireDomainUser(req, fake).catch(() => null);
  const authUserId = String(user && user.id || '').trim();
  if (!diracCentralLooksLikeUuidV146(authUserId)) return { ok: false };
  const link = await customerSecurityFetchAuthLink(authUserId).catch(() => null);
  const rows = link && link.ok && Array.isArray(link.data) ? link.data.filter((row) => row && String(row.link_status || '').toLowerCase() === 'active' && !row.disabled_at && !row.revoked_at) : [];
  const customerIds = Array.from(new Set(rows
    .map((row) => String(row.customer_id || '').trim())
    .filter(diracCentralLooksLikeUuidV146)));
  if (rows.length === 0 || customerIds.length === 0) return { ok: false, reason: 'owner_unavailable' };
  if (rows.length > 1 || customerIds.length > 1) return { ok: false, reason: 'owner_ambiguous' };
  return { ok: true, authUserId, customerIds };
}

/* source 31884-31903 */
function diracCentralIsDashboardSelfReadAuthLinkWriteV146(ctx, table, options, method, protectedFields) {
  const action = String(ctx && ctx.action || '').trim().toLowerCase();
  const requestMethod = String(ctx && ctx.method || '').trim().toUpperCase();
  const cleanTable = String(table || '').trim().toLowerCase();
  const fields = Array.isArray(protectedFields) ? protectedFields : [];
  if (action !== 'domain_me' && action !== 'domain_dashboard_me') return false;
  if (requestMethod !== 'GET' && requestMethod !== 'HEAD') return false;
  if (!ctx || !ctx.req || ctx.req.__diracCentralSecurityGuardPassedV146 !== true) return false;
  if (cleanTable !== 'security_customer_auth_links') return false;
  if (method !== 'POST' && method !== 'PATCH') return false;
  if (!fields.length || fields.some((key) => !/^auth_user_id$/i.test(String(key || '')))) return false;
  const rows = Array.isArray(options && options.body) ? options.body : [options && options.body];
  return rows.length > 0 && rows.length <= 3 && rows.every((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    const authUserId = String(row.auth_user_id || '').trim();
    const customerId = String(row.customer_id || '').trim();
    if (!diracCentralLooksLikeUuidV146(authUserId) || !diracCentralLooksLikeUuidV146(customerId)) return false;
    return Object.keys(row).every((key) => /^(auth_user_id|customer_id|email|link_status|link_method|match_confidence|verified_at|updated_at)$/i.test(String(key || '')));
  });
}

/* source 31905-31961 */
async function diracCentralInspectServiceRoleAccessV146(path, options = {}) {
  if (!options || options.auth !== 'service') return { ok: true };
  const ctx = diracCentralCurrentContextV149();
  if (!ctx) return { block: true, reason: 'service_role_central_context_required', status: 503 };
  if (!ctx.__serviceGuardActive && ctx.action === 'midtrans_webhook') return { ok: true };
  const table = diracCentralExtractRestTableV146(path);
  if (!diracCentralOwnedTableV146(table)) return { ok: true };
  const method = String(options.method || 'GET').toUpperCase();
  if (diracCentralIsInternalOwnerLookupV194(ctx, table, path, options, method)) {
    return { ok: true, guarded: 'central_owner_lookup_v194' };
  }
  if (diracCentralIsRegisterBootstrapServiceRoleV146(ctx, table, path, options, method)) return { ok: true, guarded: 'domain_register_bootstrap_service_role' };
  if (diracCentralIsCheckoutOwnerBootstrapServiceRoleV146(ctx, table, path, options, method)) return { ok: true, guarded: 'checkout_owner_bootstrap_service_role' };
  if (diracCentralIsCheckoutOrderCreateServiceRoleV146(ctx, table, path, options, method)) return { ok: true, guarded: 'checkout_order_create_service_role' };
  if (diracCentralIsPasskeyServiceRoleV146(ctx, table, path, options, method)) return { ok: true, guarded: 'passkey_owner_scoped_service_role' };
  const hasOwnerScope = diracCentralPathHasOwnerScopeV146(path, options.body);
  const hasObjectScope = diracCentralPathHasObjectScopeV146(path, options.body);
  if (!hasOwnerScope && !hasObjectScope) {
    await diracCentralBanCurrentContextV146('service_role_without_owner_scope').catch(() => null);
    return { block: true, reason: 'service_role_without_owner_scope', status: 403 };
  }
  const ownerScope = await diracCentralServiceRoleOwnerScopeGuardV146(ctx, path, options.body).catch(() => ({ ok: false, reason: 'service_role_owner_scope_error' }));
  if (!ownerScope.ok) {
    await diracCentralBanCurrentContextV146(ownerScope.reason || 'service_role_owner_scope_mismatch').catch(() => null);
    return { block: true, reason: ownerScope.reason || 'service_role_owner_scope_mismatch', status: 403 };
  }
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    const fields = diracCentralFlattenObjectV146(options.body || {}, 0, '', 200).map((item) => item.key.split('.').pop());
    if (fields.some(diracCentralProtectedFieldV146)) {
      const protectedFields = fields.filter(diracCentralProtectedFieldV146);
      const rows = Array.isArray(options.body) ? options.body : [options.body];
      const allowCreatePaymentUnpaid = String(ctx && ctx.action || '').toLowerCase() === 'create_payment'
        && String(table || '').toLowerCase() === 'payment_transactions'
        && method === 'POST'
        && protectedFields.every((key) => /^payment_status$/i.test(String(key || '')))
        && rows.length > 0
        && rows.length <= 3
        && rows.every((row) => {
          const amount = Number(row && row.amount);
          const status = String(row && row.payment_status || '').trim().toLowerCase();
          const customerId = String(row && row.customer_id || '').trim();
          const reference = String(row && row.gateway_reference || '').trim();
          return row && typeof row === 'object' && !Array.isArray(row)
            && status === 'unpaid'
            && Number.isFinite(amount) && amount > 0
            && diracCentralLooksLikeUuidV146(customerId)
            && /^[A-Za-z0-9._:@-]{3,120}$/.test(reference);
        });
      const allowDashboardSelfReadAuthLink = diracCentralIsDashboardSelfReadAuthLinkWriteV146(ctx, table, options, method, protectedFields);
      if (!allowCreatePaymentUnpaid && !allowDashboardSelfReadAuthLink) {
        await diracCentralBanCurrentContextV146('service_role_protected_field').catch(() => null);
        return { block: true, reason: 'service_role_protected_field', status: 403 };
      }
    }
  }
  return { ok: true };
}

/* source 31963-31972 */
function diracCentralIsInternalOwnerLookupV194(ctx, table, path, options, method) {
  if (!ctx || ctx.__diracCentralOwnerLookupV194 !== true || method !== 'GET') return false;
  if (options && options.body !== undefined && options.body !== null) return false;
  if (!/^(orders|domain_orders|payment_transactions|security_customer_sessions|security_customer_recovery_codes)$/.test(String(table || ''))) return false;
  const raw = String(path || '');
  return raw.startsWith('/rest/v1/' + table + '?')
    && /[?&]select=/.test(raw)
    && /[?&]or=/.test(raw)
    && /[?&]limit=80(?:&|$)/.test(raw);
}

/* source 31974-32001 */
async function diracCentralServiceRoleOwnerScopeGuardV146(ctx, path, body) {
  if (!ctx || ctx.classification === 'server') return { ok: true };
  if (ctx.__diracCentralOwnerScopeResolvingV146 === true) return { ok: true, guarded: 'owner_scope_internal_lookup' };
  const ids = diracCentralExtractServiceRoleScopeIdsV146(path, body);
  if (!ids.customerIds.length && !ids.authUserIds.length && !ids.userIds.length && !ids.objectValues.length) return { ok: true };
  let owner = null;
  ctx.__diracCentralOwnerScopeResolvingV146 = true;
  try {
    owner = await diracCentralResolveOwnerV146(ctx.req).catch(() => null);
  } finally {
    ctx.__diracCentralOwnerScopeResolvingV146 = false;
  }
  if (!owner || !owner.ok || !owner.customerIds || !owner.customerIds.length) return { ok: false, reason: 'service_role_owner_unavailable' };
  const allowedCustomers = new Set(owner.customerIds.map(String));
  if (ids.customerIds.some((id) => !allowedCustomers.has(id))) return { ok: false, reason: 'service_role_customer_scope_mismatch' };
  const expectedAuthUser = String(owner.authUserId || '').trim();
  const authIds = ids.authUserIds.concat(ids.userIds);
  if (authIds.length && (!expectedAuthUser || authIds.some((id) => id !== expectedAuthUser))) {
    return { ok: false, reason: 'service_role_auth_user_scope_mismatch' };
  }
  if (ids.objectValues.length) {
    const approved = ctx.__diracCentralOwnerBoundObjectValuesV194;
    if (!(approved instanceof Set) || ids.objectValues.some((value) => !approved.has(value))) {
      return { ok: false, reason: 'service_role_object_scope_unbound' };
    }
  }
  return { ok: true };
}

/* source 32003-32036 */
function diracCentralExtractServiceRoleScopeIdsV146(path, body) {
  const out = { customerIds: [], authUserIds: [], userIds: [], objectValues: [] };
  const add = (bucket, value) => {
    const clean = String(value || '').trim();
    if (diracCentralLooksLikeUuidV146(clean) && !out[bucket].includes(clean)) out[bucket].push(clean);
  };
  const addObject = (value) => {
    const clean = String(value || '').trim();
    if (/^[A-Za-z0-9._:@-]{1,160}$/.test(clean) && !/^(?:null|true|false)$/i.test(clean) && !out.objectValues.includes(clean)) out.objectValues.push(clean);
  };
  const raw = String(path || '');
  try {
    const query = raw.includes('?') ? raw.slice(raw.indexOf('?') + 1) : '';
    for (const part of query.split('&')) {
      const [k, v] = part.split('=');
      const key = decodeURIComponent(k || '').toLowerCase();
      const value = decodeURIComponent(String(v || '')).replace(/^(?:eq|is)\./i, '').replace(/^in\.\(|\)$/g, '');
      value.split(',').forEach((item) => {
        if (key === 'customer_id') add('customerIds', item);
        if (key === 'auth_user_id') add('authUserIds', item);
        if (key === 'user_id') add('userIds', item);
        if (/^(id|order_id|order_code|domain_order_id|payment_id|transaction_id|invoice_id|gateway_reference|session_id|recovery_code_id)$/.test(key)) addObject(item);
      });
    }
  } catch (_) {}
  diracCentralFlattenObjectV146(body || {}, 0, '', 200).forEach((item) => {
    const key = String(item.key || '').split('.').pop().toLowerCase();
    if (key === 'customer_id') add('customerIds', item.value);
    if (key === 'auth_user_id') add('authUserIds', item.value);
    if (key === 'user_id') add('userIds', item.value);
    if (/^(id|order_id|order_code|domain_order_id|payment_id|transaction_id|invoice_id|gateway_reference|session_id|recovery_code_id)$/.test(key)) addObject(item.value);
  });
  return out;
}

/* source 32038-32113 */
function diracCentralIsRegisterBootstrapServiceRoleV146(ctx, table, path, options = {}, method) {
  const action = String(ctx && ctx.action || '').toLowerCase();
  if (action !== 'domain_register' && action !== 'domain_login') return false;
  const cleanTable = String(table || '').toLowerCase();
  const cleanMethod = String(method || options.method || 'GET').toUpperCase();
  const rawPath = String(path || '').toLowerCase();
  const body = options.body;

  if (cleanTable === 'customers') {
    if (cleanMethod === 'GET') return /[?&]email=eq\./.test(rawPath);
    if (cleanMethod !== 'POST') return false;
    return diracCentralBodyRowsSafeV146(body, ['name', 'email', 'phone'], (row) => {
      const email = String(row.email || '').trim();
      return !!email && diracCentralValidateFieldFormatV146('email', email).ok;
    });
  }

  if (cleanTable === 'security_customer_auth_links') {
    if (cleanMethod === 'GET') return /[?&]auth_user_id=eq\./.test(rawPath);
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, ['auth_user_id', 'customer_id', 'email', 'link_status', 'link_method', 'match_confidence'], (row) => {
      if (row.auth_user_id && !diracCentralLooksLikeUuidV146(row.auth_user_id)) return false;
      if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.email && !diracCentralValidateFieldFormatV146('email', row.email).ok) return false;
      if (row.link_status && String(row.link_status).toLowerCase() !== 'active') return false;
      return true;
    });
  }

  if (cleanTable === 'security_customer_password_hashes') {
    return diracCentralIsAuthPasswordHashServiceRoleV146(ctx, path, body, cleanMethod);
  }

  if (cleanTable === 'security_customer_settings') {
    if (cleanMethod === 'GET') return /[?&]customer_id=eq\./.test(rawPath);
    if (cleanMethod === 'PATCH' && !/[?&](?:id|customer_id)=eq\./.test(rawPath)) return false;
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, [
      'customer_id',
      'two_factor_enabled',
      'two_factor_method',
      'last_security_check_at',
      'created_at',
      'updated_at'
    ], (row) => {
      if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.two_factor_enabled !== undefined && typeof row.two_factor_enabled !== 'boolean') return false;
      if (row.two_factor_method && !/^(authenticator|passkey)$/i.test(String(row.two_factor_method))) return false;
      return Boolean(row.customer_id || /[?&](?:id|customer_id)=eq\./.test(rawPath));
    });
  }

  if (cleanTable === 'security_customer_login_logs') {
    if (cleanMethod !== 'POST') return false;
    return diracCentralBodyRowsSafeV146(body, [
      'customer_id',
      'device_name',
      'browser_name',
      'operating_system',
      'user_agent',
      'ip_address',
      'event_type',
      'status',
      'risk_level',
      'metadata'
    ], (row) => {
      if (!diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.event_type && !/^(login_success|register_success)$/i.test(String(row.event_type))) return false;
      if (row.status && String(row.status).toLowerCase() !== 'success') return false;
      if (row.risk_level && !/^(low|medium)$/i.test(String(row.risk_level))) return false;
      return true;
    });
  }

  return false;
}

/* source 32115-32141 */
function diracCentralIsCheckoutOwnerBootstrapServiceRoleV146(ctx, table, path, options = {}, method) {
  if (!ctx || ctx.action !== 'checkout_order' || ctx.__diracCentralCheckoutOwnerBootstrapV146 !== true) return false;
  const cleanTable = String(table || '').toLowerCase();
  const cleanMethod = String(method || options.method || 'GET').toUpperCase();
  const rawPath = String(path || '').toLowerCase();
  const body = options.body;
  if (cleanTable === 'customers') {
    if (cleanMethod === 'GET') return /[?&]email=eq\./.test(rawPath);
    if (cleanMethod !== 'POST') return false;
    return diracCentralBodyRowsSafeV146(body, ['name', 'email', 'phone'], (row) => {
      const email = String(row.email || '').trim();
      return !!email && diracCentralValidateFieldFormatV146('email', email).ok;
    });
  }
  if (cleanTable === 'security_customer_auth_links') {
    if (cleanMethod === 'GET') return /[?&]auth_user_id=eq\./.test(rawPath);
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, ['auth_user_id', 'customer_id', 'email', 'link_status', 'link_method', 'match_confidence'], (row) => {
      if (row.auth_user_id && !diracCentralLooksLikeUuidV146(row.auth_user_id)) return false;
      if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.email && !diracCentralValidateFieldFormatV146('email', row.email).ok) return false;
      if (row.link_status && String(row.link_status).toLowerCase() !== 'active') return false;
      return true;
    });
  }
  return false;
}

/* source 32143-32155 */
function diracCentralIsCheckoutOrderCreateServiceRoleV146(ctx, table, path, options = {}, method) {
  if (!ctx || ctx.action !== 'checkout_order' || !ctx.req || ctx.req.__diracCentralSecurityGuardPassedV146 !== true) return false;
  const cleanTable = String(table || '').toLowerCase();
  const cleanMethod = String(method || options.method || 'GET').toUpperCase();
  if (cleanMethod !== 'POST') return false;
  if (cleanTable === 'orders') {
    return diracCentralCheckoutOrderRowsSafeV146(options.body);
  }
  if (cleanTable === 'order_items') {
    return diracCentralCheckoutOrderItemRowsSafeV152(options.body);
  }
  return false;
}

/* source 32157-32189 */
function diracCentralCheckoutOrderRowsSafeV146(body) {
  const rows = Array.isArray(body) ? body : [body];
  const allowed = new Set([
    'order_id',
    'customer_id',
    'customer_name',
    'customer_phone',
    'customer_email',
    'shipping_address',
    'service_type',
    'subtotal',
    'shipping_cost',
    'discount',
    'total',
    'note',
    'payment_method',
    'payment_status',
    'order_status'
  ]);
  if (rows.length !== 1) return false;
  return rows.every((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    const keys = Object.keys(row);
    if (!keys.length || keys.some((key) => !allowed.has(String(key || '').toLowerCase()))) return false;
    if (!/^[a-zA-Z0-9._:@-]{3,120}$/.test(String(row.order_id || '').trim())) return false;
    if (!diracCentralLooksLikeUuidV146(row.customer_id)) return false;
    if (row.customer_email && !diracCentralValidateFieldFormatV146('email', row.customer_email).ok) return false;
    if (String(row.payment_method || '') !== 'Belum dipilih') return false;
    if (String(row.payment_status || '').toLowerCase() !== 'unpaid') return false;
    if (String(row.order_status || '').toLowerCase() !== 'pending') return false;
    return ['subtotal', 'shipping_cost', 'discount', 'total'].every((key) => diracCentralIsNonNegativeNumberV146(row[key]));
  });
}

/* source 32192-32217 */
function diracCentralCheckoutOrderItemRowsSafeV152(body) {
  const rows = Array.isArray(body) ? body : [body];
  const allowed = new Set([
    'order_id',
    'product_doc_id',
    'product_title',
    'quantity',
    'unit_price',
    'cost_price'
  ]);
  if (!rows.length || rows.length > 50) return false;
  return rows.every((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    const keys = Object.keys(row);
    if (!keys.length || keys.some((key) => !allowed.has(String(key || '').toLowerCase()))) return false;
    if (!diracCentralLooksLikeUuidV146(row.order_id)) return false;
    if (row.product_doc_id && !/^[A-Za-z0-9._:@-]{1,120}$/.test(String(row.product_doc_id || '').trim())) return false;
    const title = String(row.product_title || '').trim();
    if (!title || title.length > 180 || /[<>]/.test(title)) return false;
    const quantity = Number(row.quantity);
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 999) return false;
    if (!diracCentralIsNonNegativeNumberV146(row.unit_price)) return false;
    if (!diracCentralIsNonNegativeNumberV146(row.cost_price)) return false;
    return true;
  });
}

/* source 32219-32222 */
function diracCentralIsNonNegativeNumberV146(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0;
}

/* source 32224-32361 */
function diracCentralIsPasskeyServiceRoleV146(ctx, table, path, options = {}, method) {
  const action = String(ctx && ctx.action || '').toLowerCase();
  if (!DIRAC_CENTRAL_SERVER2_RECOVERY_ACTIONS_V157.has(action)) return false;
  const cleanTable = String(table || '').toLowerCase();
  const cleanMethod = String(method || options.method || 'GET').toUpperCase();
  const rawPath = String(path || '').toLowerCase();
  const body = options.body;

  if (cleanTable === 'security_customer_auth_links') {
    return cleanMethod === 'GET' && /[?&](?:auth_user_id|customer_id|email)=eq\./.test(rawPath);
  }

  if (cleanTable === 'customers') {
    return cleanMethod === 'GET' && /[?&](?:id|email)=eq\./.test(rawPath);
  }

  if (cleanTable === 'domain_passkeys') {
    if (cleanMethod === 'GET') {
      return /[?&](?:user_id|email|credential_id|id)=eq\./.test(rawPath);
    }
    if (cleanMethod === 'PATCH' && !/[?&](?:id|credential_id|user_id)=eq\./.test(rawPath)) return false;
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, [
      'user_id',
      'email',
      'credential_id',
      'credential_json',
      'transports',
      'sign_count',
      'is_active',
      'created_at',
      'updated_at',
      'last_used_at'
    ], (row) => {
      if (row.user_id && !diracCentralLooksLikeUuidV146(row.user_id)) return false;
      if (row.email && !diracCentralValidateFieldFormatV146('email', row.email).ok) return false;
      if (row.credential_id && String(row.credential_id).length > 4096) return false;
      if (row.is_active !== undefined && typeof row.is_active !== 'boolean') return false;
      if (row.sign_count !== undefined && (!Number.isFinite(Number(row.sign_count)) || Number(row.sign_count) < 0)) return false;
      return Boolean(row.user_id || row.email || /[?&](?:id|credential_id|user_id)=eq\./.test(rawPath));
    });
  }

  if (cleanTable === 'security_customer_settings') {
    if (cleanMethod === 'GET') return /[?&]customer_id=eq\./.test(rawPath);
    if (cleanMethod === 'PATCH' && !/[?&](?:id|customer_id)=eq\./.test(rawPath)) return false;
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, [
      'customer_id',
      'two_factor_enabled',
      'two_factor_method',
      'last_security_check_at',
      'created_at',
      'updated_at'
    ], (row) => {
      if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.two_factor_enabled !== undefined && typeof row.two_factor_enabled !== 'boolean') return false;
      if (row.two_factor_method && String(row.two_factor_method).toLowerCase() !== 'passkey') return false;
      return Boolean(row.customer_id || /[?&](?:id|customer_id)=eq\./.test(rawPath));
    });
  }

  if (cleanTable === 'security_lost_passkey_recovery_requests') {
    if (cleanMethod === 'GET') return /[?&](?:request_id|customer_id|auth_user_id)=eq\./.test(rawPath);
    if (cleanMethod === 'PATCH' && !/[?&](?:request_id|customer_id|auth_user_id)=eq\./.test(rawPath)) return false;
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, [
      'request_id',
      'customer_id',
      'auth_user_id',
      'email_hash',
      'customer_binding_hash',
      'auth_user_binding_hash',
      'device_binding_hash',
      'ip_hash',
      'user_agent_hash',
      'recovery_code_hash',
      'encrypted_file_key_text',
      'file_key_wrap_nonce',
      'file_key_wrap_tag',
      'salt',
      'owner_key_salt',
      'dek_seed_wrapped',
      'dek_wrap_nonce',
      'dek_wrap_tag',
      'payload_nonce',
      'payload_auth_tag',
      'file_sha256',
      'aad_hash',
      'server_signature',
      'old_passkey_ids',
      'status',
      'attempt_count',
      'sent_at',
      'locked_at',
      'used_at',
      'revoked_at',
      'created_at',
      'expires_at',
      'metadata'
    ], (row) => {
      if (row.request_id && !/^[a-zA-Z0-9_-]{16,120}$/.test(String(row.request_id))) return false;
      if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.auth_user_id && !diracCentralLooksLikeUuidV146(row.auth_user_id)) return false;
      if (row.status && !/^(pending|verified|used|locked|revoked)$/i.test(String(row.status))) return false;
      if (row.attempt_count !== undefined && (!Number.isFinite(Number(row.attempt_count)) || Number(row.attempt_count) < 0)) return false;
      return Boolean(row.request_id || row.customer_id || row.auth_user_id || /[?&](?:request_id|customer_id|auth_user_id)=eq\./.test(rawPath));
    });
  }

  if (cleanTable === 'security_lost_passkey_recovery_sessions') {
    if (cleanMethod === 'GET') return /[?&](?:request_id|customer_id|auth_user_id)=eq\./.test(rawPath);
    if (cleanMethod === 'PATCH' && !/[?&](?:request_id|customer_id|auth_user_id)=eq\./.test(rawPath)) return false;
    if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
    return diracCentralBodyRowsSafeV146(body, [
      'request_id',
      'customer_id',
      'auth_user_id',
      'recovery_session_hash',
      'purpose',
      'status',
      'created_at',
      'expires_at',
      'used_at',
      'revoked_at',
      'metadata'
    ], (row) => {
      if (row.request_id && !/^[a-zA-Z0-9_-]{16,120}$/.test(String(row.request_id))) return false;
      if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
      if (row.auth_user_id && !diracCentralLooksLikeUuidV146(row.auth_user_id)) return false;
      if (row.purpose && String(row.purpose) !== LOST_PASSKEY_RECOVERY_PURPOSE) return false;
      if (row.status && !/^(verified|used|revoked|expired)$/i.test(String(row.status))) return false;
      return Boolean(row.request_id || row.customer_id || row.auth_user_id || /[?&](?:request_id|customer_id|auth_user_id)=eq\./.test(rawPath));
    });
  }

  return false;
}

/* source 32363-32389 */
function diracCentralIsAuthPasswordHashServiceRoleV146(ctx, path, body, method) {
  const action = String(ctx && ctx.action || '').toLowerCase();
  if (action !== 'domain_register' && action !== 'domain_login') return false;
  const cleanMethod = String(method || 'GET').toUpperCase();
  const rawPath = String(path || '').toLowerCase();
  if (cleanMethod === 'GET' || cleanMethod === 'DELETE') return /[?&]auth_user_id=eq\./.test(rawPath);
  if (cleanMethod === 'PATCH' && !/[?&]auth_user_id=eq\./.test(rawPath)) return false;
  if (cleanMethod !== 'POST' && cleanMethod !== 'PATCH') return false;
  return diracCentralBodyRowsSafeV146(body, [
    'auth_user_id',
    'customer_id',
    'email_hash',
    'password_hash',
    'hash_algorithm',
    'hash_params',
    'status',
    'created_at',
    'updated_at'
  ], (row) => {
    if (row.auth_user_id && !diracCentralLooksLikeUuidV146(row.auth_user_id)) return false;
    if (row.customer_id && !diracCentralLooksLikeUuidV146(row.customer_id)) return false;
    if (row.password_hash && !String(row.password_hash || '').startsWith('$argon2id$')) return false;
    if (row.hash_algorithm && String(row.hash_algorithm).toLowerCase() !== 'argon2id') return false;
    if (row.status && !/^(active|rotated)$/i.test(String(row.status))) return false;
    return true;
  });
}

/* source 32391-32406 */
function diracCentralBodyRowsSafeV146(body, allowedKeys, validateRow) {
  const rows = Array.isArray(body) ? body : [body];
  const allowed = new Set((allowedKeys || []).map((key) => String(key || '').toLowerCase()));
  if (!rows.length || rows.length > 3) return false;
  return rows.every((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    const keys = Object.keys(row);
    if (!keys.length || keys.length > allowed.size) return false;
    if (keys.some((key) => !allowed.has(String(key || '').toLowerCase()))) return false;
    if (keys.some(diracCentralProtectedFieldV146)) {
      const unsafe = keys.filter(diracCentralProtectedFieldV146).some((key) => !/^(auth_user_id)$/i.test(String(key || '')));
      if (unsafe) return false;
    }
    return typeof validateRow === 'function' ? validateRow(row) !== false : true;
  });
}

/* source 32408-32415 */
function diracCentralBlockedSupabaseResultV146(decision) {
  return {
    ok: false,
    status: Number(decision && decision.status || 403),
    data: { ok: false, code: 'CENTRAL_SECURITY_SERVICE_ROLE_BLOCKED', message: 'Permintaan ditolak oleh sistem keamanan.' },
    error: 'CENTRAL_SECURITY_SERVICE_ROLE_BLOCKED'
  };
}

/* source 32718-32727 */
async function diracCentralBanCurrentContextV146(reason) {
  const ctx = diracCentralCurrentContextV149();
  if (!ctx) return { ok: false };
  return diracCentralWritePersistentBanV146(ctx.req, ctx.res, ctx.action, ctx.method, {
    detected: true,
    kind: reason,
    source: DIRAC_CENTRAL_SECURITY_GUARD_V146,
    risk: 'critical'
  });
}

/* source 32729-32748 */
async function diracCentralWritePersistentBanV146(req, res, action, method, threat) {
  let lastResult = { ok: false };
  if (typeof diracV107RegisterHardBan === 'function') {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        lastResult = await diracV107RegisterHardBan(req, res || null, action || 'central_security', method || 'GET', threat || {});
        if (lastResult && lastResult.ok === true) return lastResult;
      } catch (_) {}
    }
  }
  if (typeof diracV143WriteGlobalBanOnce === 'function') {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        lastResult = await diracV143WriteGlobalBanOnce(req, res || null, action || 'central_security', method || 'GET', threat || {});
        if (lastResult && lastResult.ok === true) return lastResult;
      } catch (_) {}
    }
  }
  return lastResult && typeof lastResult === 'object' ? lastResult : { ok: false };
}

/* source 32847-32863 */
function diracCentralFlattenObjectV146(value, depth, prefix, max) {
  const out = [];
  const walk = (v, d, p) => {
    if (out.length >= max || d > 6 || v === null || v === undefined) return;
    if (typeof v !== 'object') {
      out.push({ key: p, value: v, depth: d });
      return;
    }
    if (Array.isArray(v)) {
      v.slice(0, 50).forEach((item, index) => walk(item, d + 1, p ? p + '.' + index : String(index)));
      return;
    }
    Object.entries(v).slice(0, 120).forEach(([key, child]) => walk(child, d + 1, p ? p + '.' + key : key));
  };
  walk(value, depth || 0, prefix || '');
  return out;
}

/* source 32865-32876 */
function diracCentralValidateFieldFormatV146(key, value) {
  const clean = String(key || '').toLowerCase();
  const text = String(value === undefined || value === null ? '' : value).trim();
  if (!text) return { ok: true };
  if (clean === 'email' && !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(text)) return { ok: false, reason: 'email_format_invalid' };
  if (/domain/.test(clean) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text)) return { ok: false, reason: 'domain_format_invalid' };
  if (/uuid|customer_id|user_id|auth_user_id|owner_user_id|session_id|recovery_code_id|credential_id|project_id|document_id|item_id/.test(clean) && !diracCentralLooksLikeUuidV146(text)) {
    if (/_id$/.test(clean)) return { ok: false, reason: clean + '_format_invalid' };
  }
  if (/order_code/.test(clean) && !/^[a-zA-Z0-9._:@-]{3,120}$/.test(text)) return { ok: false, reason: 'order_code_format_invalid' };
  return { ok: true };
}

/* source 32878-32880 */
function diracCentralProtectedFieldV146(key) {
  return /^(role|is_admin|admin|owner_id|balance|price|total_price|paid|payment_status|service_role|auth_user_id|owner_user_id)$/i.test(String(key || ''));
}

/* source 32894-32897 */
function diracCentralRequestSessionHashV146(req) {
  const cookies = typeof parseCookies === 'function' ? parseCookies(req) : {};
  return diracCentralHashV146([cookies[ACCESS_COOKIE], cookies[DOMAIN_SIGNED_SESSION_COOKIE], cookies.sb_access_token].filter(Boolean).join('|'));
}

/* source 32927-32929 */
function diracCentralOwnedTableV146(table) {
  return /^(orders|order_items|domain_orders|domain_order_items|payment_transactions|security_customer_sessions|security_customer_settings|security_customer_recovery_codes|security_customer_auth_links|security_customer_password_hashes|security_lost_passkey_recovery_requests|security_lost_passkey_recovery_sessions|customer_security_events|domain_passkeys|security_customer_login_logs|security_customer_account_requests|customers)$/i.test(String(table || ''));
}

/* source 32931-32938 */
function diracCentralExtractRestTableV146(path) {
  try {
    const raw = String(path || '');
    if (!raw.startsWith('/rest/v1/')) return '';
    const table = decodeURIComponent(raw.slice('/rest/v1/'.length).split('?')[0].split('/')[0] || '');
    return /^[a-zA-Z0-9_]+$/.test(table) ? table : '';
  } catch (_) { return ''; }
}

/* source 32940-32944 */
function diracCentralPathHasOwnerScopeV146(path, body) {
  const raw = String(path || '').toLowerCase();
  if (/(?:customer_id|auth_user_id|user_id)=/.test(raw)) return true;
  return diracCentralFlattenObjectV146(body || {}, 0, '', 200).some((item) => /^(customer_id|auth_user_id|user_id)$/i.test(item.key.split('.').pop()));
}

/* source 32946-32950 */
function diracCentralPathHasObjectScopeV146(path, body) {
  const raw = String(path || '').toLowerCase();
  if (/(?:id|order_id|domain_order_id|payment_id|transaction_id|gateway_reference)=/.test(raw)) return true;
  return diracCentralFlattenObjectV146(body || {}, 0, '', 200).some((item) => /^(id|order_id|domain_order_id|payment_id|transaction_id|gateway_reference)$/i.test(item.key.split('.').pop()));
}

/* source 32952-32965 */
function diracCentralIsUnsafeHostV146(host) {
  const clean = String(host || '').toLowerCase();
  return clean === 'localhost'
    || clean === '0.0.0.0'
    || clean === '127.0.0.1'
    || clean === '::1'
    || clean === '[::1]'
    || clean === '169.254.169.254'
    || clean === 'metadata.google.internal'
    || /^10\./.test(clean)
    || /^192\.168\./.test(clean)
    || /^172\.(?:1[6-9]|2\d|3[0-1])\./.test(clean)
    || /^169\.254\./.test(clean);
}

/* source 32967-32970 */
function diracCentralLooksLikeUuidV146(value) {
  try { if (typeof customerSecurityLooksLikeUuid === 'function') return customerSecurityLooksLikeUuid(value); } catch (_) {}
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

/* source 33000-33002 */
function diracCentralIsProductionV146() {
  return String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
}

/* source 33004-33006 */
function diracCentralMinimumSecretBytesV146() {
  return diracCentralIsProductionV146() ? 3000 : 32;
}

/* source 33008-33014 */
function diracCentralRootSecretV146() {
  const secret = String(process.env.DIRAC_SECURITY_ROOT_SECRET || '').trim();
  if (Buffer.byteLength(secret, 'utf8') >= diracCentralMinimumSecretBytesV146()) return secret;
  const err = new Error('DIRAC_SECURITY_ROOT_SECRET wajib minimal ' + diracCentralMinimumSecretBytesV146() + ' byte raw entropy.');
  err.statusCode = 500;
  throw err;
}

/* source 33016-33026 */
function diracCentralDeriveSecretV146(scope, inputSecret) {
  const root = String(inputSecret || diracCentralRootSecretV146());
  const cleanScope = String(scope || 'default').slice(0, 120);
  const cacheKey = cleanScope + ':' + crypto.createHash('sha256').update(root).digest('hex');
  const cached = DIRAC_CENTRAL_SECRET_CACHE_V146.get(cacheKey);
  if (cached) return cached;
  const derived = crypto.createHmac('sha512', root).update('dirac-derived-secret-v146:' + cleanScope).digest();
  DIRAC_CENTRAL_SECRET_CACHE_V146.set(cacheKey, derived);
  if (DIRAC_CENTRAL_SECRET_CACHE_V146.size > 100) DIRAC_CENTRAL_SECRET_CACHE_V146.clear();
  return derived;
}

/* source 33086-33088 */
function diracCentralSecretV146() {
  return diracCentralDeriveSecretV146('central-v146');
}

/* source 33090-33093 */
function diracCentralHashV146(value) {
  const secret = diracCentralSecretV146();
  if (!Buffer.isBuffer(secret) || secret.length < 64) {
    const error = new Error('DIRAC_CENTRAL_HASH_SECRET_INVALID');
    error.code = 'DIRAC_CENTRAL_HASH_SECRET_INVALID';
    throw error;
  }
  return crypto.createHmac('sha256', secret)
    .update(String(value || ''), 'utf8')
    .digest('hex');
}

/* source 33095-33106 */
function diracCentralFakeResponseV146() {
  const headers = {};
  return {
    statusCode: 200,
    headers,
    setHeader(name, value) { headers[String(name).toLowerCase()] = value; return this; },
    getHeader(name) { return headers[String(name).toLowerCase()]; },
    status(code) { this.statusCode = Number(code || 200); return this; },
    json(payload) { this.payload = payload; return this; },
    end() { return this; }
  };
}

/* source 33160-33168 */
try {
  const __diracCentralPreviousV137CsrfShouldForceV146 = typeof diracV137CsrfShouldForce === 'function' ? diracV137CsrfShouldForce : null;
  if (__diracCentralPreviousV137CsrfShouldForceV146 && !__diracCentralPreviousV137CsrfShouldForceV146.__diracCentralPassthroughV146) {
    diracV137CsrfShouldForce = function diracV137CsrfShouldForceCentralPassthroughV146(action, method) {
      return __diracCentralPreviousV137CsrfShouldForceV146(action, method);
    };
    Object.defineProperty(diracV137CsrfShouldForce, '__diracCentralPassthroughV146', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 33170-33178 */
try {
  const __diracCentralPreviousV138CsrfShouldForceV146 = typeof diracV138CsrfShouldForce === 'function' ? diracV138CsrfShouldForce : null;
  if (__diracCentralPreviousV138CsrfShouldForceV146 && !__diracCentralPreviousV138CsrfShouldForceV146.__diracCentralPassthroughV146) {
    diracV138CsrfShouldForce = function diracV138CsrfShouldForceCentralPassthroughV146(action, method) {
      return __diracCentralPreviousV138CsrfShouldForceV146(action, method);
    };
    Object.defineProperty(diracV138CsrfShouldForce, '__diracCentralPassthroughV146', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 33180-33188 */
try {
  const __diracCentralPreviousV128InspectHttpV146 = typeof diracBolaIdorV128InspectHttpRequest === 'function' ? diracBolaIdorV128InspectHttpRequest : null;
  if (__diracCentralPreviousV128InspectHttpV146 && !__diracCentralPreviousV128InspectHttpV146.__diracCentralPassthroughV146) {
    diracBolaIdorV128InspectHttpRequest = async function diracBolaIdorV128InspectHttpRequestCentralPassthroughV146(req) {
      return __diracCentralPreviousV128InspectHttpV146(req);
    };
    Object.defineProperty(diracBolaIdorV128InspectHttpRequest, '__diracCentralPassthroughV146', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 33200-33208 */
try {
  const __diracCentralPreviousV133InspectHttpV146 = typeof diracBolaIdorV133InspectHttpRequest === 'function' ? diracBolaIdorV133InspectHttpRequest : null;
  if (__diracCentralPreviousV133InspectHttpV146 && !__diracCentralPreviousV133InspectHttpV146.__diracCentralPassthroughV146) {
    diracBolaIdorV133InspectHttpRequest = async function diracBolaIdorV133InspectHttpRequestCentralPassthroughV146(req) {
      return __diracCentralPreviousV133InspectHttpV146(req);
    };
    Object.defineProperty(diracBolaIdorV133InspectHttpRequest, '__diracCentralPassthroughV146', { value: true, enumerable: false });
  }
} catch (_) {}

/* source 33210-33219 */
function diracCentralCurrentContextPassedV146() {
  const ctx = diracCentralCurrentContextV149();
  return Boolean(
    ctx
    && ctx.req
    && ctx.req.__diracCentralSecurityGuardPassedV146 === true
    && ctx.guardPassport
    && ctx.guardPassport.integrity_checked === true
  );
}

/* source 33231-33231 */
const DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159 = 'customer_security_recovery_hpke_verify';

/* source 33232-33232 */
const DIRAC_RECOVERY_HPKE_PROOF_ACTION_V159 = 'customer_security_recovery_hpke_submit';

/* source 33235-33235 */
const DIRAC_RECOVERY_HPKE_PROOF_VERSION_V159 = 'dirac-recovery-hpke-proof-v2';

/* source 33236-33236 */
const DIRAC_RECOVERY_HPKE_SUITE_V159 = 'DHKEM-X25519-HKDF-SHA256+HKDF-SHA384+AES-256-GCM';

/* source 33237-33237 */
const DIRAC_RECOVERY_HPKE_ARGON2_PROFILE_V159 = 'argon2id-salt-pepper-v1';

/* source 33241-33241 */
const DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187 = globalThis.__DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187__ || { running: 0 };

/* source 33243-33243 */
globalThis.__DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187__ = DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187;

/* source 33245-33245 */
CUSTOMER_SECURITY_GUARDED_ACTIONS.add(DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159);

/* source 33246-33246 */
DIRAC_CENTRAL_SERVER2_RECOVERY_ACTIONS_V157.add(DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159);

/* source 33247-33247 */
DIRAC_CENTRAL_ACTIVE_ACTIONS_V146.add(DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159);

/* source 33248-33248 */
DIRAC_CENTRAL_KNOWN_ACTION_INPUTS_V146.add(DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159);

/* source 33313-33315 */
function diracRecoveryHpkeEnvTextV159(name) {
  return String(process.env[String(name || '')] || '').trim();
}

/* source 33317-33321 */
function diracRecoveryHpkeEnvIntegerV159(name, minimum, maximum) {
  const value = Number(diracRecoveryHpkeEnvTextV159(name));
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) return 0;
  return value;
}

/* source 33323-33327 */
function diracRecoveryHpkeArgon2ClaimV187() {
  if (DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187.running !== 0) return false;
  DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187.running = 1;
  return true;
}

/* source 33329-33331 */
function diracRecoveryHpkeArgon2ReleaseV187() {
  DIRAC_RECOVERY_HPKE_ARGON2_GATE_V187.running = 0;
}

/* source 33333-33337 */
function diracRecoveryHpkeAsciiV159(value, minLength, maxLength) {
  const clean = String(value || '').trim();
  if (clean.length < minLength || clean.length > maxLength) return '';
  return /^[A-Za-z0-9_.-]+$/.test(clean) ? clean : '';
}

/* source 33415-33422 */
function diracRecoveryHpkePrivateKeyV159() {
  const raw = diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_HPKE_PRIVATE_KEY');
  if (!raw) throw new Error('RECOVERY_HPKE_PRIVATE_KEY_MISSING');
  const normalized = raw.includes('-----BEGIN') ? raw.replace(/\\n/g, '\n') : Buffer.from(raw, 'base64').toString('utf8');
  const key = crypto.createPrivateKey(normalized);
  if (key.asymmetricKeyType !== 'x25519') throw new Error('RECOVERY_HPKE_PRIVATE_KEY_TYPE_INVALID');
  return key;
}

/* source 33559-33585 */
function diracRecoveryHpkeEnvGuardV159() {
  const allowlist = DIRAC_CENTRAL_ENV_VERCEL2_ONLY_ACTIONS_V174;
  const role = diracCentralEnvValueV150('DIRAC_CENTRAL_DEPLOYMENT_ROLE') || diracCentralEnvValueV150('DIRAC_DEPLOYMENT_ROLE');
  const workerSecret = customerSecurityRecoveryWorkerSecret();
  const privateKey = diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_HPKE_PRIVATE_KEY');
  const keyId = diracRecoveryHpkeAsciiV159(diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_HPKE_KEY_ID'), 1, 80);
  const pepper = diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_HPKE_PEPPER');
  const server1Url = diracRecoveryHpkeServer1UrlV159();
  const minimumMemory = diracRecoveryHpkeEnvIntegerV159('DIRAC_RECOVERY_HPKE_ARGON2_MEMORY_KIB', 1048576, 5242880);
  const minimumTime = diracRecoveryHpkeEnvIntegerV159('DIRAC_RECOVERY_HPKE_ARGON2_TIME_COST', 4, 12);
  const server1OnlyEnv = [
    'DIRAC_RECOVERY_WORKER_URL',
    'DIRAC_RECOVERY_WORKER_CALLER',
    'DIRAC_RECOVERY_HPKE_ALLOWED_CALLER'
  ].filter((name) => diracRecoveryHpkeEnvTextV159(name));

  if (!allowlist.has(DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159)) return { ok: false, reason: 'vercel2_action_env_allowlist_missing' };
  if (role !== 'vercel2') return { ok: false, reason: 'vercel2_role_invalid' };
  if (server1OnlyEnv.length) return { ok: false, reason: 'server1_env_present_on_vercel2' };
  if (!workerSecret) return { ok: false, reason: 'worker_secret_invalid' };
  if (!privateKey || !keyId) return { ok: false, reason: 'hpke_key_env_invalid' };
  if (Buffer.byteLength(pepper, 'utf8') < 64) return { ok: false, reason: 'hpke_pepper_invalid' };
  if (!server1Url) return { ok: false, reason: 'server1_url_invalid' };
  if (!minimumMemory || !minimumTime) return { ok: false, reason: 'argon2_policy_invalid' };
  try { diracRecoveryHpkePrivateKeyV159(); } catch (_) { return { ok: false, reason: 'hpke_private_key_invalid' }; }
  return { ok: true, workerSecret, pepper, keyId, server1Url, minimumMemory, minimumTime };
}

/* source 33587-33601 */
function diracRecoveryHpkeServer1UrlV159() {
  const raw = diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_SERVER1_URL');
  if (!raw) return '';
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) return '';
    if (url.origin !== 'https://diracgroup.store') return '';
    if (typeof diracCentralIsUnsafeHostV146 === 'function' && diracCentralIsUnsafeHostV146(url.hostname)) return '';
    if (url.pathname.replace(/\/+$/, '') !== '/api/health') return '';
    url.pathname = '/api/health';
    url.search = '';
    return url.toString();
  } catch (_) {
    return '';
  }
}

/* source 33603-33619 */
function diracRecoveryHpkeArgon2PolicyV159(encodedHash, minimumMemory, minimumTime) {
  const value = String(encodedHash || '');
  const matched = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(value);
  if (!matched) return { ok: false };
  const memory = Number(matched[1]);
  const time = Number(matched[2]);
  const parallelism = Number(matched[3]);
  return {
    ok: Number.isSafeInteger(memory) && Number.isSafeInteger(time) && Number.isSafeInteger(parallelism)
      && memory >= 1048576 && memory >= minimumMemory && memory <= 5242880
      && time >= 4 && time >= minimumTime && time <= 12
      && parallelism === 4,
    memory,
    time,
    parallelism
  };
}

/* source 33621-33633 */
async function diracRecoveryHpkeReadRequestV159(requestId) {
  const fields = 'id,request_id,customer_id,auth_user_id,recovery_code_hash,salt,status,attempt_count,expires_at,used_at,revoked_at,locked_at,old_passkey_ids,metadata';
  const path = '/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE
    + '?select=' + encodeURIComponent(fields)
    + '&request_id=eq.' + encodeURIComponent(requestId)
    + '&limit=1';
  const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
  return {
    ok: Boolean(result && result.ok),
    status: Number(result && result.status || 0),
    row: result && result.ok && Array.isArray(result.data) ? result.data[0] || null : null
  };
}

/* source 33635-33648 */
function diracRecoveryHpkeRequestActiveV159(row) {
  const expiresAtMs = Date.parse(row && row.expires_at || '');
  return Boolean(row && row.id
    && row.status === 'pending'
    && !row.used_at
    && !row.revoked_at
    && !row.locked_at
    && Number.isFinite(expiresAtMs)
    && expiresAtMs > Date.now()
    && customerSecurityLooksLikeUuid(row.customer_id)
    && customerSecurityLooksLikeUuid(row.auth_user_id)
    && Array.isArray(row.old_passkey_ids)
    && row.old_passkey_ids.length > 0);
}

/* source 33682-33703 */
async function diracRecoveryHpkeRegisterCodeFailureV159(req, row, requestId) {
  const nextAttempts = Number(row && row.attempt_count || 0) + 1;
  const lock = nextAttempts >= LOST_PASSKEY_RECOVERY_ATTEMPT_LIMIT;
  await supabaseFetch('/rest/v1/' + LOST_PASSKEY_RECOVERY_REQUEST_TABLE
    + '?request_id=eq.' + encodeURIComponent(requestId)
    + '&status=eq.pending', {
    method: 'PATCH',
    auth: 'service',
    body: {
      attempt_count: nextAttempts,
      status: lock ? 'locked' : 'pending',
      locked_at: lock ? diracNowIso() : row && row.locked_at || null,
      metadata: {
        ...(row && row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata : {}),
        last_failed_verify_at: diracNowIso(),
        failed_verify_source: DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159
      }
    }
  }).catch(() => null);
  await customerSecurityRegisterFailedVerification(req, DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159, lock ? 'recovery_code_locked' : 'recovery_code_not_matched', row && row.customer_id).catch(() => null);
  return { locked: lock };
}

/* source 33705-33722 */
function diracRecoveryHpkeContextHashV159(row, keyId, verifiedAtMs, proofExpiresAtMs) {
  const context = {
    action: DIRAC_RECOVERY_HPKE_PROOF_ACTION_V159,
    version: DIRAC_RECOVERY_HPKE_PROOF_VERSION_V159,
    request_id: String(row && row.request_id || ''),
    customer_id: String(row && row.customer_id || ''),
    auth_user_id: String(row && row.auth_user_id || ''),
    request_salt_hash: crypto.createHash('sha384').update(String(row && row.salt || '')).digest('base64url'),
    hpke_suite: DIRAC_RECOVERY_HPKE_SUITE_V159,
    hpke_key_id: keyId,
    argon2_profile: DIRAC_RECOVERY_HPKE_ARGON2_PROFILE_V159,
    verified_at_ms: verifiedAtMs,
    proof_expires_at_ms: proofExpiresAtMs
  };
  return crypto.createHash('sha384')
    .update(customerSecurityLostPasskeyCanonical(context))
    .digest('base64url');
}

/* source 33724-33743 */
function diracRecoveryHpkeArgon2ProofV159(env, row, proofNonce, contextHash) {
  const material = customerSecurityLostPasskeyCanonical({
    version: DIRAC_RECOVERY_HPKE_ARGON2_PROFILE_V159,
    request_id: String(row && row.request_id || ''),
    recovery_code_hash_sha384: crypto.createHash('sha384').update(String(row && row.recovery_code_hash || '')).digest('base64url'),
    proof_nonce: proofNonce,
    verification_context_hash: contextHash,
    hpke_key_id: env.keyId,
    pepper_key_id: diracRecoveryHpkeAsciiV159(diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_HPKE_PEPPER_KEY_ID'), 1, 80) || 'recovery-pepper-v1'
  });
  const pepper = Buffer.from(env.pepper, 'utf8');
  try {
    return crypto.createHmac('sha384', pepper)
      .update('dirac-recovery-hpke-argon2-proof-v159\n')
      .update(material)
      .digest('base64url');
  } finally {
    pepper.fill(0);
  }
}

/* source 33745-33764 */
function diracRecoveryHpkeProofBodyV159(env, row) {
  const verifiedAtMs = Date.now();
  const proofExpiresAtMs = verifiedAtMs + 90 * 1000;
  const proofNonce = crypto.randomBytes(48).toString('base64url');
  const contextHash = diracRecoveryHpkeContextHashV159(row, env.keyId, verifiedAtMs, proofExpiresAtMs);
  const argon2Proof = diracRecoveryHpkeArgon2ProofV159(env, row, proofNonce, contextHash);
  return {
    action: DIRAC_RECOVERY_HPKE_PROOF_ACTION_V159,
    version: DIRAC_RECOVERY_HPKE_PROOF_VERSION_V159,
    request_id: String(row.request_id || ''),
    proof_nonce: proofNonce,
    verified_at_ms: verifiedAtMs,
    proof_expires_at_ms: proofExpiresAtMs,
    hpke_suite: DIRAC_RECOVERY_HPKE_SUITE_V159,
    hpke_key_id: env.keyId,
    argon2_profile: DIRAC_RECOVERY_HPKE_ARGON2_PROFILE_V159,
    argon2_proof: argon2Proof,
    verification_context_hash: contextHash
  };
}

/* source 33766-33783 */
function diracRecoveryHpkeProofSignatureV159(caller, timestamp, body) {
  const secretText = customerSecurityRecoveryWorkerSecret();
  if (!secretText) return '';
  const secret = Buffer.from(secretText, 'utf8');
  try {
    return crypto.createHmac('sha384', secret)
      .update('dirac-recovery-hpke-proof-v159')
      .update('\n')
      .update(caller)
      .update('\n')
      .update(timestamp)
      .update('\n')
      .update(customerSecurityLostPasskeyCanonical(body))
      .digest('base64url');
  } finally {
    secret.fill(0);
  }
}

/* source 33785-33785 */
const DIRAC_RECOVERY_HPKE_PROOF_RESPONSE_VERSION_V190 = 'dirac-recovery-hpke-proof-response-v191';

/* source 33787-33804 */
function diracRecoveryHpkeProofResponseKeyV190(body) {
  const secretText = customerSecurityRecoveryWorkerSecret();
  if (!secretText) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_PROOF_RESPONSE_SECRET_MISSING');
  const secret = Buffer.from(secretText, 'utf8');
  const salt = crypto.createHash('sha512').update(customerSecurityLostPasskeyCanonical(body || {})).digest();
  const info = Buffer.from([
    'dirac/recovery-hpke/v190/proof-response',
    String(body && body.request_id || ''),
    String(body && body.proof_nonce || '')
  ].join('\n'), 'utf8');
  try {
    return Buffer.from(crypto.hkdfSync('sha512', secret, salt, info, 32));
  } finally {
    secret.fill(0);
    salt.fill(0);
    info.fill(0);
  }
}

/* source 33806-33813 */
function diracRecoveryHpkeProofResponseAadV190(body, status) {
  return {
    version: DIRAC_RECOVERY_HPKE_PROOF_RESPONSE_VERSION_V190,
    status: Number(status),
    request_id: String(body && body.request_id || ''),
    proof_nonce: String(body && body.proof_nonce || '')
  };
}

/* source 33815-33866 */
function diracRecoveryHpkeOpenProofResponseV190(data, body, status) {
  const outer = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
  const expectedOuterKeys = ['ok', 'proof_response', 'proof_response_encrypted'];
  const actualOuterKeys = Object.keys(outer).sort();
  if (actualOuterKeys.length !== expectedOuterKeys.length || actualOuterKeys.some((key, index) => key !== expectedOuterKeys[index])) {
    throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_PROOF_RESPONSE_OUTER_FIELDS_INVALID');
  }
  const response = outer.proof_response && typeof outer.proof_response === 'object' && !Array.isArray(outer.proof_response)
    ? outer.proof_response
    : null;
  if (outer.ok !== true || outer.proof_response_encrypted !== true || !response || response.version !== DIRAC_RECOVERY_HPKE_PROOF_RESPONSE_VERSION_V190) {
    throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_ENCRYPTED_PROOF_RESPONSE_REQUIRED');
  }
  const expectedKeys = ['auth_tag_b64url', 'ciphertext_b64url', 'nonce_b64url', 'proof_nonce', 'request_id', 'status', 'version'];
  const actualKeys = Object.keys(response).sort();
  if (actualKeys.length !== expectedKeys.length || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_PROOF_RESPONSE_FIELDS_INVALID');
  }
  if (Number(response.status) !== Number(status)
    || response.request_id !== String(body && body.request_id || '')
    || response.proof_nonce !== String(body && body.proof_nonce || '')) {
    throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_PROOF_RESPONSE_BINDING_INVALID');
  }
  const key = diracRecoveryHpkeProofResponseKeyV190(body);
  const nonce = customerSecurityRecoveryWorkerDecodeB64uV190(response.nonce_b64url, 12, 128);
  const ciphertext = customerSecurityRecoveryWorkerDecodeB64uV190(response.ciphertext_b64url, null, 128 * 1024);
  const tag = customerSecurityRecoveryWorkerDecodeB64uV190(response.auth_tag_b64url, 16, 128);
  const aad = Buffer.from(customerSecurityLostPasskeyCanonical(diracRecoveryHpkeProofResponseAadV190(body, status)), 'utf8');
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || customerSecurityLostPasskeyCanonical(parsed) !== text) {
      throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_PROOF_RESPONSE_PLAINTEXT_INVALID');
    }
    return parsed;
  } catch (error) {
    if (error && error.code) throw error;
    throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_PROOF_RESPONSE_AUTHENTICATION_FAILED');
  } finally {
    key.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    tag.fill(0);
    aad.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}

/* source 33868-34084 */
async function diracRecoveryHpkeSendProofV159(env, proofBody) {
  const target = new URL(env.server1Url);
  target.searchParams.set('action', DIRAC_RECOVERY_HPKE_PROOF_ACTION_V159);
  const caller = diracS2SIdV206(diracS2STextV206('DIRAC_S2S_SERVER_ID'));
  const timestamp = String(Date.now());
  const signature = diracRecoveryHpkeProofSignatureV159(caller, timestamp, proofBody);
  const diagnosticStartedAt = Date.now();
  const requestIdHash = crypto.createHash('sha256')
    .update(String(proofBody && proofBody.request_id || ''))
    .digest('hex')
    .slice(0, 24);
  const diagnosticBase = {
    diagnostic_version: 'recovery-hpke-server1-diagnostic-v177',
    action: DIRAC_RECOVERY_HPKE_PROOF_ACTION_V159,
    target_origin: target.origin,
    target_path: target.pathname,
    request_id_hash: requestIdHash,
    timeout_ms: 12000,
    redirect_mode: 'error'
  };
  const diagnosticLog = (event, extra = {}, level = 'log') => {
    try {
      const payload = {
        ...diagnosticBase,
        event,
        elapsed_ms: Date.now() - diagnosticStartedAt,
        ...extra,
        time: new Date().toISOString()
      };
      const writer = level === 'error' ? console.error : console.log;
      writer('[dirac-recovery-hpke-server1-v177]', JSON.stringify(payload));
    } catch (_) {}
  };

  if (!signature) {
    diagnosticLog('proof_signature_unavailable', {}, 'error');
    return { ok: false, status: 503, code: 'proof_signature_unavailable' };
  }

  const controller = new AbortController();
  let timeoutTriggered = false;
  const timeout = setTimeout(() => {
    timeoutTriggered = true;
    controller.abort();
  }, 12000);

  diagnosticLog('server1_fetch_start', {
    proof_version: String(proofBody && proofBody.version || ''),
    signature_present: true
  });

  try {
    const response = await fetch(target.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Origin': target.origin,
        'Referer': target.origin + '/',
        'X-Dirac-HPKE-Caller': caller,
        'X-Dirac-HPKE-Timestamp': timestamp,
        'X-Dirac-HPKE-Signature': signature,
        ...diracS2SSignHeadersV206({
          target,
          action: DIRAC_RECOVERY_HPKE_PROOF_ACTION_V159,
          body: proofBody,
          targetServerId: diracS2SIdV206(process.env.DIRAC_RECOVERY_SERVER1_SERVER_ID || 'vercel1-main')
        })
      },
      body: JSON.stringify(proofBody),
      redirect: 'error',
      signal: controller.signal
    });

    const contentType = String(response.headers && response.headers.get && response.headers.get('content-type') || '');
    const length = Number(response.headers && response.headers.get && response.headers.get('content-length') || 0);
    const vercelMitigated = String(response.headers && response.headers.get && response.headers.get('x-vercel-mitigated') || '');
    const retryAfter = String(response.headers && response.headers.get && response.headers.get('retry-after') || '');
    const vercelId = String(response.headers && response.headers.get && response.headers.get('x-vercel-id') || '');
    diagnosticLog('server1_response_headers', {
      http_status: Number(response.status || 0),
      response_ok: Boolean(response.ok),
      redirected: Boolean(response.redirected),
      response_url_origin: (() => {
        try { return new URL(response.url).origin; } catch (_) { return ''; }
      })(),
      response_url_path: (() => {
        try { return new URL(response.url).pathname; } catch (_) { return ''; }
      })(),
      content_type: contentType.slice(0, 120),
      content_length: Number.isFinite(length) ? length : 0,
      vercel_mitigated: vercelMitigated.slice(0, 80),
      retry_after: retryAfter.slice(0, 40),
      vercel_id_present: Boolean(vercelId)
    });

    if (Number.isFinite(length) && length > 64 * 1024) {
      diagnosticLog('server1_response_rejected_too_large_header', {
        content_length: length
      }, 'error');
      return { ok: false, status: 502, code: 'server1_response_too_large' };
    }

    const responseText = await diracRecoveryReadResponseLimitedV201(response, 64 * 1024);
    if (Buffer.byteLength(responseText, 'utf8') > 64 * 1024) {
      diagnosticLog('server1_response_rejected_too_large_body', {
        body_length: responseText.length
      }, 'error');
      return { ok: false, status: 502, code: 'server1_response_too_large' };
    }

    let data = null;
    let jsonParsed = false;
    try {
      data = responseText ? JSON.parse(responseText) : null;
      jsonParsed = responseText ? true : false;
    } catch (_) {
      data = null;
    }

    let encryptedProofResponseValid = false;
    let encryptedProofResponseErrorCode = '';
    if (data && data.proof_response_encrypted === true) {
      try {
        data = diracRecoveryHpkeOpenProofResponseV190(data, proofBody, response.status);
        encryptedProofResponseValid = true;
      } catch (error) {
        const safeErrorCode = error && /^[A-Z0-9_]{1,120}$/.test(String(error.code || ''))
          ? String(error.code)
          : 'RECOVERY_HPKE_PROOF_RESPONSE_OPEN_FAILED';
        encryptedProofResponseErrorCode = safeErrorCode;
        const outerEnvelope = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
        const encryptedEnvelope = outerEnvelope.proof_response && typeof outerEnvelope.proof_response === 'object' && !Array.isArray(outerEnvelope.proof_response)
          ? outerEnvelope.proof_response
          : {};
        const failureStage = safeErrorCode.includes('OUTER_FIELDS') ? 'outer_envelope_shape'
          : safeErrorCode.includes('ENCRYPTED_PROOF_RESPONSE_REQUIRED') ? 'encrypted_envelope_policy'
          : safeErrorCode.includes('RESPONSE_FIELDS') ? 'encrypted_response_shape'
          : safeErrorCode.includes('BINDING') ? 'response_binding'
          : safeErrorCode.includes('BASE64URL') ? 'response_encoding'
          : safeErrorCode.includes('AUTHENTICATION') ? 'aes_256_gcm_authentication'
          : safeErrorCode.includes('PLAINTEXT') ? 'plaintext_canonical_json'
          : safeErrorCode.includes('SECRET_MISSING') ? 'local_worker_secret'
          : 'encrypted_response_open';
        diagnosticLog('server1_encrypted_response_open_failed', {
          error_code: safeErrorCode,
          failure_stage: failureStage,
          outer_keys: Object.keys(outerEnvelope).sort().slice(0, 16),
          proof_response_keys: Object.keys(encryptedEnvelope).sort().slice(0, 16),
          envelope_policy_ok: outerEnvelope.ok === true && outerEnvelope.proof_response_encrypted === true,
          response_version_matches: encryptedEnvelope.version === DIRAC_RECOVERY_HPKE_PROOF_RESPONSE_VERSION_V190,
          expected_response_version: DIRAC_RECOVERY_HPKE_PROOF_RESPONSE_VERSION_V190,
          received_response_version: String(encryptedEnvelope.version || '').slice(0, 120),
          expected_response_version_length: DIRAC_RECOVERY_HPKE_PROOF_RESPONSE_VERSION_V190.length,
          received_response_version_length: String(encryptedEnvelope.version || '').length,
          response_status_matches: Number(encryptedEnvelope.status) === Number(response.status),
          request_id_matches: encryptedEnvelope.request_id === String(proofBody && proofBody.request_id || ''),
          proof_nonce_matches: encryptedEnvelope.proof_nonce === String(proofBody && proofBody.proof_nonce || ''),
          nonce_b64url_length: String(encryptedEnvelope.nonce_b64url || '').length,
          ciphertext_b64url_length: String(encryptedEnvelope.ciphertext_b64url || '').length,
          auth_tag_b64url_length: String(encryptedEnvelope.auth_tag_b64url || '').length,
          local_worker_secret_present: Boolean(customerSecurityRecoveryWorkerSecret()),
          secret_value_logged: false,
          encrypted_payload_logged: false
        }, 'error');
        data = null;
      }
    } else {
      encryptedProofResponseErrorCode = vercelMitigated
        ? 'RECOVERY_SERVER1_VERCEL_MITIGATED'
        : Number(response.status) === 429
          ? 'RECOVERY_SERVER1_RATE_LIMITED'
          : jsonParsed
            ? 'RECOVERY_HPKE_ENCRYPTED_PROOF_RESPONSE_REQUIRED'
            : 'RECOVERY_HPKE_PROOF_RESPONSE_JSON_INVALID';
      diagnosticLog('server1_encrypted_response_missing', {
        error_code: encryptedProofResponseErrorCode,
        json_parsed: jsonParsed,
        response_object_present: Boolean(data && typeof data === 'object' && !Array.isArray(data)),
        proof_response_encrypted_flag: Boolean(data && data.proof_response_encrypted === true),
        secret_value_logged: false,
        response_body_logged: false
      }, 'error');
    }
    if (response.ok && !encryptedProofResponseValid) {
      diagnosticLog('server1_encrypted_response_required', {
        error_code: encryptedProofResponseErrorCode || 'RECOVERY_HPKE_ENCRYPTED_PROOF_RESPONSE_REQUIRED'
      }, 'error');
    }

    diagnosticLog('server1_response_body', {
      http_status: Number(response.status || 0),
      response_ok: Boolean(response.ok),
      body_length: responseText.length,
      body_sha256_24: crypto.createHash('sha256').update(responseText).digest('hex').slice(0, 24),
      json_parsed: jsonParsed,
      server_ok: Boolean(data && data.ok === true),
      server_code: data && data.code ? String(data.code).slice(0, 100) : '',
      server_message: data && data.message ? String(data.message).slice(0, 160) : '',
      recovery_session_present: Boolean(data && data.dirac_lost_passkey_recovery_session),
      recovery_expiry_present: Boolean(data && data.recovery_session_expires_at)
    }, response.ok ? 'log' : 'error');

    return {
      ok: Boolean(response.ok && encryptedProofResponseValid),
      status: response.status,
      data,
      code: encryptedProofResponseValid ? '' : (encryptedProofResponseErrorCode || 'RECOVERY_HPKE_ENCRYPTED_PROOF_RESPONSE_REQUIRED')
    };
  } catch (error) {
    const cause = error && error.cause && typeof error.cause === 'object' ? error.cause : null;
    diagnosticLog('server1_fetch_error', {
      timeout_triggered: timeoutTriggered,
      aborted: Boolean(controller.signal && controller.signal.aborted),
      error_name: error && error.name ? String(error.name).slice(0, 100) : '',
      error_message: error && error.message ? String(error.message).slice(0, 200) : '',
      cause_name: cause && cause.name ? String(cause.name).slice(0, 100) : '',
      cause_code: cause && cause.code ? String(cause.code).slice(0, 100) : '',
      cause_message: cause && cause.message ? String(cause.message).slice(0, 200) : ''
    }, 'error');
    return {
      ok: false,
      status: 502,
      code: timeoutTriggered ? 'server1_timeout' : 'server1_unreachable'
    };
  } finally {
    clearTimeout(timeout);
    diagnosticLog('server1_fetch_finished', {
      timeout_triggered: timeoutTriggered,
      aborted: Boolean(controller.signal && controller.signal.aborted)
    });
  }
}

/* source 34371-34371 */
const DIRAC_RECOVERY_CRYPTO_V2_PATCH = 'dirac-recovery-crypto-v2-max-2026';

/* source 34373-34379 */
function diracRecoveryCryptoV2BundleFromMetadata(metadata) {
  const source = metadata && typeof metadata === 'object' && !Array.isArray(metadata) ? metadata : {};
  const bundle = source.vault_bundle && typeof source.vault_bundle === 'object' && !Array.isArray(source.vault_bundle)
    ? source.vault_bundle
    : null;
  return bundle && bundle.version === DIRAC_RECOVERY_CRYPTO_V2.VERSION ? bundle : null;
}

/* source 34506-34694 */
async function diracRecoveryCryptoV2VerifyEnvelope(req, res, ctx, body) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, message: 'Gunakan POST.' });
  if (req.__diracCentralSecurityGuardPassedV146 !== true || !diracCentralCurrentContextPassedV146()) {
    return res.status(403).json({ ok: false, code: 'CENTRAL_GUARD_REQUIRED', message: 'Permintaan ditolak oleh sistem keamanan.' });
  }
  if (!ctx || ctx.req !== req || ctx.action !== DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159 || ctx.classification !== 'browser' || !ctx.guardPassport || ctx.guardPassport.integrity_checked !== true) {
    return res.status(403).json({ ok: false, code: 'RECOVERY_V2_GUARD_CONTEXT_INVALID', message: 'Permintaan ditolak oleh sistem keamanan.' });
  }
  if (!DIRAC_CENTRAL_ENV_VERCEL2_ONLY_ACTIONS_V174.has(DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159)) {
    return res.status(403).json({ ok: false, code: 'RECOVERY_V2_ACTION_NOT_ALLOWED', message: 'Action tidak diizinkan pada server ini.' });
  }

  let hybrid = null;
  let parsedHybrid = null;
  let recovered = null;
  let recoveryCode = '';
  let argon2GateClaimed = false;
  let argonQueueTicket = null;
  try {
    const env = diracRecoveryHpkeEnvGuardV159();
    if (!env.ok) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_V2_ENVIRONMENT_INVALID');
    DIRAC_RECOVERY_CRYPTO_V2.assertRuntimePolicy();
    if (String(body.action || '') !== DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_V2_ACTION_INVALID');

    const request = await diracRecoveryHpkeReadRequestV159(String(body.request_id || ''));
    if (!request.ok) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_REQUEST_STORAGE_UNAVAILABLE');
    const row = request.row;
    if (!diracRecoveryHpkeRequestActiveV159(row)) {
      return res.status(403).json({ ok: false, code: 'RECOVERY_REQUEST_INACTIVE', message: 'Recovery request tidak aktif.' });
    }
    const metadata = row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata : {};
    const bundle = diracRecoveryCryptoV2BundleFromMetadata(metadata);
    if (!bundle) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_V2_VAULT_REQUIRED');
    if (bundle.request_id !== row.request_id || bundle.request_id !== body.request_id) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_V2_REQUEST_BINDING_INVALID');

    DIRAC_RECOVERY_CRYPTO_V2.validateEnvelope(body, env.keyId, bundle.transport.mlkem_key_id);

    hybrid = DIRAC_RECOVERY_CRYPTO_V2.openHybridEnvelope({
      body,
      bundle,
      expectedHpkeKeyId: env.keyId,
      x25519PrivateKey: diracRecoveryHpkePrivateKeyV159()
    });
    parsedHybrid = DIRAC_RECOVERY_CRYPTO_V2.parseHybridPlaintext(hybrid.plaintext, row.request_id);

    const submittedManifest = parsedHybrid.parsed.signed_manifest;
    const manifestPayload = DIRAC_RECOVERY_CRYPTO_V2.verifySignedManifestContainer(submittedManifest);
    const currentBundleHash = DIRAC_RECOVERY_CRYPTO_V2.sha512B64u(Buffer.from(DIRAC_RECOVERY_CRYPTO_V2.jcs(bundle), 'utf8'));
    if (parsedHybrid.parsed.vault_bundle_sha512 !== currentBundleHash || manifestPayload.vault_bundle_sha512 !== currentBundleHash) {
      throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_V2_BUNDLE_HASH_INVALID');
    }
    if (manifestPayload.request_id !== row.request_id || manifestPayload.vault_id !== bundle.vault_id || manifestPayload.legacy_fallback_allowed !== false) {
      throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_V2_MANIFEST_BINDING_INVALID');
    }

    recovered = await DIRAC_RECOVERY_CRYPTO_V2.openVaultPayload({
      bundle,
      dek: parsedHybrid.dek
    });
    recoveryCode = String(recovered.recovery_code || '');

    const vaultSecrets = customerSecurityLostPasskeyRequireVaultSecretsV157();
    if (!vaultSecrets.ok) throw DIRAC_RECOVERY_CRYPTO_V2.fail(String(vaultSecrets.code || 'RECOVERY_VAULT_SECRET_INVALID'));
    const argon2Policy = diracRecoveryHpkeArgon2PolicyV159(row.recovery_code_hash, env.minimumMemory, env.minimumTime);
    if (!argon2Policy.ok) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_ARGON2_POLICY_INVALID');

    argonQueueTicket = await customerSecurityLostPasskeyQueueAcquireV164(req, {
      nonce: row.request_id,
      caller_id: 'browser_hybrid_v2',
      queue_task: DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159
    });
    if (!argonQueueTicket || !argonQueueTicket.ok) {
      return res.status(429).json({ ok: false, code: 'RECOVERY_ARGON2_BUSY', message: 'Verifikasi recovery sedang diproses. Silakan coba kembali.' });
    }
    if (!diracRecoveryHpkeArgon2ClaimV187()) {
      try { await argonQueueTicket.release(); } catch (_) {}
      argonQueueTicket = null;
      return res.status(429).json({ ok: false, code: 'RECOVERY_ARGON2_BUSY', message: 'Verifikasi recovery sedang diproses. Silakan coba kembali.' });
    }
    argon2GateClaimed = true;

    let codeOk = false;
    try {
      // Claim only after every Central Guard and cryptographic envelope check,
      // and only after both Argon2id gates are available. A busy queue therefore
      // cannot consume the one-time replay claim.
      await DIRAC_RECOVERY_CRYPTO_V2.atomicClaim(supabaseFetch, body, bundle, row);

      const bindings = metadata.binding_hashes && typeof metadata.binding_hashes === 'object' && !Array.isArray(metadata.binding_hashes)
        ? metadata.binding_hashes
        : null;
      if (!bindings || !metadata.binding_hash_commitment) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_BINDING_INVALID');
      const bindingOk = await customerSecurityLostPasskeyArgon2VerifyHashV157(
        'binding',
        customerSecurityLostPasskeyCanonical(bindings),
        metadata.binding_hash_commitment,
        vaultSecrets.pepper,
        vaultSecrets.rootSecret
      ).catch(() => false);
      if (!bindingOk) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_BINDING_INVALID');

      codeOk = await customerSecurityLostPasskeyArgon2VerifyHashV157(
        'recovery_code',
        recoveryCode,
        row.recovery_code_hash,
        vaultSecrets.pepper,
        vaultSecrets.rootSecret
      ).catch(() => false);
      if (!customerSecurityLostPasskeyQueueLeaseHealthyV188(argonQueueTicket)) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_ARGON2_LEASE_LOST');
    } finally {
      if (argon2GateClaimed) {
        diracRecoveryHpkeArgon2ReleaseV187();
        argon2GateClaimed = false;
      }
      if (argonQueueTicket && typeof argonQueueTicket.release === 'function') {
        try { await argonQueueTicket.release(); } catch (_) {}
        argonQueueTicket = null;
      }
    }

    if (!codeOk) {
      const failed = await diracRecoveryHpkeRegisterCodeFailureV159(req, row, row.request_id);
      return res.status(failed.locked ? 423 : 403).json({
        ok: false,
        code: failed.locked ? 'RECOVERY_CODE_LOCKED' : 'RECOVERY_CODE_INVALID',
        message: failed.locked ? 'Recovery request dikunci.' : 'Kode pemulihan tidak valid.'
      });
    }

    const proofBody = diracRecoveryHpkeProofBodyV159(env, row);
    const server1 = await diracRecoveryHpkeSendProofV159(env, proofBody);
    if (!server1.ok) {
      const deliveryStatus = server1.status === 429
        || server1.code === 'RECOVERY_SERVER1_VERCEL_MITIGATED'
        || server1.code === 'RECOVERY_SERVER1_RATE_LIMITED'
        ? 503
        : (server1.status >= 400 && server1.status <= 599 ? server1.status : 502);
      return res.status(deliveryStatus).json({
        ok: false,
        code: 'RECOVERY_PROOF_DELIVERY_FAILED',
        message: 'Bukti recovery belum dapat diproses oleh server utama.'
      });
    }
    const server1Data = server1.data && typeof server1.data === 'object' ? server1.data : {};
    const session = String(server1Data.dirac_lost_passkey_recovery_session || '').trim();
    const sessionExpiresAt = String(server1Data.recovery_session_expires_at || '').trim();
    if (!server1Data.ok || !/^[A-Za-z0-9_-]{32,160}$/.test(session) || !Number.isFinite(Date.parse(sessionExpiresAt))) {
      throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_PROOF_RESPONSE_INVALID');
    }

    const sealedRecovery = DIRAC_RECOVERY_CRYPTO_V2.encryptResponse(
      hybrid.responseKey,
      hybrid.transcriptHash,
      row.request_id,
      recoveryCode
    );
    await customerSecurityWriteGuardEvent(row.customer_id, {
      event_type: 'lost_passkey_recovery_hybrid_v2_verified',
      status: 'success',
      risk_level: 'high',
      description: 'Central Guard memverifikasi hybrid X25519 + ML-KEM-1024, dual signature, wrapped DEK A256KW, dan Argon2id.',
      req,
      metadata: {
        action: DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159,
        request_id: row.request_id,
        crypto_profile: DIRAC_RECOVERY_CRYPTO_V2_PATCH,
        plaintext_recovery_code_logged: false,
        legacy_fallback_allowed: false
      }
    }).catch(() => null);

    return res.status(200).json({
      ok: true,
      active: true,
      method: 'x25519_mlkem1024_a256kw_dek_dual_signature',
      code: 'RECOVERY_HYBRID_V2_VERIFIED',
      central_guard: DIRAC_CENTRAL_SECURITY_GUARD_V146,
      request_id: row.request_id,
      recovery_session: session,
      recovery_session_expires_at: sessionExpiresAt,
      sealed_recovery: sealedRecovery
    });
  } catch (error) {
    const code = String(error && error.code || 'RECOVERY_HYBRID_V2_FAILED');
    const status = code === 'ATOMIC_REPLAY_REJECTED' ? 409
      : code === 'ATOMIC_REPLAY_STORAGE_UNAVAILABLE' ? 503
      : /INVALID|FAILED|REJECTED|EXPIRED|BINDING/.test(code) ? 403
      : 503;
    try {
      console.error('[dirac-recovery-crypto-v2-verify-failed]', JSON.stringify({
        code: code.slice(0, 100),
        request_id: String(body && body.request_id || '').slice(0, 80)
      }));
    } catch (_) {}
    return res.status(status).json({ ok: false, code, message: 'Recovery maksimum tidak dapat diverifikasi.' });
  } finally {
    if (argon2GateClaimed) diracRecoveryHpkeArgon2ReleaseV187();
    if (argonQueueTicket && typeof argonQueueTicket.release === 'function') {
      try { await argonQueueTicket.release(); } catch (_) {}
    }
    try { if (hybrid && hybrid.plaintext) hybrid.plaintext.fill(0); } catch (_) {}
    try { if (hybrid && hybrid.responseKey) hybrid.responseKey.fill(0); } catch (_) {}
    try { if (hybrid && hybrid.transcriptHash) hybrid.transcriptHash.fill(0); } catch (_) {}
    try { if (parsedHybrid && parsedHybrid.dek) parsedHybrid.dek.fill(0); } catch (_) {}
    recoveryCode = '';
    recovered = null;
  }
}

/* ============================================================
   DIRAC RECOVERY-ONLY SERVER 2 FINAL BOUNDARY v201
   This export accepts only the isolated recovery worker and the
   encrypted recovery verification action. No application, payment,
   product, login, dashboard, or invoice route is exported here.
   ============================================================ */

const DIRAC_RECOVERY_ONLY_SERVER2_V201 = 'dirac-recovery-only-server2-v201';
const DIRAC_RECOVERY_WORKER_AUTH_CONTEXT_V201 = 'dirac-recovery-worker-auth-v201';
const DIRAC_RECOVERY_WORKER_DEFAULT_PATH_V201 = '/api/health';
const DIRAC_RECOVERY_BROWSER_ORIGIN_V201 = 'https://secure.diracgroup.store';
const DIRAC_RECOVERY_PAGE_NONCE_HEADER_V203 = 'X-Dirac-Page-Nonce';
const DIRAC_RECOVERY_PAGE_NONCE_TYPE_V203 = 'dirac-recovery-page-nonce-v203';
const DIRAC_RECOVERY_PAGE_NONCE_MAX_AGE_MS_V203 = 120_000;
const DIRAC_RECOVERY_PAGE_NONCE_CLOCK_SKEW_MS_V203 = 30_000;
const DIRAC_RECOVERY_PERMANENT_BAN_MS_V201 = 100 * 365 * 24 * 60 * 60 * 1000;
const DIRAC_RECOVERY_CONTEXT_STACK_V201 = [];
const DIRAC_RECOVERY_MEMORY_BANS_V201 = globalThis.__DIRAC_RECOVERY_MEMORY_BANS_V201__ || new Map();
globalThis.__DIRAC_RECOVERY_MEMORY_BANS_V201__ = DIRAC_RECOVERY_MEMORY_BANS_V201;

function diracNowIso() {
  return new Date().toISOString();
}

function safeEqual(left, right) {
  const a = crypto.createHash('sha512').update(String(left === undefined ? '' : left), 'utf8').digest();
  const b = crypto.createHash('sha512').update(String(right === undefined ? '' : right), 'utf8').digest();
  try { return crypto.timingSafeEqual(a, b); } finally { a.fill(0); b.fill(0); }
}

function diracRecoveryWorkerConfiguredPathV201() {
  const raw = String(process.env.DIRAC_RECOVERY_WORKER_PATH || DIRAC_RECOVERY_WORKER_DEFAULT_PATH_V201).trim();
  if (!/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,240}$/.test(raw) || raw.includes('//') || raw.includes('..')) return '';
  return raw.replace(/\/+$/, '') || '/';
}

customerSecurityRecoveryWorkerSign = function customerSecurityRecoveryWorkerSignV201(caller, timestamp, canonicalBody) {
  const path = diracRecoveryWorkerConfiguredPathV201();
  const secret = customerSecurityRecoveryWorkerSecret();
  if (!path || !secret) return '';
  return crypto.createHmac('sha512', secret)
    .update(DIRAC_RECOVERY_WORKER_AUTH_CONTEXT_V201)
    .update('\nPOST\n')
    .update(path)
    .update('\n')
    .update(String(caller || ''))
    .update('\n')
    .update(String(timestamp || ''))
    .update('\n')
    .update(String(canonicalBody || ''))
    .digest('base64url');
};
Object.defineProperty(customerSecurityRecoveryWorkerSign, '__diracRecoveryOnlyV201', { value: true, enumerable: false });

function diracRecoveryHeaderV201(req, name) {
  const headers = req && req.headers || {};
  const lower = String(name || '').toLowerCase();
  const value = headers[lower] !== undefined ? headers[lower] : headers[name];
  return Array.isArray(value) ? String(value[0] || '').trim() : String(value || '').trim();
}

function diracRecoveryPageNonceCsrfV203(req) {
  return diracRecoveryHeaderV201(req, 'x-dirac-csrf-token')
    || diracRecoveryHeaderV201(req, 'x-csrf-token');
}

function diracRecoveryPageNonceIssueV203(res, action, csrfToken) {
  const csrf = String(csrfToken || '').trim();
  if (!csrf || !res || typeof res.setHeader !== 'function') return '';
  const now = Date.now();
  const payload = {
    typ: DIRAC_RECOVERY_PAGE_NONCE_TYPE_V203,
    action: String(action || ''),
    guard: DIRAC_CENTRAL_SECURITY_GUARD_V146,
    iat_ms: now,
    exp_ms: now + DIRAC_RECOVERY_PAGE_NONCE_MAX_AGE_MS_V203,
    nonce: crypto.randomBytes(24).toString('base64url'),
    csrf_sha512: crypto.createHash('sha512').update('csrf|' + csrf, 'utf8').digest('base64url'),
    origin_sha512: crypto.createHash('sha512').update('origin|' + DIRAC_RECOVERY_BROWSER_ORIGIN_V201, 'utf8').digest('base64url')
  };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  let secret;
  try {
    secret = Buffer.from(diracCentralDeriveSecretV146('recovery-page-nonce-v203'));
    if (secret.length !== 64) return '';
    const signature = crypto.createHmac('sha512', secret).update(body, 'ascii').digest('base64url');
    const token = body + '.' + signature;
    res.setHeader(DIRAC_RECOVERY_PAGE_NONCE_HEADER_V203, token);
    return token;
  } catch (_) {
    return '';
  } finally {
    if (Buffer.isBuffer(secret)) secret.fill(0);
  }
}

function diracRecoveryPageNonceVerifyV203(req, action) {
  const csrf = diracRecoveryPageNonceCsrfV203(req);
  const token = diracRecoveryHeaderV201(req, 'x-dirac-page-nonce');
  if (!csrf) return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_CSRF_MISSING' };
  if (!token) return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_MISSING' };
  if (token.length > 4096) return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_FORMAT_INVALID' };
  const parts = token.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{86}$/.test(parts[1])) {
    return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_FORMAT_INVALID' };
  }
  let secret;
  try {
    secret = Buffer.from(diracCentralDeriveSecretV146('recovery-page-nonce-v203'));
    if (secret.length !== 64) return { ok: false, status: 503, code: 'RECOVERY_PAGE_NONCE_SECRET_INVALID' };
    const expectedSignature = crypto.createHmac('sha512', secret).update(parts[0], 'ascii').digest('base64url');
    if (!safeEqual(parts[1], expectedSignature)) return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_SIGNATURE_INVALID' };

    const decodedBytes = Buffer.from(parts[0], 'base64url');
    if (!decodedBytes.length || decodedBytes.length > 2048 || decodedBytes.toString('base64url') !== parts[0]) {
      decodedBytes.fill(0);
      return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_FORMAT_INVALID' };
    }
    let payload;
    try { payload = JSON.parse(decodedBytes.toString('utf8')); }
    finally { decodedBytes.fill(0); }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_PAYLOAD_INVALID' };
    }
    const keys = Object.keys(payload).sort();
    const expectedKeys = ['action', 'csrf_sha512', 'exp_ms', 'guard', 'iat_ms', 'nonce', 'origin_sha512', 'typ'];
    if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
      return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_FIELDS_INVALID' };
    }
    const now = Date.now();
    const issuedAt = Number(payload.iat_ms);
    const expiresAt = Number(payload.exp_ms);
    if (payload.typ !== DIRAC_RECOVERY_PAGE_NONCE_TYPE_V203
        || payload.action !== String(action || '')
        || payload.guard !== DIRAC_CENTRAL_SECURITY_GUARD_V146
        || !Number.isSafeInteger(issuedAt)
        || !Number.isSafeInteger(expiresAt)
        || expiresAt <= issuedAt
        || expiresAt - issuedAt !== DIRAC_RECOVERY_PAGE_NONCE_MAX_AGE_MS_V203
        || issuedAt > now + DIRAC_RECOVERY_PAGE_NONCE_CLOCK_SKEW_MS_V203
        || expiresAt + DIRAC_RECOVERY_PAGE_NONCE_CLOCK_SKEW_MS_V203 < now
        || !/^[A-Za-z0-9_-]{32}$/.test(String(payload.nonce || ''))) {
      return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_POLICY_INVALID' };
    }
    const expectedCsrfHash = crypto.createHash('sha512').update('csrf|' + csrf, 'utf8').digest('base64url');
    const expectedOriginHash = crypto.createHash('sha512').update('origin|' + DIRAC_RECOVERY_BROWSER_ORIGIN_V201, 'utf8').digest('base64url');
    if (!safeEqual(payload.csrf_sha512, expectedCsrfHash)) {
      return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_CSRF_BINDING_INVALID' };
    }
    if (!safeEqual(payload.origin_sha512, expectedOriginHash)) {
      return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_ORIGIN_BINDING_INVALID' };
    }
    return { ok: true, source: 'central_guard_bootstrap_page_nonce_v203' };
  } catch (_) {
    return { ok: false, status: 403, code: 'RECOVERY_PAGE_NONCE_INVALID' };
  } finally {
    if (Buffer.isBuffer(secret)) secret.fill(0);
  }
}

function diracRecoveryValidatePlainObjectV201(value, depth = 0, budget = { keys: 0, bytes: 0 }) {
  if (depth > 12) throw new Error('RECOVERY_JSON_DEPTH_INVALID');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('RECOVERY_JSON_NUMBER_INVALID');
    return value;
  }
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value, 'utf8');
    if (budget.bytes > 256 * 1024 || value.length > 128 * 1024) throw new Error('RECOVERY_JSON_STRING_INVALID');
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 256) throw new Error('RECOVERY_JSON_ARRAY_INVALID');
    for (const item of value) diracRecoveryValidatePlainObjectV201(item, depth + 1, budget);
    return value;
  }
  if (!value || typeof value !== 'object') throw new Error('RECOVERY_JSON_TYPE_INVALID');
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new Error('RECOVERY_JSON_PROTOTYPE_INVALID');
  for (const [key, item] of Object.entries(value)) {
    budget.keys += 1;
    budget.bytes += Buffer.byteLength(key, 'utf8');
    if (budget.keys > 512 || key.length > 128 || /^(?:__proto__|prototype|constructor)$/i.test(key)) {
      throw new Error('RECOVERY_JSON_KEY_INVALID');
    }
    diracRecoveryValidatePlainObjectV201(item, depth + 1, budget);
  }
  return value;
}

async function readLimitedJsonBody(req, limitBytes = 64 * 1024) {
  if (req && req.__diracCentralParsedBodyV146 && typeof req.__diracCentralParsedBodyV146 === 'object') {
    return diracRecoveryValidatePlainObjectV201(req.__diracCentralParsedBodyV146);
  }
  if (req && req.body !== undefined && req.body !== null) {
    let body = req.body;
    if (Buffer.isBuffer(body)) body = body.toString('utf8');
    if (typeof body === 'string') {
      if (Buffer.byteLength(body, 'utf8') > limitBytes) {
        const error = new Error('RECOVERY_BODY_TOO_LARGE'); error.statusCode = 413; throw error;
      }
      body = JSON.parse(body);
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      const error = new Error('RECOVERY_BODY_OBJECT_REQUIRED'); error.statusCode = 400; throw error;
    }
    req.__diracCentralParsedBodyV146 = diracRecoveryValidatePlainObjectV201(body);
    return req.__diracCentralParsedBodyV146;
  }
  const chunks = [];
  let total = 0;
  for await (const chunkValue of req) {
    const chunk = Buffer.from(chunkValue);
    total += chunk.length;
    if (total > limitBytes) {
      for (const item of chunks) item.fill(0);
      chunk.fill(0);
      const error = new Error('RECOVERY_BODY_TOO_LARGE'); error.statusCode = 413; throw error;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  for (const item of chunks) item.fill(0);
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    const body = JSON.parse(text);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      const error = new Error('RECOVERY_BODY_OBJECT_REQUIRED'); error.statusCode = 400; throw error;
    }
    req.__diracCentralParsedBodyV146 = diracRecoveryValidatePlainObjectV201(body);
    return req.__diracCentralParsedBodyV146;
  } catch (error) {
    if (!error.statusCode) error.statusCode = 400;
    throw error;
  } finally {
    raw.fill(0);
  }
}

async function readBody(req) {
  return readLimitedJsonBody(req, customerSecurityRecoveryWorkerMaxBodyBytes());
}

function diracRecoverySupabaseAllowedTableV201(table) {
  const configuredGuard = DIRAC_PERSISTENT_BAN_TABLE;
  const allowed = new Set([
    configuredGuard,
    DIRAC_S2S_SECURITY_TABLE,
    'dirac_security_rate_limits',
    'security_customer_access_blocks',
    'security_customer_auth_links',
    'security_customer_settings',
    'security_customer_password_hashes',
    'security_customer_recovery_codes',
    'security_customer_sessions',
    'security_lost_passkey_recovery_requests',
    'security_lost_passkey_recovery_sessions',
    'security_customer_events',
    'customers',
    'domain_passkeys'
  ]);
  return /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(table) && allowed.has(table);
}

async function diracRecoveryReadResponseLimitedV201(response, maximum = 2 * 1024 * 1024) {
  const limit = Math.max(1024, Math.min(16 * 1024 * 1024, Number(maximum || 0)));
  const lengthHeader = String(response && response.headers && response.headers.get
    ? response.headers.get('content-length') || ''
    : '').trim();
  if (lengthHeader && (!/^\d+$/.test(lengthHeader) || Number(lengthHeader) > limit)) {
    const error = new Error('UPSTREAM_RESPONSE_TOO_LARGE');
    error.code = 'UPSTREAM_RESPONSE_TOO_LARGE';
    throw error;
  }
  if (!response || !response.body || typeof response.body.getReader !== 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > limit) {
      const error = new Error('UPSTREAM_RESPONSE_TOO_LARGE');
      error.code = 'UPSTREAM_RESPONSE_TOO_LARGE';
      throw error;
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const item = await reader.read();
      if (item.done) break;
      const chunk = Buffer.from(item.value || []);
      total += chunk.length;
      if (total > limit) {
        chunk.fill(0);
        try { await reader.cancel('response_limit_exceeded'); } catch (_) {}
        const error = new Error('UPSTREAM_RESPONSE_TOO_LARGE');
        error.code = 'UPSTREAM_RESPONSE_TOO_LARGE';
        throw error;
      }
      chunks.push(chunk);
    }
    const joined = Buffer.concat(chunks, total);
    try { return joined.toString('utf8'); }
    finally { joined.fill(0); }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch (_) {}
  }
}

async function supabaseFetch(path, options = {}) {
  const cleanPath = String(path || '');
  if (!cleanPath.startsWith('/') || cleanPath.includes('\\') || /[\r\n\0]/.test(cleanPath) || cleanPath.startsWith('//')) {
    return { ok: false, status: 400, data: { code: 'SUPABASE_PATH_INVALID' } };
  }
  const table = typeof getDiracRestTableFromPath === 'function' ? getDiracRestTableFromPath(cleanPath) : '';
  if (cleanPath.startsWith('/rest/v1/') && table && !diracRecoverySupabaseAllowedTableV201(table)) {
    return { ok: false, status: 403, data: { code: 'SUPABASE_TABLE_NOT_ALLOWED' } };
  }
  if (!cleanPath.startsWith('/rest/v1/') && !cleanPath.startsWith('/auth/v1/')) {
    return { ok: false, status: 403, data: { code: 'SUPABASE_ROUTE_NOT_ALLOWED' } };
  }
  const method = String(options.method || 'GET').toUpperCase();
  if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) {
    return { ok: false, status: 405, data: { code: 'SUPABASE_METHOD_NOT_ALLOWED' } };
  }
  let target;
  try {
    const targetKey = typeof resolveDiracSupabaseTargetKey === 'function' ? resolveDiracSupabaseTargetKey(cleanPath, options) : 'legacy';
    target = readDiracSupabaseCredentials(targetKey);
    const base = new URL(String(target.url || ''));
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || (base.port && base.port !== '443')) {
      throw new Error('SUPABASE_URL_INVALID');
    }
    target.url = base.origin;
  } catch (error) {
    return { ok: false, status: 503, data: { code: 'SUPABASE_CONFIGURATION_INVALID' }, error: String(error && error.code || error && error.message || '') };
  }
  const key = options.auth === 'service' ? target.serviceKey : target.anonKey;
  const bearer = String(options.bearer || key || '');
  if (!key || !bearer || Buffer.byteLength(String(key), 'utf8') < 20) {
    return { ok: false, status: 503, data: { code: 'SUPABASE_KEY_INVALID' } };
  }
  const headers = {
    apikey: String(key),
    Authorization: `Bearer ${bearer}`,
    Accept: 'application/json',
    'Content-Type': 'application/json'
  };
  if (options.prefer) headers.Prefer = String(options.prefer).slice(0, 300);
  const controller = new AbortController();
  const timeoutMs = Math.max(1000, Math.min(30000, Number(options.timeoutMs || process.env.DIRAC_SUPABASE_FETCH_TIMEOUT_MS || 8000)));
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(target.url + cleanPath, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      redirect: 'error',
      signal: controller.signal
    });
    const text = await diracRecoveryReadResponseLimitedV201(response);
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text.slice(0, 2048); }
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    return {
      ok: false,
      status: error && error.name === 'AbortError' ? 504 : 502,
      data: { code: error && error.name === 'AbortError' ? 'SUPABASE_FETCH_TIMEOUT' : 'SUPABASE_FETCH_FAILED' },
      error: String(error && error.code || error && error.name || 'SUPABASE_FETCH_FAILED')
    };
  } finally {
    clearTimeout(timer);
  }
}

async function customerSecurityWriteGuardEvent(customerId, options = {}) {
  const cleanId = String(customerId || '').trim();
  if (!/^[0-9a-f]{8}-[0-9a-f-]{27,40}$/i.test(cleanId)) return false;
  const req = options.req || {};
  const userAgent = String(req.headers && req.headers['user-agent'] || '').replace(/[\u0000-\u001f\u007f<>]/g, '').slice(0, 512);
  const metadata = options.metadata && typeof options.metadata === 'object' && !Array.isArray(options.metadata)
    ? diracRecoveryValidatePlainObjectV201(JSON.parse(JSON.stringify(options.metadata)))
    : {};
  const result = await supabaseFetch('/rest/v1/security_customer_events', {
    method: 'POST',
    auth: 'service',
    body: [{
      customer_id: cleanId,
      event_type: String(options.event_type || 'lost_passkey_recovery').replace(/[^a-z0-9_.:-]/gi, '_').slice(0, 100),
      status: String(options.status || 'info').slice(0, 30),
      risk_level: String(options.risk_level || 'high').slice(0, 30),
      description: String(options.description || 'Recovery security event.').replace(/[\u0000-\u001f\u007f<>]/g, '').slice(0, 500),
      ip_address: diracCentralTrustedClientIpV183(req),
      user_agent: userAgent,
      metadata: { source: DIRAC_RECOVERY_ONLY_SERVER2_V201, ...metadata }
    }]
  });
  return Boolean(result && result.ok);
}

function diracRecoveryApplyHeadersV201(req, res, action) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Origin-Agent-Cluster', '?1');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Vary', 'Origin');
  if ([DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159, DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165].includes(action)) {
    const origin = diracRecoveryHeaderV201(req, 'origin');
    if (origin === DIRAC_RECOVERY_BROWSER_ORIGIN_V201) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', action === DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159 ? 'HEAD, POST, OPTIONS' : 'POST, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Accept, X-Dirac-CSRF-Token, X-CSRF-Token, X-Dirac-Page-Nonce, X-Idempotency-Key, X-Dirac-Html-Signature-Version, X-Dirac-Html-Signature-Timestamp, X-Dirac-Html-Signature-Nonce, X-Dirac-Html-Signature'
      );
      res.setHeader('Access-Control-Expose-Headers', 'X-Dirac-CSRF-Token, X-Dirac-CSRF-Ready, X-Dirac-Page-Nonce, X-Dirac-Central-Security-Guard');
      res.setHeader('Access-Control-Max-Age', '300');
    }
  }
}

function diracRecoveryLegacyIdentityV201(req, action) {
  const ip = diracCentralTrustedClientIpV183(req);
  if (process.env.NODE_ENV === 'production' && ip === 'unknown') throw new Error('RECOVERY_TRUSTED_CLIENT_IP_REQUIRED');
  const caller = diracRecoveryHeaderV201(req, 'x-dirac-worker-caller').slice(0, 80);
  const ua = diracRecoveryHeaderV201(req, 'user-agent').slice(0, 512);
  const cleanAction = String(action || '');
  const hpkeVerifyNamespaceV203 = cleanAction === DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159;
  const material = [cleanAction, ip, caller, ua].join('|');
  const secret = Buffer.from(diracCentralRootSecretV146(), 'utf8');
  if (secret.length < 64) throw new Error('RECOVERY_BAN_SECRET_INVALID');
  try {
    const namespace = hpkeVerifyNamespaceV203 ? 'central-ban-v203:' : 'central-ban-v201:';
    return namespace + crypto.createHmac('sha512', secret).update(material, 'utf8').digest('hex');
  } finally {
    secret.fill(0);
  }
}

function diracRecoveryIdentityV201(req, action) {
  const ip = diracCentralTrustedClientIpV183(req);
  if (process.env.NODE_ENV === 'production' && ip === 'unknown') throw new Error('RECOVERY_TRUSTED_CLIENT_IP_REQUIRED');
  const caller = diracRecoveryHeaderV201(req, 'x-dirac-worker-caller').slice(0, 80);
  const allowedCaller = customerSecurityRecoveryWorkerAllowedCaller();
  const callerClass = caller && allowedCaller && safeEqual(caller, allowedCaller) ? 'trusted-worker' : (caller ? 'untrusted-worker' : 'browser');
  const ua = diracRecoveryHeaderV201(req, 'user-agent').slice(0, 512);
  const cleanAction = String(action || '');
  const origin = diracRecoveryHeaderV201(req, 'origin').slice(0, 256).toLowerCase();
  const originClass = origin === DIRAC_RECOVERY_BROWSER_ORIGIN_V201 ? 'official-origin' : (origin ? 'untrusted-origin' : 'origin-absent');
  const forwardedHost = diracRecoveryHeaderV201(req, 'x-forwarded-host').split(',')[0].trim().slice(0, 255).toLowerCase();
  const host = (forwardedHost || diracRecoveryHeaderV201(req, 'host').split(',')[0].trim()).slice(0, 255).toLowerCase();
  const hostClass = host === 'secure.diracgroup.store' ? 'official-host' : (host ? 'untrusted-host' : 'host-absent');
  const fetchSite = diracRecoveryHeaderV201(req, 'sec-fetch-site').slice(0, 32).toLowerCase();
  const fetchSiteClass = fetchSite === 'same-origin' || fetchSite === 'same-site' ? fetchSite : (fetchSite ? 'cross-site' : 'fetch-site-absent');
  let sessionHash = '';
  try { sessionHash = typeof diracCentralRequestSessionHashV146 === 'function' ? String(diracCentralRequestSessionHashV146(req) || '') : ''; } catch (_) {}
  const material = [cleanAction, ip, callerClass, ua, originClass, hostClass, fetchSiteClass, sessionHash].join('|');
  const secret = Buffer.from(diracCentralDeriveSecretV146('recovery-ban-v205'));
  if (secret.length < 64) throw new Error('RECOVERY_BAN_SECRET_INVALID');
  try {
    return 'central-ban-v205:' + crypto.createHmac('sha512', secret)
      .update('dirac-recovery-ban-identity-v205\n', 'utf8')
      .update(material, 'utf8')
      .digest('hex');
  } finally {
    secret.fill(0);
  }
}

function diracRecoveryIdentityKeysV205(req, action) {
  const keys = [diracRecoveryIdentityV201(req, action), diracRecoveryLegacyIdentityV201(req, action)];
  return Array.from(new Set(keys.filter(Boolean)));
}

async function diracRecoveryCheckBanV201(req, action) {
  const keys = diracRecoveryIdentityKeysV205(req, action);
  const primaryKey = keys[0];
  for (const key of keys) {
    const memory = Number(DIRAC_RECOVERY_MEMORY_BANS_V201.get(key) || 0);
    if (memory > Date.now()) return { ok: false, key: primaryKey, blockedUntilMs: memory };
  }
  for (const key of keys) {
    const strict = await readPersistentSecurityJsonStrictV194(key);
    if (!strict || strict.ok !== true) return { ok: false, key: primaryKey, persistenceUnavailable: true };
    const blockedUntilMs = Number(strict.found && strict.record && strict.record.blocked_until_ms || 0);
    if (blockedUntilMs > Date.now()) {
      for (const banKey of keys) DIRAC_RECOVERY_MEMORY_BANS_V201.set(banKey, blockedUntilMs);
      return { ok: false, key: primaryKey, blockedUntilMs };
    }
  }
  return { ok: true, key: primaryKey };
}

async function diracRecoveryPermanentBanV201(req, action, reason, identityKey) {
  const now = Date.now();
  const blockedUntilMs = now + DIRAC_RECOVERY_PERMANENT_BAN_MS_V201;
  const key = identityKey || diracRecoveryIdentityV201(req, action);
  const record = {
    type: 'recovery_one_strike_persistent_ban_v201',
    risk: 'critical',
    action: String(action || '').slice(0, 100),
    method: String(req && req.method || '').slice(0, 20),
    reason: String(reason || 'central_guard_failed').replace(/[^a-z0-9_.:-]/gi, '_').slice(0, 120),
    source: DIRAC_RECOVERY_ONLY_SERVER2_V201,
    created_at: new Date(now).toISOString(),
    blocked_until_ms: blockedUntilMs
  };
  const wrote = await writePersistentSecurityJsonRequiredV194(key, record, blockedUntilMs, Math.ceil(DIRAC_RECOVERY_PERMANENT_BAN_MS_V201 / 1000));
  DIRAC_RECOVERY_MEMORY_BANS_V201.set(key, blockedUntilMs);
  return Boolean(wrote);
}

async function diracRecoveryGuardRejectV201(req, res, action, reason, status = 403, identityKey = '') {
  const persisted = await diracRecoveryPermanentBanV201(req, action, reason, identityKey).catch(() => false);
  return res.status(persisted ? status : 503).json({
    ok: false,
    code: persisted ? 'RECOVERY_CENTRAL_GUARD_BLOCKED' : 'RECOVERY_BAN_PERSISTENCE_UNAVAILABLE',
    message: 'Permintaan ditolak oleh sistem keamanan.'
  });
}

function diracRecoveryAssertServer2EnvironmentV201() {
  const role = String(process.env.DIRAC_CENTRAL_DEPLOYMENT_ROLE || process.env.DIRAC_DEPLOYMENT_ROLE || '').trim().toLowerCase();
  const enabled = /^(?:1|true|yes|on|enabled)$/i.test(String(process.env.DIRAC_CENTRAL_VERCEL2_ACTIONS_ENABLED || process.env.DIRAC_VERCEL2_ACTIONS_ENABLED || ''));
  if (process.env.NODE_ENV === 'production' && role !== 'vercel2') {
    throw new Error('DIRAC_SERVER2_DEPLOYMENT_ROLE_REQUIRED');
  }
  if (process.env.NODE_ENV === 'production' && !enabled) throw new Error('DIRAC_SERVER2_ACTIONS_ENABLED_REQUIRED');
  if (process.env.NODE_ENV === 'production'
      && (!DIRAC_CENTRAL_ASYNC_CONTEXT_V149
        || typeof DIRAC_CENTRAL_ASYNC_CONTEXT_V149.run !== 'function'
        || typeof DIRAC_CENTRAL_ASYNC_CONTEXT_V149.getStore !== 'function')) {
    throw new Error('DIRAC_SERVER2_ASYNC_REQUEST_CONTEXT_REQUIRED');
  }
  if (process.env.NODE_ENV === 'production') {
    const configuredActions = DIRAC_CENTRAL_ENV_VERCEL2_ONLY_ACTIONS_V174;
    const compiledActions = DIRAC_CENTRAL_ACTIVE_ACTIONS_V146;
    if (configuredActions.size !== compiledActions.size
        || Array.from(compiledActions).some((action) => !configuredActions.has(action))
        || Array.from(configuredActions).some((action) => !compiledActions.has(action))) {
      throw new Error('DIRAC_SERVER2_ACTION_ENV_ALLOWLIST_INVALID');
    }
  }
  const forbidden = [
    'DIRAC_RECOVERY_WORKER_URL',
    'DIRAC_RECOVERY_WORKER_EXPECTED_HOST',
    'DIRAC_RECOVERY_WORKER_CALLER',
    'DIRAC_RECOVERY_HPKE_ALLOWED_CALLER'
  ];
  if (process.env.NODE_ENV === 'production' && forbidden.some((name) => String(process.env[name] || '').trim())) {
    throw new Error('DIRAC_SERVER2_ENV_PARTITION_FAILED');
  }
  if (process.env.NODE_ENV === 'production' && DIRAC_PERSISTENT_BAN_TABLE !== 'dirac_persistent_bans') {
    throw new Error('DIRAC_SERVER2_PERSISTENT_BAN_TABLE_REQUIRED');
  }
  if (process.env.NODE_ENV === 'production') {
    diracCentralRootSecretV146();
    const workerSecret = customerSecurityRecoveryWorkerSecret();
    if (!workerSecret) throw new Error('DIRAC_SERVER2_WORKER_SECRET_REQUIRED');
    if (!customerSecurityRecoveryWorkerAllowedCaller()) throw new Error('DIRAC_SERVER2_ALLOWED_CALLER_REQUIRED');
    customerSecurityRecoveryWorkerPrivateKeyV190('DIRAC_RECOVERY_WORKER_X25519_PRIVATE_KEY', 'x25519');
    customerSecurityRecoveryWorkerPrivateKeyV190('DIRAC_RECOVERY_WORKER_MLKEM1024_PRIVATE_KEY', 'ml-kem-1024');
    DIRAC_RECOVERY_CRYPTO_V2.assertRuntimePolicy();
    if (!customerSecurityRecoveryWorkerLocalEnabled()) throw new Error('DIRAC_SERVER2_RECOVERY_WORKER_BOUNDARY_INVALID');
    const explicitPepper = String(process.env.DIRAC_LOST_PASSKEY_DB_PEPPER || '').normalize('NFC');
    if (Buffer.byteLength(explicitPepper, 'utf8') < LOST_PASSKEY_DB_PEPPER_MIN_BYTES_V157) {
      throw new Error('DIRAC_SERVER2_DB_PEPPER_REQUIRED');
    }
    const vaultSecrets = customerSecurityLostPasskeyRequireVaultSecretsV157();
    if (!vaultSecrets || vaultSecrets.ok !== true) throw new Error(String(vaultSecrets && vaultSecrets.code || 'DIRAC_SERVER2_VAULT_SECRET_INVALID'));
  }
  return true;
}

diracRecoveryAssertServer2EnvironmentV201();

const DIRAC_RECOVERY_HTML_SIGNATURE_VERSION_V202 = 'dirac-html-action-signature-v180';
const DIRAC_RECOVERY_HTML_SIGNATURE_MAX_SKEW_MS_V202 = 30_000;

function diracRecoveryLinkOpenJsonV202(res, status, code, message) {
  try { res.setHeader('Content-Type', 'application/json; charset=utf-8'); } catch (_) {}
  return res.status(status).json({
    ok: false,
    code: String(code || 'RECOVERY_LINK_INVALID'),
    message: String(message || 'Link recovery tidak valid atau sudah tidak berlaku.')
  });
}

function diracRecoveryLinkOpenGenericInvalidV202(res) {
  return diracRecoveryLinkOpenJsonV202(res, 404, 'RECOVERY_LINK_INVALID', 'Link recovery tidak valid atau sudah tidak berlaku.');
}

function diracRecoveryLinkOpenSignaturePayloadV202(body, timestamp, nonce) {
  const bodyCanonical = customerSecurityLostPasskeyCanonical(body);
  return {
    action: DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165,
    body_sha256: crypto.createHash('sha256').update(bodyCanonical, 'utf8').digest('base64url'),
    iat_ms: timestamp,
    method: 'POST',
    nonce,
    origin: DIRAC_RECOVERY_BROWSER_ORIGIN_V201,
    path: '/api/health',
    query_format: 'json',
    rid: String(body.rid || ''),
    token_sha256: crypto.createHash('sha256').update(String(body.token || ''), 'utf8').digest('base64url'),
    typ: DIRAC_RECOVERY_HTML_SIGNATURE_VERSION_V202
  };
}

function diracRecoveryLinkOpenExpectedSignatureV202(body, timestamp, nonce) {
  const token = Buffer.from(String(body && body.token || ''), 'utf8');
  const salt = Buffer.from('dirac-html-action-signature-v180:salt', 'utf8');
  const info = Buffer.from('dirac-lost-passkey-recovery-link-open:v180', 'utf8');
  let key;
  try {
    key = Buffer.from(crypto.hkdfSync('sha256', token, salt, info, 32));
    return crypto.createHmac('sha256', key)
      .update(customerSecurityLostPasskeyCanonical(diracRecoveryLinkOpenSignaturePayloadV202(body, timestamp, nonce)), 'utf8')
      .digest('base64url');
  } finally {
    token.fill(0);
    salt.fill(0);
    info.fill(0);
    if (Buffer.isBuffer(key)) key.fill(0);
  }
}

function diracRecoveryLinkOpenArgonPolicyV202(metadata) {
  const source = metadata && typeof metadata === 'object' && !Array.isArray(metadata) ? metadata : {};
  const encoded = String(source.link_token_hash || '');
  const encodedParams = customerSecurityLostPasskeyArgon2EncodedParamsV171(encoded);
  const declared = source.link_token_argon2id_params && typeof source.link_token_argon2id_params === 'object' && !Array.isArray(source.link_token_argon2id_params)
    ? source.link_token_argon2id_params
    : null;
  if (!encoded.startsWith('$argon2id$') || !encodedParams || !declared) return { ok: false, encoded: '' };
  const memoryCost = Number(declared.memoryCost);
  const timeCost = Number(declared.timeCost);
  const parallelism = Number(declared.parallelism);
  const exactBinding = memoryCost === encodedParams.memoryCost
    && timeCost === encodedParams.timeCost
    && parallelism === encodedParams.parallelism;
  let required;
  try { required = customerSecurityLostPasskeyLinkOpenArgon2ParamsV171(64); }
  catch (_) { return { ok: false, encoded: '' }; }
  const strictProfile = Number.isSafeInteger(memoryCost)
    && memoryCost >= 1048576
    && memoryCost >= Number(required.memoryCost || 0)
    && memoryCost <= 5242880
    && Number.isSafeInteger(timeCost)
    && timeCost >= 4
    && timeCost >= Number(required.timeCost || 0)
    && timeCost <= 12
    && parallelism === 4
    && parallelism === Number(required.parallelism || 0);
  return { ok: exactBinding && strictProfile, encoded };
}

async function diracRecoveryLinkOpenGuardV202(req, res, ctx, body, identityKey) {
  const origin = diracRecoveryHeaderV201(req, 'origin');
  if (origin !== DIRAC_RECOVERY_BROWSER_ORIGIN_V201) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_origin_invalid', 403, identityKey);
  }
  const forwardedHost = diracRecoveryHeaderV201(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase();
  const host = (forwardedHost || diracRecoveryHeaderV201(req, 'host').split(',')[0].trim()).toLowerCase();
  if (host !== 'secure.diracgroup.store') {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_host_invalid', 403, identityKey);
  }
  const forwardedProto = diracRecoveryHeaderV201(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();
  if ((process.env.NODE_ENV === 'production' && forwardedProto !== 'https')
      || (process.env.NODE_ENV !== 'production' && forwardedProto && forwardedProto !== 'https')) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_protocol_invalid', 403, identityKey);
  }
  const secFetchSite = diracRecoveryHeaderV201(req, 'sec-fetch-site').toLowerCase();
  if (secFetchSite && !['same-origin', 'same-site'].includes(secFetchSite)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_fetch_site_invalid', 403, identityKey);
  }
  const secFetchDest = diracRecoveryHeaderV201(req, 'sec-fetch-dest').toLowerCase();
  if (secFetchDest && secFetchDest !== 'empty') {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_fetch_dest_invalid', 403, identityKey);
  }
  if (req.method !== 'POST') {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_method_invalid', 405, identityKey);
  }
  const contentType = diracRecoveryHeaderV201(req, 'content-type').toLowerCase();
  const accept = diracRecoveryHeaderV201(req, 'accept').toLowerCase();
  if (!/^application\/json(?:\s*;|$)/i.test(contentType) || (accept && !accept.includes('application/json') && !accept.includes('*/*'))) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_media_type_invalid', 415, identityKey);
  }
  const query = req && req.query && typeof req.query === 'object' && !Array.isArray(req.query) ? req.query : {};
  const queryKeys = Object.keys(query).sort();
  const expectedQueryKeys = ['action', 'format'];
  if (queryKeys.length !== expectedQueryKeys.length
      || queryKeys.some((key, index) => key !== expectedQueryKeys[index])
      || String(query.action || '').trim().toLowerCase() !== DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
      || String(query.format || '').trim().toLowerCase() !== 'json') {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_query_invalid', 403, identityKey);
  }
  const bodyKeys = Object.keys(body).sort();
  const expectedBodyKeys = ['action', 'rid', 'token'];
  if (bodyKeys.length !== expectedBodyKeys.length || bodyKeys.some((key, index) => key !== expectedBodyKeys[index])) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_body_fields_invalid', 403, identityKey);
  }
  if (String(body.action || '') !== DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
      || !customerSecurityNormalizeLostPasskeyRequestId(body.rid)
      || !customerSecurityLostPasskeyLinkTokenShapeV162(body.token)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_body_binding_invalid', 403, identityKey);
  }
  const version = diracRecoveryHeaderV201(req, 'x-dirac-html-signature-version');
  const timestampText = diracRecoveryHeaderV201(req, 'x-dirac-html-signature-timestamp');
  const nonce = diracRecoveryHeaderV201(req, 'x-dirac-html-signature-nonce');
  const signature = diracRecoveryHeaderV201(req, 'x-dirac-html-signature');
  const timestamp = Number(timestampText);
  if (version !== DIRAC_RECOVERY_HTML_SIGNATURE_VERSION_V202
      || !Number.isSafeInteger(timestamp)
      || timestamp <= 0
      || Math.abs(Date.now() - timestamp) > DIRAC_RECOVERY_HTML_SIGNATURE_MAX_SKEW_MS_V202
      || !/^[A-Za-z0-9_-]{43}$/.test(nonce)
      || !/^[A-Za-z0-9_-]{43}$/.test(signature)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_html_signature_headers_invalid', 403, identityKey);
  }
  let expectedSignature = '';
  try { expectedSignature = diracRecoveryLinkOpenExpectedSignatureV202(body, timestamp, nonce); }
  catch (_) { return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_html_signature_runtime_invalid', 403, identityKey); }
  if (!expectedSignature || !safeEqual(signature, expectedSignature)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'recovery_link_html_signature_invalid', 403, identityKey);
  }
  const nonceClaim = await diracCentralRecoveryWorkerClaimNonceV183(
    DIRAC_RECOVERY_HTML_SIGNATURE_VERSION_V202 + ':' + String(body.rid || ''),
    nonce,
    timestamp + DIRAC_RECOVERY_HTML_SIGNATURE_MAX_SKEW_MS_V202 + 60_000
  );
  if (!nonceClaim || nonceClaim.ok !== true) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, String(nonceClaim && nonceClaim.reason || 'recovery_link_nonce_replay'), 409, identityKey);
  }
  return null;
}

async function diracRecoveryLinkOpenV202(req, res, ctx, body) {
  if (!diracCentralGuardPassedForHandlerV168(req)
      || !ctx
      || ctx.req !== req
      || ctx.action !== DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
      || ctx.classification !== 'browser'
      || !ctx.guardPassport
      || ctx.guardPassport.integrity_checked !== true) {
    return diracRecoveryLinkOpenJsonV202(res, 403, 'CENTRAL_GUARD_REQUIRED', 'Permintaan ditolak oleh sistem keamanan.');
  }
  if (!DIRAC_CENTRAL_ENV_VERCEL2_ONLY_ACTIONS_V174.has(DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165)) {
    return diracRecoveryLinkOpenJsonV202(res, 403, 'RECOVERY_LINK_ACTION_NOT_ALLOWED', 'Action tidak diizinkan pada server ini.');
  }

  const requestId = customerSecurityNormalizeLostPasskeyRequestId(body && body.rid);
  const linkToken = String(body && body.token || '').trim();
  let argonQueueTicket = null;
  let hpkePublicRaw = null;
  try {
    if (!requestId || !customerSecurityLostPasskeyLinkTokenShapeV162(linkToken)) return diracRecoveryLinkOpenGenericInvalidV202(res);
    const initialRequest = await diracRecoveryHpkeReadRequestV159(requestId);
    if (!initialRequest.ok) return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_REQUEST_STORAGE_UNAVAILABLE', 'Layanan recovery belum siap.');
    if (!diracRecoveryHpkeRequestActiveV159(initialRequest.row)) return diracRecoveryLinkOpenGenericInvalidV202(res);

    let row = initialRequest.row;
    let metadata = row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata : {};
    const argonPolicy = diracRecoveryLinkOpenArgonPolicyV202(metadata);
    if (!argonPolicy.ok) return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_LINK_ARGON2_POLICY_INVALID', 'Layanan recovery belum siap.');
    const vaultSecrets = customerSecurityLostPasskeyRequireVaultSecretsV157();
    if (!vaultSecrets.ok) return diracRecoveryLinkOpenJsonV202(res, 503, String(vaultSecrets.code || 'RECOVERY_VAULT_SECRET_INVALID'), 'Layanan recovery belum siap.');

    argonQueueTicket = await customerSecurityLostPasskeyQueueAcquireV164(req, {
      nonce: requestId,
      caller_id: 'recovery_link',
      queue_task: DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
    });
    if (!argonQueueTicket || !argonQueueTicket.ok) {
      try { res.setHeader('Retry-After', String(Math.max(1, Math.ceil(customerSecurityLostPasskeyQueuePollMsV164() / 1000)))); } catch (_) {}
      return diracRecoveryLinkOpenJsonV202(res, 429, 'RECOVERY_ARGON2_BUSY', 'Verifikasi recovery sedang diproses. Silakan coba kembali.');
    }

    const tokenOk = await customerSecurityLostPasskeyArgon2VerifyHashV157(
      'link_token',
      linkToken,
      argonPolicy.encoded,
      vaultSecrets.pepper,
      vaultSecrets.rootSecret
    ).catch(() => false);
    if (!customerSecurityLostPasskeyQueueLeaseHealthyV188(argonQueueTicket)) {
      return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_ARGON2_LEASE_LOST', 'Layanan recovery belum siap.');
    }
    if (!tokenOk) {
      const persistedBan = await diracRecoveryPermanentBanV201(
        req,
        DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165,
        'recovery_link_token_invalid'
      ).catch(() => false);
      return persistedBan
        ? diracRecoveryLinkOpenGenericInvalidV202(res)
        : diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_BAN_PERSISTENCE_UNAVAILABLE', 'Layanan recovery belum siap.');
    }

    const freshRequest = await diracRecoveryHpkeReadRequestV159(requestId);
    if (!freshRequest.ok) return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_REQUEST_STORAGE_UNAVAILABLE', 'Layanan recovery belum siap.');
    if (!diracRecoveryHpkeRequestActiveV159(freshRequest.row) || freshRequest.row.id !== row.id) return diracRecoveryLinkOpenGenericInvalidV202(res);
    row = freshRequest.row;
    metadata = row.metadata && typeof row.metadata === 'object' && !Array.isArray(row.metadata) ? row.metadata : {};
    const bundle = diracRecoveryCryptoV2BundleFromMetadata(metadata);
    if (!bundle || bundle.request_id !== requestId || bundle.request_id !== row.request_id || bundle.metadata.request_id !== requestId) {
      return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_V2_REQUEST_BINDING_INVALID', 'Layanan recovery belum siap.');
    }

    DIRAC_RECOVERY_CRYPTO_V2.assertRuntimePolicy();
    hpkePublicRaw = DIRAC_RECOVERY_CRYPTO_V2.rawX25519Public(diracRecoveryHpkePrivateKeyV159());
    const hpkeKeyId = diracRecoveryHpkeAsciiV159(diracRecoveryHpkeEnvTextV159('DIRAC_RECOVERY_HPKE_KEY_ID'), 1, 80);
    if (!hpkeKeyId) throw DIRAC_RECOVERY_CRYPTO_V2.fail('RECOVERY_HPKE_KEY_ID_INVALID');
    const response = DIRAC_RECOVERY_CRYPTO_V2.makeSignedVaultResponse({
      row,
      metadata,
      bundle,
      hpkePublicRaw,
      hpkeKeyId,
      action: DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165,
      centralGuard: DIRAC_CENTRAL_SECURITY_GUARD_V146
    });
    const argonQueueReleased = await argonQueueTicket.release();
    if (argonQueueReleased !== true) {
      return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_ARGON2_LEASE_LOST', 'Layanan recovery belum siap.');
    }
    argonQueueTicket = null;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Dirac-Central-Security-Guard', DIRAC_CENTRAL_SECURITY_GUARD_V146);
    res.setHeader('X-Dirac-Recovery-Signed-Envelope', DIRAC_RECOVERY_CRYPTO_V2.VERSION);
    res.setHeader('X-Dirac-Recovery-Link-Stage', 'vault_ready');
    return res.status(200).json(response);
  } catch (error) {
    if (customerSecurityLostPasskeyRootCauseDebugEnabledV173()) {
      try { console.error('[dirac-recovery-link-open-v202]', customerSecurityLostPasskeyDiagnosticCodeV210(error && (error.code || error.name) || 'RECOVERY_LINK_OPEN_FAILED', 120)); } catch (_) {}
    }
    return diracRecoveryLinkOpenJsonV202(res, 503, 'RECOVERY_LINK_OPEN_FAILED', 'Layanan recovery belum siap.');
  } finally {
    try { if (argonQueueTicket && typeof argonQueueTicket.release === 'function') await argonQueueTicket.release(); } catch (_) {}
    if (Buffer.isBuffer(hpkePublicRaw)) hpkePublicRaw.fill(0);
    if (body && typeof body === 'object') body.token = '';
  }
}

/* ============================================================
   DIRAC INTERNAL SERVER MESH v206 - SERVER 2 NARROW PATCH
   - Seven independent asymmetric signatures are mandatory for the
     authenticated Server 1 -> Server 2 recovery-worker channel.
   - Signature failure rejects before recovery/Argon2id business logic.
   - Attributed failures are persisted locally and reported to Server 1.
   - Server 2 checks the central revocation registry on every valid request.
   - Existing recovery cryptography, Argon2id costs, endpoints, and handlers
     remain unchanged.
   ============================================================ */
const DIRAC_S2S_VERSION_V206 = 'dirac-s2s-seven-signatures-v1';
const DIRAC_S2S_POLICY_V206 = 'all-seven-required-fail-closed';
const DIRAC_S2S_MAX_CLOCK_SKEW_MS_V206 = 15_000;
const DIRAC_S2S_MLDSA_CONTEXT_V206 = Buffer.from('DIRAC-S2S-SEVEN-SIGNATURES-V1', 'utf8');

function diracS2SStableJsonV206(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(diracS2SStableJsonV206).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + diracS2SStableJsonV206(value[key])).join(',') + '}';
}

function diracS2STextV206(name) {
  return String(process.env[name] || '').trim();
}

const DIRAC_S2S_ENV_JSON_CACHE_V207 = globalThis.__DIRAC_S2S_ENV_JSON_CACHE_V207__ || new Map();
globalThis.__DIRAC_S2S_ENV_JSON_CACHE_V207__ = DIRAC_S2S_ENV_JSON_CACHE_V207;

function diracS2SEnvJsonObjectV207(name, required) {
  const envName = String(name || '').trim();
  const raw = diracS2STextV206(envName);
  if (!raw) return required
    ? { ok: false, unavailable: true, reason: envName + '_missing', value: null }
    : { ok: true, value: Object.freeze({}), source: 'environment' };
  const cached = DIRAC_S2S_ENV_JSON_CACHE_V207.get(envName);
  if (cached && cached.raw === raw) return cached.result;
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch (_) {
    const result = { ok: false, unavailable: true, reason: envName + '_invalid_json', value: null };
    DIRAC_S2S_ENV_JSON_CACHE_V207.set(envName, { raw, result });
    return result;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    const result = { ok: false, unavailable: true, reason: envName + '_invalid_object', value: null };
    DIRAC_S2S_ENV_JSON_CACHE_V207.set(envName, { raw, result });
    return result;
  }
  const result = { ok: true, value: parsed, source: 'environment' };
  DIRAC_S2S_ENV_JSON_CACHE_V207.set(envName, { raw, result });
  return result;
}

function diracS2SValidateEnvRegistryV207(registry) {
  if (!registry || typeof registry !== 'object' || Array.isArray(registry) || Object.keys(registry).length === 0) return false;
  const signatureNames = diracS2SSignatureSpecsV206().map((spec) => spec.name);
  for (const [serverId, entry] of Object.entries(registry)) {
    if (diracS2SIdV206(serverId) !== serverId || !entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
    if (!['active', 'revoked'].includes(String(entry.status || '').trim().toLowerCase())) return false;
    if (!diracS2SKeyVersionV206(entry.key_version)) return false;
    if (!Array.isArray(entry.allowed_targets) || !entry.allowed_targets.length || entry.allowed_targets.some((item) => !diracS2SIdV206(item))) return false;
    if (!Array.isArray(entry.allowed_actions) || !entry.allowed_actions.length || entry.allowed_actions.some((item) => !/^[a-z0-9_-]{1,80}$/.test(String(item || '').trim()))) return false;
    const publicKeys = entry.public_keys;
    if (!publicKeys || typeof publicKeys !== 'object' || Array.isArray(publicKeys)) return false;
    if (signatureNames.some((name) => !String(publicKeys[name] || '').trim())) return false;
  }
  return true;
}

function diracS2SEnvRevocationStatusV207(serverId, keyVersion) {
  const cleanServerId = diracS2SIdV206(serverId);
  const cleanKeyVersion = diracS2SKeyVersionV206(keyVersion);
  if (!cleanServerId || !cleanKeyVersion) return { ok: false, unavailable: true, reason: 'env_revocation_identity_invalid', revoked: false };
  const parsed = diracS2SEnvJsonObjectV207('DIRAC_S2S_REVOKED_KEYS_JSON', false);
  if (!parsed.ok) return { ok: false, unavailable: true, reason: 'env_revocation_json_invalid', revoked: false };
  const configured = parsed.value[cleanServerId];
  if (configured === undefined) return { ok: true, revoked: false, source: 'environment' };
  if (!Array.isArray(configured) || configured.some((item) => !diracS2SKeyVersionV206(item))) {
    return { ok: false, unavailable: true, reason: 'env_revocation_entry_invalid', revoked: false };
  }
  return { ok: true, revoked: configured.includes(cleanKeyVersion), source: 'environment' };
}


function diracS2SIdV206(value) {
  const clean = String(value || '').trim().toLowerCase();
  return /^[a-z0-9](?:[a-z0-9_.-]{0,78}[a-z0-9])?$/.test(clean) ? clean : '';
}

function diracS2SKeyVersionV206(value) {
  const clean = String(value || '').trim();
  return /^[A-Za-z0-9_.-]{1,80}$/.test(clean) ? clean : '';
}

function diracS2SHeaderV206(req, name) {
  const value = req && req.headers && req.headers[String(name || '').toLowerCase()];
  return Array.isArray(value) ? String(value[0] || '').trim() : String(value || '').trim();
}

function diracS2SPathV206(input) {
  try {
    if (input instanceof URL) return input.pathname.replace(/\/+$/, '') || '/';
    return new URL(String(input && input.url || input || '/api/health'), 'https://dirac.invalid').pathname.replace(/\/+$/, '') || '/';
  } catch (_) { return '/api/health'; }
}

function diracS2SBodyHashV206(body) {
  return crypto.createHash('sha512').update(diracS2SStableJsonV206(body && typeof body === 'object' ? body : {}), 'utf8').digest('hex');
}

function diracS2SCanonicalV206(meta) {
  return Buffer.from([
    DIRAC_S2S_VERSION_V206,
    String(meta.networkId || ''),
    String(meta.serverId || ''),
    String(meta.targetServerId || ''),
    String(meta.keyVersion || ''),
    String(meta.method || '').toUpperCase(),
    String(meta.path || ''),
    String(meta.action || ''),
    String(meta.timestamp || ''),
    String(meta.nonce || ''),
    String(meta.requestId || ''),
    String(meta.bodyHash || '')
  ].join('\n'), 'utf8');
}

function diracS2SKeyObjectV206(raw, kind, expectedType) {
  const clean = String(raw || '').trim();
  if (!clean) throw new Error('DIRAC_S2S_KEY_MISSING_' + kind);
  const material = clean.includes('-----BEGIN') ? clean.replace(/\\n/g, '\n') : Buffer.from(clean, 'base64');
  const key = kind === 'private' ? crypto.createPrivateKey(material) : crypto.createPublicKey(material);
  if (expectedType && key.asymmetricKeyType !== expectedType) throw new Error('DIRAC_S2S_KEY_TYPE_INVALID_' + expectedType);
  if (expectedType === 'rsa') {
    const modulusLength = Number(key && key.asymmetricKeyDetails && key.asymmetricKeyDetails.modulusLength || 0);
    if (!Number.isSafeInteger(modulusLength) || modulusLength < 3072) {
      throw new Error('DIRAC_S2S_RSA_MODULUS_TOO_SMALL');
    }
  }
  return key;
}

function diracS2SDecodeSignatureV210(raw) {
  const encoded = String(raw || '');
  if (!/^[A-Za-z0-9_-]{40,22000}$/.test(encoded)) throw new Error('DIRAC_S2S_SIGNATURE_FORMAT_INVALID');
  const signature = Buffer.from(encoded, 'base64url');
  if (!signature.length || signature.toString('base64url') !== encoded) {
    signature.fill(0);
    throw new Error('DIRAC_S2S_SIGNATURE_ENCODING_NON_CANONICAL');
  }
  return signature;
}

function diracS2SSignatureSpecsV206() {
  return Object.freeze([
    Object.freeze({ index: 1, name: 'ed25519', type: 'ed25519', privateEnv: 'DIRAC_S2S_ED25519_PRIVATE_KEY_PEM', sign: (message, key) => crypto.sign(null, message, key), verify: (message, key, signature) => crypto.verify(null, message, key, signature) }),
    Object.freeze({ index: 2, name: 'ed448', type: 'ed448', privateEnv: 'DIRAC_S2S_ED448_PRIVATE_KEY_PEM', sign: (message, key) => crypto.sign(null, message, key), verify: (message, key, signature) => crypto.verify(null, message, key, signature) }),
    Object.freeze({ index: 3, name: 'ecdsa_p256', type: 'ec', privateEnv: 'DIRAC_S2S_ECDSA_P256_PRIVATE_KEY_PEM', curve: 'prime256v1', sign: (message, key) => crypto.sign('sha256', message, { key, dsaEncoding: 'ieee-p1363' }), verify: (message, key, signature) => crypto.verify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, signature) }),
    Object.freeze({ index: 4, name: 'ecdsa_p384', type: 'ec', privateEnv: 'DIRAC_S2S_ECDSA_P384_PRIVATE_KEY_PEM', curve: 'secp384r1', sign: (message, key) => crypto.sign('sha384', message, { key, dsaEncoding: 'ieee-p1363' }), verify: (message, key, signature) => crypto.verify('sha384', message, { key, dsaEncoding: 'ieee-p1363' }, signature) }),
    Object.freeze({ index: 5, name: 'ecdsa_p521', type: 'ec', privateEnv: 'DIRAC_S2S_ECDSA_P521_PRIVATE_KEY_PEM', curve: 'secp521r1', sign: (message, key) => crypto.sign('sha512', message, { key, dsaEncoding: 'ieee-p1363' }), verify: (message, key, signature) => crypto.verify('sha512', message, { key, dsaEncoding: 'ieee-p1363' }, signature) }),
    Object.freeze({ index: 6, name: 'rsa_pss_sha512', type: 'rsa', privateEnv: 'DIRAC_S2S_RSA_PSS_PRIVATE_KEY_PEM', sign: (message, key) => crypto.sign('sha512', message, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }), verify: (message, key, signature) => crypto.verify('sha512', message, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }, signature) }),
    Object.freeze({ index: 7, name: 'ml_dsa_87', type: 'ml-dsa-87', privateEnv: 'DIRAC_S2S_MLDSA87_PRIVATE_KEY_PEM', sign: (message, key) => crypto.sign(null, message, { key, context: DIRAC_S2S_MLDSA_CONTEXT_V206 }), verify: (message, key, signature) => crypto.verify(null, message, { key, context: DIRAC_S2S_MLDSA_CONTEXT_V206 }, signature) })
  ]);
}

function diracS2SAssertEcCurveV206(key, expectedCurve) {
  if (!expectedCurve) return true;
  const curve = String(key && key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve || '').toLowerCase();
  const accepted = expectedCurve === 'prime256v1' ? new Set(['prime256v1', 'secp256r1']) : new Set([expectedCurve]);
  if (!accepted.has(curve)) throw new Error('DIRAC_S2S_EC_CURVE_INVALID_' + expectedCurve);
  return true;
}

function diracS2SAssertConfigurationV206() {
  const serverId = diracS2SIdV206(diracS2STextV206('DIRAC_S2S_SERVER_ID'));
  const keyVersion = diracS2SKeyVersionV206(diracS2STextV206('DIRAC_S2S_KEY_VERSION'));
  const networkId = diracS2STextV206('DIRAC_S2S_NETWORK_ID');
  if (!serverId || !keyVersion) throw new Error('DIRAC_S2S_CONFIGURATION_IDENTITY_INVALID');
  if (!/^[A-Za-z0-9_-]{43,256}$/.test(networkId)) throw new Error('DIRAC_S2S_NETWORK_ID_INVALID');
  if (DIRAC_S2S_SECURITY_TABLE !== 'dirac_s2s_security') throw new Error('DIRAC_S2S_SECURITY_TABLE_REQUIRED');
  readDiracSupabaseCredentials('security');
  const revoked = diracS2SEnvJsonObjectV207('DIRAC_S2S_REVOKED_KEYS_JSON', false);
  if (!revoked.ok) throw new Error('DIRAC_S2S_REVOKED_KEYS_JSON_INVALID');
  for (const [revokedServerId, versions] of Object.entries(revoked.value)) {
    if (diracS2SIdV206(revokedServerId) !== revokedServerId
        || !Array.isArray(versions)
        || versions.some((item) => !diracS2SKeyVersionV206(item))) {
      throw new Error('DIRAC_S2S_REVOKED_KEYS_JSON_INVALID');
    }
  }
  for (const spec of diracS2SSignatureSpecsV206()) {
    const key = diracS2SKeyObjectV206(diracS2STextV206(spec.privateEnv), 'private', spec.type);
    diracS2SAssertEcCurveV206(key, spec.curve);
  }
  return true;
}

async function diracS2SRegistryEntryV206(serverId) {
  const cleanServerId = diracS2SIdV206(serverId);
  if (!cleanServerId) return { ok: true, found: false, entry: null, source: 'security_database_registry' };
  if (typeof readPersistentSecurityJsonStrictV194 !== 'function') {
    return { ok: false, found: false, entry: null, unavailable: true, source: 'security_database_registry' };
  }
  const lookup = await readPersistentSecurityJsonStrictV194('s2s-server-registry:' + cleanServerId);
  if (!lookup || lookup.ok !== true) {
    return { ok: false, found: false, entry: null, unavailable: true, source: 'security_database_registry' };
  }
  if (!lookup.found) return { ok: true, found: false, entry: null, source: 'security_database_registry' };
  const record = lookup.record && typeof lookup.record === 'object' && !Array.isArray(lookup.record) ? lookup.record : null;
  const entry = record && record.entry && typeof record.entry === 'object' && !Array.isArray(record.entry)
    ? record.entry
    : record;
  if (!entry || !diracS2SValidateEnvRegistryV207({ [cleanServerId]: entry })) {
    return { ok: false, found: false, entry: null, unavailable: true, source: 'security_database_registry' };
  }
  return { ok: true, found: true, entry, source: 'security_database_registry' };
}

function diracS2SSignHeadersV206(input) {
  const target = input && input.target instanceof URL ? input.target : new URL(String(input && input.target || ''));
  const action = String(input && input.action || '').trim().toLowerCase();
  const body = input && input.body && typeof input.body === 'object' ? input.body : {};
  const serverId = diracS2SIdV206(diracS2STextV206('DIRAC_S2S_SERVER_ID'));
  const targetServerId = diracS2SIdV206(input && input.targetServerId || '');
  const keyVersion = diracS2SKeyVersionV206(diracS2STextV206('DIRAC_S2S_KEY_VERSION'));
  const networkId = diracS2STextV206('DIRAC_S2S_NETWORK_ID');
  if (!serverId || !targetServerId || !keyVersion || !action || !/^[A-Za-z0-9_-]{43,256}$/.test(networkId)) throw new Error('DIRAC_S2S_SIGNING_IDENTITY_INVALID');
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(32).toString('base64url');
  const requestId = crypto.randomBytes(24).toString('base64url');
  const bodyHash = diracS2SBodyHashV206(body);
  const message = diracS2SCanonicalV206({ networkId, serverId, targetServerId, keyVersion, method: 'POST', path: diracS2SPathV206(target), action, timestamp, nonce, requestId, bodyHash });
  const headers = {
    'X-Dirac-S2S-Version': DIRAC_S2S_VERSION_V206,
    'X-Dirac-S2S-Policy': DIRAC_S2S_POLICY_V206,
    'X-Dirac-Server-Id': serverId,
    'X-Dirac-Target-Server-Id': targetServerId,
    'X-Dirac-Key-Version': keyVersion,
    'X-Dirac-Timestamp': timestamp,
    'X-Dirac-Nonce': nonce,
    'X-Dirac-Request-Id': requestId,
    'X-Dirac-Body-SHA512': bodyHash
  };
  headers['X-Dirac-Network-Id'] = networkId;
  try {
    for (const spec of diracS2SSignatureSpecsV206()) {
      const key = diracS2SKeyObjectV206(diracS2STextV206(spec.privateEnv), 'private', spec.type);
      diracS2SAssertEcCurveV206(key, spec.curve);
      const signature = spec.sign(message, key);
      headers['X-Dirac-Signature-' + spec.index] = Buffer.from(signature).toString('base64url');
      if (Buffer.isBuffer(signature)) signature.fill(0);
    }
    return headers;
  } finally { message.fill(0); }
}

function diracS2SEvidenceV206(ctx, verification, failureCode) {
  const evidence = {
    version: DIRAC_S2S_VERSION_V206,
    incident_id: 'S2S-' + crypto.randomBytes(18).toString('base64url'),
    reporter_server_id: diracS2SIdV206(diracS2STextV206('DIRAC_S2S_SERVER_ID')),
    reporter_key_version: diracS2SKeyVersionV206(diracS2STextV206('DIRAC_S2S_KEY_VERSION')),
    offender_server_id: diracS2SIdV206(verification && verification.serverId),
    offender_key_version: diracS2SKeyVersionV206(verification && verification.keyVersion),
    target_server_id: diracS2SIdV206(verification && verification.targetServerId),
    original_request_id: String(verification && verification.requestId || '').slice(0, 160),
    original_nonce: String(verification && verification.nonce || '').slice(0, 160),
    original_body_sha512: String(verification && verification.bodyHash || '').slice(0, 128),
    failure_code: String(failureCode || verification && verification.reason || 'seven_signature_invalid').slice(0, 120),
    failed_signature_indexes: Array.isArray(verification && verification.failures) ? verification.failures.slice(0, 7).map(Number) : [],
    attributed_valid_signature_count: Math.max(0, Math.min(7, Number(verification && verification.validCount || 0))),
    detected_at_ms: Date.now(),
    action: String(ctx && ctx.action || '').slice(0, 80),
    method: String(ctx && ctx.method || '').slice(0, 12),
    path: diracS2SPathV206(ctx && ctx.req)
  };
  evidence.evidence_hash = crypto.createHash('sha512').update(diracS2SStableJsonV206(evidence), 'utf8').digest('hex');
  return evidence;
}

function diracS2SServer1TargetV206() {
  const raw = diracS2STextV206('DIRAC_RECOVERY_SERVER1_URL');
  if (!raw) return null;
  try {
    const target = new URL(raw);
    if (target.protocol !== 'https:' || target.username || target.password || target.hash) return null;
    target.search = '';
    target.searchParams.set('action', 'security_report');
    return target;
  } catch (_) { return null; }
}

async function diracS2SSendSecurityReportV206(payload) {
  const target = diracS2SServer1TargetV206();
  const targetServerId = diracS2SIdV206(diracS2STextV206('DIRAC_RECOVERY_SERVER1_SERVER_ID') || 'vercel1-main');
  if (!target || !targetServerId) return { ok: false, unavailable: true };
  let signedHeaders;
  try { signedHeaders = diracS2SSignHeadersV206({ target, action: 'security_report', body: payload, targetServerId }); }
  catch (_) { return { ok: false, unavailable: true }; }
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), 12_000) : null;
  try {
    const response = await fetch(target.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', ...signedHeaders },
      body: JSON.stringify(payload),
      redirect: 'error',
      signal: controller ? controller.signal : undefined
    });
    const text = await diracRecoveryReadResponseLimitedV201(response, 32 * 1024).catch(() => '');
    if (Buffer.byteLength(text, 'utf8') > 32 * 1024) return { ok: false, unavailable: true };
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) { data = {}; }
    return { ok: response.ok && data && data.ok === true, status: response.status, data };
  } catch (_) {
    return { ok: false, unavailable: true };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function diracS2SQueueAndReportFailureV206(ctx, verification, failureCode) {
  const evidence = diracS2SEvidenceV206(ctx, verification, failureCode);
  if (evidence.attributed_valid_signature_count < 1 || !evidence.offender_server_id || !evidence.offender_key_version) return { ok: false, attributed: false, evidence };
  const queueKey = 's2s-report-queue:' + evidence.incident_id;
  const pending = { type: 'dirac_s2s_report_queue_v206', state: 'pending', event: 'signature_failure', evidence, created_at: new Date().toISOString() };
  const persisted = typeof writePersistentSecurityJsonRequiredV194 === 'function'
    ? await writePersistentSecurityJsonRequiredV194(queueKey, pending, Date.now() + DIRAC_RECOVERY_PERMANENT_BAN_MS_V201, Math.ceil(DIRAC_RECOVERY_PERMANENT_BAN_MS_V201 / 1000))
    : false;
  const sent = await diracS2SSendSecurityReportV206({ action: 'security_report', event: 'signature_failure', evidence });
  if (sent.ok && persisted) {
    await writePersistentSecurityJsonRequiredV194(queueKey, { ...pending, state: 'delivered', delivered_at: new Date().toISOString() }, 0, 24 * 60 * 60).catch(() => false);
  }
  return { ok: sent.ok, attributed: true, queued: persisted, evidence };
}

async function diracS2SFlushPendingReportsV206() {
  if (DIRAC_S2S_SECURITY_TABLE !== 'dirac_s2s_security' || typeof supabaseFetch !== 'function') return false;
  try {
    const path = '/rest/v1/' + encodeURIComponent(DIRAC_S2S_SECURITY_TABLE)
      + '?select=security_key,record_json&security_key=like.' + encodeURIComponent('s2s-report-queue:*')
      + '&limit=10';
    const result = await supabaseFetch(path, { method: 'GET', auth: 'service' });
    if (!result.ok || !Array.isArray(result.data)) return false;
    for (const row of result.data) {
      const record = row && row.record_json && typeof row.record_json === 'object' ? row.record_json : null;
      if (!record || record.state !== 'pending' || !record.evidence) continue;
      const sent = await diracS2SSendSecurityReportV206({ action: 'security_report', event: 'signature_failure', evidence: record.evidence });
      if (sent.ok) {
        await writePersistentSecurityJsonRequiredV194(String(row.security_key || ''), { ...record, state: 'delivered', delivered_at: new Date().toISOString() }, 0, 24 * 60 * 60).catch(() => false);
      }
    }
    return true;
  } catch (_) { return false; }
}

async function diracS2SCheckCentralRevocationV206(serverId, keyVersion) {
  const envStatus = diracS2SEnvRevocationStatusV207(serverId, keyVersion);
  if (!envStatus.ok) return { ok: false, unavailable: true };
  if (envStatus.revoked === true) return { ok: true, revoked: true, source: 'environment' };
  const result = await diracS2SSendSecurityReportV206({
    action: 'security_report',
    event: 'revocation_check',
    offender_server_id: serverId,
    offender_key_version: keyVersion
  });
  if (!result.ok || !result.data || result.data.event !== 'revocation_check') return { ok: false, unavailable: true };
  return { ok: true, revoked: result.data.revoked === true, source: 'server1' };
}

async function diracS2SVerifyInboundV206(req, ctx, body) {
  const serverId = diracS2SIdV206(diracS2SHeaderV206(req, 'x-dirac-server-id'));
  const targetServerId = diracS2SIdV206(diracS2SHeaderV206(req, 'x-dirac-target-server-id'));
  const localServerId = diracS2SIdV206(diracS2STextV206('DIRAC_S2S_SERVER_ID'));
  const suppliedNetworkId = diracS2SHeaderV206(req, 'x-dirac-network-id');
  const expectedNetworkId = diracS2STextV206('DIRAC_S2S_NETWORK_ID');
  const keyVersion = diracS2SKeyVersionV206(diracS2SHeaderV206(req, 'x-dirac-key-version'));
  const timestampText = diracS2SHeaderV206(req, 'x-dirac-timestamp');
  const timestamp = Number(timestampText);
  const nonce = diracS2SHeaderV206(req, 'x-dirac-nonce');
  const requestId = diracS2SHeaderV206(req, 'x-dirac-request-id');
  const suppliedBodyHash = diracS2SHeaderV206(req, 'x-dirac-body-sha512').toLowerCase();
  const base = { ok: false, serverId, targetServerId, keyVersion, timestamp: timestampText, nonce, requestId, bodyHash: suppliedBodyHash, failures: [], validCount: 0 };
  if (diracS2SHeaderV206(req, 'x-dirac-s2s-version') !== DIRAC_S2S_VERSION_V206 || diracS2SHeaderV206(req, 'x-dirac-s2s-policy') !== DIRAC_S2S_POLICY_V206) return { ...base, reason: 's2s_version_or_policy_invalid' };
  if (!/^[A-Za-z0-9_-]{43,256}$/.test(expectedNetworkId)
      || !/^[A-Za-z0-9_-]{43,256}$/.test(suppliedNetworkId)
      || !(typeof safeEqual === 'function' ? safeEqual(suppliedNetworkId, expectedNetworkId) : suppliedNetworkId === expectedNetworkId)) return { ...base, reason: 's2s_network_id_invalid' };
  if (!serverId || !targetServerId || !localServerId || targetServerId !== localServerId || !keyVersion) return { ...base, reason: 's2s_identity_binding_invalid' };
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > DIRAC_S2S_MAX_CLOCK_SKEW_MS_V206) return { ...base, reason: 's2s_timestamp_invalid' };
  if (!/^[A-Za-z0-9_-]{32,160}$/.test(nonce) || !/^[A-Za-z0-9_-]{24,160}$/.test(requestId) || !/^[a-f0-9]{128}$/.test(suppliedBodyHash)) return { ...base, reason: 's2s_request_binding_invalid' };
  const actualBodyHash = diracS2SBodyHashV206(body || {});
  if (!(typeof safeEqual === 'function' ? safeEqual(suppliedBodyHash, actualBodyHash) : suppliedBodyHash === actualBodyHash)) return { ...base, reason: 's2s_body_hash_invalid' };
  const registryLookup = await diracS2SRegistryEntryV206(serverId);
  if (!registryLookup || registryLookup.ok !== true) return { ...base, reason: 's2s_registry_store_unavailable', unavailable: true };
  const entry = registryLookup.found ? registryLookup.entry : null;
  if (!entry || String(entry.status || '').toLowerCase() !== 'active' || diracS2SKeyVersionV206(entry.key_version) !== keyVersion) return { ...base, reason: 's2s_registry_or_key_version_invalid' };
  const allowedTargets = Array.isArray(entry.allowed_targets) ? entry.allowed_targets.map(diracS2SIdV206) : [];
  const allowedActions = Array.isArray(entry.allowed_actions) ? entry.allowed_actions.map((item) => String(item || '').trim().toLowerCase()) : [];
  if (!allowedTargets.includes(localServerId) || !allowedActions.includes(String(ctx && ctx.action || '').toLowerCase())) return { ...base, reason: 's2s_scope_not_allowed' };
  const publicKeys = entry.public_keys && typeof entry.public_keys === 'object' ? entry.public_keys : {};
  const message = diracS2SCanonicalV206({ networkId: expectedNetworkId, serverId, targetServerId, keyVersion, method: ctx.method, path: diracS2SPathV206(req), action: ctx.action, timestamp: timestampText, nonce, requestId, bodyHash: suppliedBodyHash });
  let validCount = 0;
  const failures = [];
  try {
    for (const spec of diracS2SSignatureSpecsV206()) {
      let valid = false;
      let signature = null;
      try {
        const rawSignature = diracS2SHeaderV206(req, 'x-dirac-signature-' + spec.index);
        signature = diracS2SDecodeSignatureV210(rawSignature);
        const key = diracS2SKeyObjectV206(String(publicKeys[spec.name] || ''), 'public', spec.type);
        diracS2SAssertEcCurveV206(key, spec.curve);
        valid = spec.verify(message, key, signature) === true;
      } catch (_) { valid = false; }
      finally { if (Buffer.isBuffer(signature)) signature.fill(0); }
      if (valid) validCount += 1;
      else failures.push(spec.index);
    }
  } finally { message.fill(0); }
  const verification = { ...base, validCount, failures, reason: failures.length ? 's2s_seven_signature_invalid' : '', ok: failures.length === 0 };
  if (!verification.ok) return verification;
  const central = await diracS2SCheckCentralRevocationV206(serverId, keyVersion);
  if (!central.ok) return { ...verification, ok: false, unavailable: true, reason: 's2s_central_revocation_unavailable' };
  if (central.revoked) return { ...verification, ok: false, revoked: true, reason: 's2s_key_revoked' };
  if (typeof claimPersistentSecurityKeyOnceV194 !== 'function') return { ...verification, ok: false, unavailable: true, reason: 's2s_replay_store_unavailable' };
  const replayKey = 's2s-replay:' + serverId + ':' + keyVersion + ':' + requestId + ':' + nonce;
  const claimed = await claimPersistentSecurityKeyOnceV194(replayKey, { type: 'dirac_s2s_replay_claim_v206', server_id: serverId, key_version: keyVersion, request_id: requestId, nonce, created_at: new Date().toISOString() }, 180);
  if (!claimed) return { ...verification, ok: false, reason: 's2s_replay_detected' };
  await diracS2SFlushPendingReportsV206().catch(() => false);
  return verification;
}

async function diracS2SLegacyRejectV206(req, res, ctx, verification, reason, status, identityKey) {
  await diracS2SQueueAndReportFailureV206(ctx, verification, reason).catch(() => null);
  return diracRecoveryGuardRejectV201(req, res, ctx.action, reason, status, identityKey);
}

if (process.env.NODE_ENV === 'production') diracS2SAssertConfigurationV206();


async function diracRecoveryWorkerGuardV201(req, res, ctx, body, identityKey) {
  if (req.method !== 'POST') return diracRecoveryGuardRejectV201(req, res, ctx.action, 'worker_method_invalid', 405, identityKey);
  if (diracRecoveryHeaderV201(req, 'origin')) return diracRecoveryGuardRejectV201(req, res, ctx.action, 'worker_origin_forbidden', 403, identityKey);
  const sevenSignatureVerification = await diracS2SVerifyInboundV206(req, ctx, body);
  ctx.__diracS2SSevenSignatureVerificationV206 = sevenSignatureVerification;
  if (!sevenSignatureVerification.ok) {
    await diracS2SQueueAndReportFailureV206(ctx, sevenSignatureVerification, sevenSignatureVerification.reason).catch(() => null);
    return diracRecoveryGuardRejectV201(req, res, ctx.action, sevenSignatureVerification.reason, sevenSignatureVerification.unavailable ? 503 : 403, identityKey);
  }
  ctx.guardPassport.seven_signatures_checked = true;
  const caller = diracRecoveryHeaderV201(req, 'x-dirac-worker-caller');
  const allowedCaller = customerSecurityRecoveryWorkerAllowedCaller();
  if (!caller || !allowedCaller || !safeEqual(caller, allowedCaller)) {
    return diracS2SLegacyRejectV206(req, res, ctx, sevenSignatureVerification, 'worker_caller_invalid', 403, identityKey);
  }
  const timestampText = diracRecoveryHeaderV201(req, 'x-dirac-worker-timestamp');
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0 || Math.abs(Date.now() - timestamp) > customerSecurityRecoveryWorkerClockSkewMs()) {
    return diracS2SLegacyRejectV206(req, res, ctx, sevenSignatureVerification, 'worker_timestamp_invalid', 403, identityKey);
  }
  const signature = diracRecoveryHeaderV201(req, 'x-dirac-worker-signature');
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) {
    return diracS2SLegacyRejectV206(req, res, ctx, sevenSignatureVerification, 'worker_signature_format_invalid', 403, identityKey);
  }
  const outerKeys = Object.keys(body).sort();
  const expectedKeys = [
    'action', 'aead_nonce_b64url', 'auth_tag_b64url', 'caller_id', 'ciphertext_b64url',
    'expires_at_ms', 'hkdf_salt_b64url', 'mlkem_ciphertext_b64url', 'nonce',
    'receiver_key_fingerprint', 'sent_at_ms', 'transport_suite', 'transport_version',
    'worker_action', 'x25519_ephemeral_public_key_b64url'
  ].sort();
  if (outerKeys.length !== expectedKeys.length || outerKeys.some((key, index) => key !== expectedKeys[index])) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'worker_envelope_fields_invalid', 403, identityKey);
  }
  if (body.action !== DIRAC_RECOVERY_WORKER_ACTION
      || body.caller_id !== caller
      || ![DIRAC_RECOVERY_WORKER_TASK_GENERATE, DIRAC_RECOVERY_WORKER_TASK_VERIFY, DIRAC_RECOVERY_WORKER_TASK_FINALIZE].includes(String(body.worker_action || ''))
      || !/^[A-Za-z0-9_-]{32,120}$/.test(String(body.nonce || ''))) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'worker_envelope_binding_invalid', 403, identityKey);
  }
  const canonical = customerSecurityLostPasskeyCanonical(body);
  const expected = customerSecurityRecoveryWorkerSign(caller, timestampText, canonical);
  if (!expected || !safeEqual(signature, expected)) {
    return diracS2SLegacyRejectV206(req, res, ctx, sevenSignatureVerification, 'worker_hmac_invalid', 403, identityKey);
  }
  let transportContext;
  try {
    transportContext = customerSecurityRecoveryWorkerOpenV190(body, caller, timestampText);
    ctx.body = transportContext.body;
    req.__diracCentralParsedBodyV146 = transportContext.body;
    req.__diracRecoveryWorkerTransportVerifiedV190 = true;
    req.__diracRecoveryWorkerVerified = true;
    ctx.__diracRecoveryWorkerResponseKeyV190 = transportContext.responseKey;
    customerSecurityRecoveryWorkerInstallResponseGuardV190(req, ctx, transportContext);
  } catch (error) {
    if (transportContext && transportContext.responseKey) transportContext.responseKey.fill(0);
    return diracRecoveryGuardRejectV201(req, res, ctx.action, String(error && error.code || 'worker_transport_invalid'), 403, identityKey);
  }

  // The transport is authenticated before the replay claim so every response to
  // a valid encrypted Server 1 envelope, including a replay rejection, remains
  // encrypted with the request-bound response key. The replay guard itself is
  // still mandatory and executes before any recovery business handler.
  const persistentNonce = await diracCentralRecoveryWorkerClaimNonceV183(
    caller,
    body.nonce,
    Date.now() + customerSecurityRecoveryWorkerClockSkewMs() + 60000
  );
  if (!persistentNonce || persistentNonce.ok !== true) {
    return diracRecoveryGuardRejectV201(
      req,
      res,
      ctx.action,
      String(persistentNonce && persistentNonce.reason || 'worker_nonce_replay'),
      409,
      identityKey
    );
  }
  return null;
}

async function diracRecoveryBrowserGuardV201(req, res, ctx, body, identityKey) {
  const method = String(req && req.method || '').toUpperCase();
  const origin = diracRecoveryHeaderV201(req, 'origin');
  const secFetchSite = diracRecoveryHeaderV201(req, 'sec-fetch-site').toLowerCase();
  const forwardedHost = diracRecoveryHeaderV201(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase();
  const host = (forwardedHost || diracRecoveryHeaderV201(req, 'host').split(',')[0].trim()).toLowerCase();
  const forwardedProto = diracRecoveryHeaderV201(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();

  const exactBrowserOrigin = origin === DIRAC_RECOVERY_BROWSER_ORIGIN_V201;
  const exactBrowserTarget = host === 'secure.diracgroup.store'
    && (process.env.NODE_ENV === 'production' ? forwardedProto === 'https' : (!forwardedProto || forwardedProto === 'https'));
  const exactHeadTarget = method !== 'HEAD'
    || (secFetchSite === 'same-origin' && exactBrowserTarget);
  const exactSameOriginHead = method === 'HEAD'
    && !origin
    && exactHeadTarget;

  if ((!exactBrowserOrigin && !exactSameOriginHead) || !exactHeadTarget || !exactBrowserTarget) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'browser_origin_invalid', 403, identityKey);
  }
  if (secFetchSite && !['same-origin', 'same-site'].includes(secFetchSite)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'browser_fetch_site_invalid', 403, identityKey);
  }
  if (method === 'HEAD') return null;
  if (method !== 'POST') return diracRecoveryGuardRejectV201(req, res, ctx.action, 'browser_method_invalid', 405, identityKey);
  const contentType = diracRecoveryHeaderV201(req, 'content-type').toLowerCase();
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'browser_content_type_invalid', 415, identityKey);
  }
  const csrf = diracV138CsrfForceVerify(req, ctx.action);
  if (!csrf || csrf.ok !== true) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, String(csrf && csrf.code || 'csrf_guard_failed'), Number(csrf && csrf.status || 403), identityKey);
  }
  const pageNonce = diracRecoveryPageNonceVerifyV203(req, ctx.action);
  if (!pageNonce || pageNonce.ok !== true) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, String(pageNonce && pageNonce.code || 'recovery_page_nonce_invalid'), Number(pageNonce && pageNonce.status || 403), identityKey);
  }
  try {
    const expectedHpkeKeyId = String(process.env.DIRAC_RECOVERY_HPKE_KEY_ID || '').trim();
    const expectedMlkemKeyId = String(process.env.DIRAC_RECOVERY_MLKEM1024_KEY_ID || '').trim();
    if (!expectedHpkeKeyId || !expectedMlkemKeyId) throw new Error('RECOVERY_KEY_ID_UNCONFIGURED');
    DIRAC_RECOVERY_CRYPTO_V2.validateEnvelope(body, expectedHpkeKeyId, expectedMlkemKeyId);
    if (String(body.action || '') !== DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159) throw new Error('RECOVERY_ACTION_INVALID');
  } catch (error) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, String(error && error.code || error && error.message || 'browser_envelope_invalid'), 403, identityKey);
  }
  return null;
}

async function diracRecoveryPreflightGuardV204(req, res, ctx, identityKey) {
  if (req.method !== 'OPTIONS') return diracRecoveryGuardRejectV201(req, res, ctx.action, 'preflight_method_invalid', 405, identityKey);
  if (![DIRAC_RECOVERY_HPKE_VERIFY_ACTION_V159, DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165].includes(ctx.action)) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'preflight_action_invalid', 403, identityKey);
  }
  const origin = diracRecoveryHeaderV201(req, 'origin');
  const forwardedHost = diracRecoveryHeaderV201(req, 'x-forwarded-host').split(',')[0].trim().toLowerCase();
  const host = (forwardedHost || diracRecoveryHeaderV201(req, 'host').split(',')[0].trim()).toLowerCase();
  const forwardedProto = diracRecoveryHeaderV201(req, 'x-forwarded-proto').split(',')[0].trim().toLowerCase();
  const secFetchSite = diracRecoveryHeaderV201(req, 'sec-fetch-site').toLowerCase();
  if (origin !== DIRAC_RECOVERY_BROWSER_ORIGIN_V201
      || host !== 'secure.diracgroup.store'
      || (process.env.NODE_ENV === 'production' ? forwardedProto !== 'https' : (forwardedProto && forwardedProto !== 'https'))
      || (secFetchSite && !['same-origin', 'same-site'].includes(secFetchSite))) {
    return diracRecoveryGuardRejectV201(req, res, ctx.action, 'preflight_origin_invalid', 403, identityKey);
  }
  return null;
}

module.exports = async function diracRecoveryOnlyServer2HandlerV201(req, res) {
  if (DIRAC_CENTRAL_ASYNC_CONTEXT_V149
      && typeof DIRAC_CENTRAL_ASYNC_CONTEXT_V149.run === 'function'
      && typeof DIRAC_CENTRAL_ASYNC_CONTEXT_V149.getStore === 'function') {
    const activeStore = DIRAC_CENTRAL_ASYNC_CONTEXT_V149.getStore();
    if (!activeStore || activeStore.__diracRecoveryRequestV210 !== true) {
      return DIRAC_CENTRAL_ASYNC_CONTEXT_V149.run(
        { ctx: null, __diracRecoveryRequestV210: true },
        () => module.exports(req, res)
      );
    }
  }
  const rawAction = String(req && req.query && req.query.action || '');
  const action = rawAction.trim().toLowerCase();
  diracRecoveryApplyHeadersV201(req, res, action);

  const isRecoveryWorkerAction = action === DIRAC_RECOVERY_WORKER_ACTION;
  let identity;
  if (isRecoveryWorkerAction) {
    // For the authenticated Server 1 channel, defer only the ban lookup until
    // the hybrid envelope has been authenticated and the encrypted response
    // guard is installed. The persistent-ban decision remains mandatory and
    // still runs before the business handler.
    try { identity = { ok: true, key: diracRecoveryIdentityV201(req, action), deferredWorkerBan: true }; }
    catch (_) { return res.status(503).json({ ok: false, code: 'RECOVERY_GUARD_UNAVAILABLE', message: 'Sistem keamanan belum tersedia.' }); }
  } else {
    try { identity = await diracRecoveryCheckBanV201(req, /^[a-z0-9_-]{1,80}$/.test(action) ? action : 'invalid_action'); }
    catch (_) { return res.status(503).json({ ok: false, code: 'RECOVERY_GUARD_UNAVAILABLE', message: 'Sistem keamanan belum tersedia.' }); }
    if (!identity.ok) {
      return res.status(identity.persistenceUnavailable ? 503 : 403).json({
        ok: false,
        code: identity.persistenceUnavailable ? 'RECOVERY_GUARD_PERSISTENCE_UNAVAILABLE' : 'RECOVERY_PERSISTENT_BAN_ACTIVE',
        message: 'Permintaan ditolak oleh sistem keamanan.'
      });
    }
  }
  if (!rawAction || rawAction !== action || !/^[a-z0-9_-]{1,80}$/.test(action)) {
    return diracRecoveryGuardRejectV201(req, res, 'invalid_action', 'action_format_invalid', 403, identity.key);
  }
  if (!DIRAC_CENTRAL_ACTIVE_ACTIONS_V146.has(action)) {
    return diracRecoveryGuardRejectV201(req, res, action, 'action_not_allowlisted', 403, identity.key);
  }
  if (!DIRAC_CENTRAL_ENV_VERCEL2_ONLY_ACTIONS_V174.has(action)) {
    return diracRecoveryGuardRejectV201(req, res, action, 'action_not_enabled_by_environment', 403, identity.key);
  }

  let deploymentRoleChecked = false;
  let environmentPartitionChecked = false;
  try {
    diracRecoveryAssertServer2EnvironmentV201();
    deploymentRoleChecked = true;
    environmentPartitionChecked = true;
  } catch (error) {
    return diracRecoveryGuardRejectV201(req, res, action, String(error && error.message || 'server2_environment_invalid'), 503, identity.key);
  }

  let body = {};
  if (req.method !== 'HEAD' && req.method !== 'OPTIONS') {
    try { body = await readLimitedJsonBody(req, action === DIRAC_RECOVERY_WORKER_ACTION ? customerSecurityRecoveryWorkerMaxBodyBytes() : 64 * 1024); }
    catch (error) { return diracRecoveryGuardRejectV201(req, res, action, String(error && error.message || 'body_invalid'), error && error.statusCode || 400, identity.key); }
  }
  const ctx = {
    req,
    res,
    action,
    method: String(req.method || 'GET').toUpperCase(),
    classification: action === DIRAC_RECOVERY_WORKER_ACTION ? 'server' : 'browser',
    body,
    guardPassport: {
      persistent_ban_checked: !isRecoveryWorkerAction,
      action_format_checked: true,
      whitelist_checked: true,
      deployment_role_checked: deploymentRoleChecked,
      environment_partition_checked: environmentPartitionChecked,
      body_checked: true,
      seven_signatures_checked: !isRecoveryWorkerAction,
      action_guard_checked: false,
      integrity_checked: false,
      version: 'dirac-recovery-central-guard-v204'
    }
  };
  let asyncContextStore = null;
  try {
    asyncContextStore = DIRAC_CENTRAL_ASYNC_CONTEXT_V149 && DIRAC_CENTRAL_ASYNC_CONTEXT_V149.getStore();
    if (asyncContextStore) asyncContextStore.ctx = ctx;
  } catch (_) { asyncContextStore = null; }
  DIRAC_RECOVERY_CONTEXT_STACK_V201.push(ctx);
  if (typeof DIRAC_CENTRAL_CONTEXT_STACK_V146 !== 'undefined') DIRAC_CENTRAL_CONTEXT_STACK_V146.push(ctx);
  try {
    const guardResponse = req.method === 'OPTIONS'
      ? await diracRecoveryPreflightGuardV204(req, res, ctx, identity.key)
      : action === DIRAC_RECOVERY_WORKER_ACTION
        ? await diracRecoveryWorkerGuardV201(req, res, ctx, body, identity.key)
        : action === DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165
          ? await diracRecoveryLinkOpenGuardV202(req, res, ctx, body, identity.key)
          : await diracRecoveryBrowserGuardV201(req, res, ctx, body, identity.key);
    if (guardResponse) return guardResponse;

    if (isRecoveryWorkerAction && identity && identity.deferredWorkerBan === true) {
      let checkedIdentity;
      try { checkedIdentity = await diracRecoveryCheckBanV201(req, action); }
      catch (_) {
        return res.status(503).json({
          ok: false,
          code: 'RECOVERY_GUARD_UNAVAILABLE',
          message: 'Sistem keamanan belum tersedia.'
        });
      }
      if (!checkedIdentity.ok) {
        return res.status(checkedIdentity.persistenceUnavailable ? 503 : 403).json({
          ok: false,
          code: checkedIdentity.persistenceUnavailable
            ? 'RECOVERY_GUARD_PERSISTENCE_UNAVAILABLE'
            : 'RECOVERY_PERSISTENT_BAN_ACTIVE',
          message: 'Permintaan ditolak oleh sistem keamanan.'
        });
      }
      identity = checkedIdentity;
      ctx.guardPassport.persistent_ban_checked = true;
    }

    ctx.guardPassport.action_guard_checked = true;
    ctx.guardPassport.integrity_checked = Object.entries(ctx.guardPassport)
      .filter(([key]) => key.endsWith('_checked') && key !== 'integrity_checked')
      .every(([, value]) => value === true);
    if (!ctx.guardPassport.integrity_checked) {
      return diracRecoveryGuardRejectV201(req, res, action, 'central_guard_integrity_incomplete', 403, identity.key);
    }
    req.__diracCentralSecurityGuardPassedV146 = true;
    if (req.method === 'OPTIONS') {
      res.setHeader('X-Dirac-Central-Security-Guard', DIRAC_CENTRAL_SECURITY_GUARD_V146);
      return res.status(204).end();
    }
    if (req.method === 'HEAD') {
      res.setHeader('X-Dirac-Central-Security-Guard', DIRAC_CENTRAL_SECURITY_GUARD_V146);
      const bootstrapToken = diracCsrfIssueToken(req, res, action);
      const pageNonce = bootstrapToken ? diracRecoveryPageNonceIssueV203(res, action, bootstrapToken) : '';
      if (!bootstrapToken || !pageNonce) {
        return res.status(503).json({
          ok: false,
          code: 'CENTRAL_GUARD_BOOTSTRAP_TOKEN_UNAVAILABLE',
          message: 'Token bootstrap keamanan belum tersedia.'
        });
      }
      return res.status(204).end();
    }
    if (action === DIRAC_RECOVERY_WORKER_ACTION) {
      return customerSecurityHandleRecoveryWorkerGenerate(req, res, action);
    }
    if (action === DIRAC_LOST_PASSKEY_RECOVERY_LINK_ACTION_V165) {
      return diracRecoveryLinkOpenV202(req, res, ctx, body);
    }
    return diracRecoveryCryptoV2VerifyEnvelope(req, res, ctx, body);
  } catch (error) {
    if (req.__diracRecoveryWorkerTransportVerifiedV190 !== true) {
      return diracRecoveryGuardRejectV201(req, res, action, String(error && error.code || 'central_guard_exception'), 403, identity.key);
    }
    return res.status(500).json({ ok: false, code: 'RECOVERY_PROCESSING_FAILED', message: 'Recovery belum dapat diproses.' });
  } finally {
    req.__diracCentralSecurityGuardPassedV146 = false;
    if (asyncContextStore && asyncContextStore.ctx === ctx) asyncContextStore.ctx = null;
    if (typeof DIRAC_CENTRAL_CONTEXT_STACK_V146 !== 'undefined') {
      const centralIndex = DIRAC_CENTRAL_CONTEXT_STACK_V146.lastIndexOf(ctx);
      if (centralIndex >= 0) DIRAC_CENTRAL_CONTEXT_STACK_V146.splice(centralIndex, 1);
    }
    const recoveryIndex = DIRAC_RECOVERY_CONTEXT_STACK_V201.lastIndexOf(ctx);
    if (recoveryIndex >= 0) DIRAC_RECOVERY_CONTEXT_STACK_V201.splice(recoveryIndex, 1);
  }
};
Object.defineProperty(module.exports, '__diracCentralSecurityGuardV146', { value: true, enumerable: false });
Object.defineProperty(module.exports, '__diracRecoveryOnlyServer2V201', { value: true, enumerable: false });


/* ============================================================
   DIRAC SERVER 2 RECOVERY-ONLY INVARIANT v220
   Narrow invariant only; no non-recovery route is introduced.
   ============================================================ */
if (typeof module.exports !== 'function'
    || module.exports.__diracCentralSecurityGuardV146 !== true
    || module.exports.__diracRecoveryOnlyServer2V201 !== true) {
  throw new Error('DIRAC_SERVER2_RECOVERY_ONLY_EXPORT_INVARIANT_FAILED_V220');
}
Object.defineProperty(module.exports, '__diracServer2RecoveryOnlyV220', { value: true, enumerable: false });

/* ============================================================
   DIRAC SERVER 2 STRICT RECOVERY BOUNDARY v221
   Insert-only outer invariant. Existing recovery/lost-passkey handler bytes
   and Central Guard bytes remain unchanged.
   ============================================================ */
const DIRAC_SERVER2_STRICT_RECOVERY_BOUNDARY_V221 = 'dirac-server2-strict-recovery-boundary-v221';
const DIRAC_SERVER2_FORBIDDEN_SECURITY_DISABLE_ENVS_V221 = Object.freeze([
  'DIRAC_LOST_PASSKEY_QUEUE_DISABLED',
  'DIRAC_GLOBAL_API_THREAT_GUARD_DISABLED',
  'DIRAC_BOLA_IDOR_GLOBAL_BAN_DISABLED',
  'DIRAC_BOLA_IDOR_SERVICE_SCOPE_DISABLED',
  'DIRAC_SECURITY_WRITE_COALESCER_DISABLED',
  'DIRAC_CSRF_ALL_WEBSITE_ACTIONS_DISABLED'
]);

function diracServer2StrictEnvTrueV221(name) {
  return /^(?:1|true|yes|on|enabled)$/i.test(String(process.env[String(name || '')] || '').trim());
}

function diracServer2StrictAssertV221() {
  const disabled = DIRAC_SERVER2_FORBIDDEN_SECURITY_DISABLE_ENVS_V221.filter(diracServer2StrictEnvTrueV221);
  if (disabled.length) throw new Error('DIRAC_SERVER2_SECURITY_DISABLE_FLAG_FORBIDDEN_V221');
  if (typeof customerSecurityLostPasskeyQueueEnabledV164 !== 'function'
      || customerSecurityLostPasskeyQueueEnabledV164() !== true) {
    throw new Error('DIRAC_SERVER2_LOST_PASSKEY_QUEUE_REQUIRED_V221');
  }
  if (typeof customerSecurityLostPasskeyQueueTableV164 !== 'function'
      || String(customerSecurityLostPasskeyQueueTableV164() || '').trim() !== String(DIRAC_PERSISTENT_BAN_TABLE || '').trim()
      || !String(DIRAC_PERSISTENT_BAN_TABLE || '').trim()) {
    throw new Error('DIRAC_SERVER2_QUEUE_PERSISTENCE_TABLE_INVALID_V221');
  }
  if (typeof readPersistentSecurityJsonStrictV194 !== 'function'
      || typeof writePersistentSecurityJsonRequiredV194 !== 'function'
      || typeof claimPersistentSecurityKeyOnceV194 !== 'function') {
    throw new Error('DIRAC_SERVER2_SECURITY_PERSISTENCE_BINDING_MISSING_V221');
  }
  return true;
}

diracServer2StrictAssertV221();
const __diracServer2RecoveryOnlyBeforeV221 = module.exports;
module.exports = async function diracServer2StrictRecoveryBoundaryV221(req, res) {
  try {
    diracServer2StrictAssertV221();
  } catch (_) {
    if (res && typeof res.status === 'function' && typeof res.json === 'function') {
      return res.status(503).json({
        ok: false,
        code: 'DIRAC_SERVER2_SECURITY_BOUNDARY_UNAVAILABLE_V221',
        message: 'Sistem keamanan recovery belum tersedia.'
      });
    }
    throw _;
  }
  return __diracServer2RecoveryOnlyBeforeV221(req, res);
};
Object.defineProperty(module.exports, '__diracCentralSecurityGuardV146', { value: true, enumerable: false });
Object.defineProperty(module.exports, '__diracRecoveryOnlyServer2V201', { value: true, enumerable: false });
Object.defineProperty(module.exports, '__diracServer2RecoveryOnlyV220', { value: true, enumerable: false });
Object.defineProperty(module.exports, '__diracServer2StrictRecoveryBoundaryV221', { value: true, enumerable: false });
if (module.exports.__diracCentralSecurityGuardV146 !== true
    || module.exports.__diracRecoveryOnlyServer2V201 !== true
    || module.exports.__diracServer2RecoveryOnlyV220 !== true
    || module.exports.__diracServer2StrictRecoveryBoundaryV221 !== true) {
  throw new Error('DIRAC_SERVER2_STRICT_EXPORT_INVARIANT_FAILED_V221');
}

