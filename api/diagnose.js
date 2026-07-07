'use strict';

/*
  Dirac Recovery Worker ENV Diagnostic
  - Standalone script only. Tidak mengubah health.js.
  - Tidak menampilkan secret plaintext.
  - Jalankan di env Server 1 atau Server 2:
      node dirac-recovery-diagnose.js server1
      node dirac-recovery-diagnose.js server2
      node dirac-recovery-diagnose.js auto
*/

const crypto = require('crypto');

const MODE = String(process.argv[2] || 'auto').trim().toLowerCase();
const WORKER_ACTION = 'dirac_recovery_worker_generate';

function env(name) {
  return String(process.env[name] || '').trim();
}

function present(name) {
  return env(name).length > 0;
}

function bytes(value) {
  return Buffer.byteLength(String(value || ''), 'utf8');
}

function asciiToken(value) {
  return /^[A-Za-z0-9_.-]{1,80}$/.test(String(value || '').trim());
}

function mask(value, keepStart = 6, keepEnd = 4) {
  const raw = String(value || '');
  if (!raw) return 'missing';
  if (raw.length <= keepStart + keepEnd) return '*'.repeat(raw.length);
  return raw.slice(0, keepStart) + '...' + raw.slice(-keepEnd);
}

function sha12(value) {
  const raw = String(value || '');
  if (!raw) return 'missing';
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 12);
}

function safeUrlInfo(rawUrl) {
  const raw = String(rawUrl || '').trim();
  if (!raw) return { present: false, valid: false, reason: 'missing' };
  try {
    const u = new URL(raw);
    return {
      present: true,
      valid: u.protocol === 'https:' && Boolean(u.hostname),
      protocol: u.protocol.replace(':', ''),
      host: u.hostname,
      path: u.pathname.replace(/\/+$/, '') || '/',
      reason: u.protocol === 'https:' ? 'ok' : 'must_use_https'
    };
  } catch (_) {
    return { present: true, valid: false, reason: 'invalid_url' };
  }
}

function roleInfo() {
  const central = env('DIRAC_CENTRAL_DEPLOYMENT_ROLE');
  const generic = env('DIRAC_DEPLOYMENT_ROLE');
  const role = (central || generic || '').toLowerCase();
  return {
    role: role || 'missing',
    DIRAC_CENTRAL_DEPLOYMENT_ROLE: central ? mask(central, 4, 2) : 'missing',
    DIRAC_DEPLOYMENT_ROLE: generic ? mask(generic, 4, 2) : 'missing',
    is_vercel2: role === 'vercel2'
  };
}

function secretInfo(name) {
  const raw = env(name);
  return {
    present: Boolean(raw),
    bytes: bytes(raw),
    valid_min_64_bytes: bytes(raw) >= 64,
    sha256_12: sha12(raw)
  };
}

function callerInfo(name) {
  const raw = env(name);
  return {
    present: Boolean(raw),
    valid_ascii_token: raw ? asciiToken(raw) : false,
    masked: raw ? mask(raw, 4, 3) : 'missing',
    sha256_12: sha12(raw)
  };
}

const SERVER2_ONLY_ENV = [
  'DIRAC_RECOVERY_WORKER_ALLOWED_CALLER',
  'DIRAC_RECOVERY_WORKER_MAX_BODY_BYTES',
  'DIRAC_RECOVERY_WORKER_CLOCK_SKEW_SECONDS',
  'DIRAC_LOST_PASSKEY_ARGON2_MEMORY_KIB',
  'DIRAC_LOST_PASSKEY_ARGON2_TIME_COST',
  'DIRAC_LOST_PASSKEY_MAX_RUNNING',
  'DIRAC_LOST_PASSKEY_QUEUE_MAX',
  'DIRAC_LOST_PASSKEY_PROCESSING_LOCK_TTL_SECONDS'
];

const SERVER1_CALLER_ENV = [
  'DIRAC_RECOVERY_WORKER_URL',
  'DIRAC_RECOVERY_WORKER_SECRET',
  'DIRAC_RECOVERY_WORKER_CALLER'
];

function diagnoseServer1() {
  const problems = [];
  const warnings = [];
  const url = safeUrlInfo(env('DIRAC_RECOVERY_WORKER_URL'));
  const secret = secretInfo('DIRAC_RECOVERY_WORKER_SECRET');
  const caller = callerInfo('DIRAC_RECOVERY_WORKER_CALLER');

  if (!url.present) problems.push('SERVER1_MISSING_DIRAC_RECOVERY_WORKER_URL');
  else if (!url.valid) problems.push('SERVER1_INVALID_DIRAC_RECOVERY_WORKER_URL_' + String(url.reason).toUpperCase());

  if (!secret.present) problems.push('SERVER1_MISSING_DIRAC_RECOVERY_WORKER_SECRET');
  else if (!secret.valid_min_64_bytes) problems.push('SERVER1_SECRET_TOO_SHORT_MIN_64_BYTES');

  if (!caller.present) problems.push('SERVER1_MISSING_DIRAC_RECOVERY_WORKER_CALLER');
  else if (!caller.valid_ascii_token) problems.push('SERVER1_CALLER_INVALID_ASCII_TOKEN');

  for (const name of SERVER2_ONLY_ENV) {
    if (present(name)) warnings.push('SERVER1_HAS_SERVER2_ONLY_ENV_REMOVE_' + name);
  }

  return {
    role_expected: 'server1 caller/front door',
    worker_url: url,
    worker_secret: secret,
    worker_caller: caller,
    wrong_server_env_present: SERVER2_ONLY_ENV.filter(present),
    problems,
    warnings,
    ok: problems.length === 0,
    expected_flow: 'Browser -> Server1 customer_security_recovery_codes_generate -> signed worker call -> Server2 dirac_recovery_worker_generate'
  };
}

function diagnoseServer2() {
  const problems = [];
  const warnings = [];
  const role = roleInfo();
  const secret = secretInfo('DIRAC_RECOVERY_WORKER_SECRET');
  const allowedCaller = callerInfo('DIRAC_RECOVERY_WORKER_ALLOWED_CALLER');
  const url = safeUrlInfo(env('DIRAC_RECOVERY_WORKER_URL'));
  const caller = callerInfo('DIRAC_RECOVERY_WORKER_CALLER');

  if (!role.is_vercel2) problems.push('SERVER2_ROLE_NOT_VERCEL2_CAUSES_VERCEL2_ONLY_ACTION_BLOCKED');
  if (url.present) problems.push('SERVER2_MUST_NOT_HAVE_DIRAC_RECOVERY_WORKER_URL_LOCAL_WORKER_DISABLED');
  if (caller.present) warnings.push('SERVER2_HAS_DIRAC_RECOVERY_WORKER_CALLER_REMOVE_CALLER_ENV_FROM_WORKER');

  if (!secret.present) problems.push('SERVER2_MISSING_DIRAC_RECOVERY_WORKER_SECRET');
  else if (!secret.valid_min_64_bytes) problems.push('SERVER2_SECRET_TOO_SHORT_MIN_64_BYTES');

  if (!allowedCaller.present) problems.push('SERVER2_MISSING_DIRAC_RECOVERY_WORKER_ALLOWED_CALLER');
  else if (!allowedCaller.valid_ascii_token) problems.push('SERVER2_ALLOWED_CALLER_INVALID_ASCII_TOKEN');

  const lostPasskeyEnv = [
    'DIRAC_LOST_PASSKEY_ARGON2_MEMORY_KIB',
    'DIRAC_LOST_PASSKEY_ARGON2_TIME_COST',
    'DIRAC_LOST_PASSKEY_MAX_RUNNING',
    'DIRAC_LOST_PASSKEY_QUEUE_MAX',
    'DIRAC_LOST_PASSKEY_PROCESSING_LOCK_TTL_SECONDS'
  ];
  const missingRecommended = lostPasskeyEnv.filter((name) => !present(name));
  if (missingRecommended.length) warnings.push('SERVER2_MISSING_RECOMMENDED_LOST_PASSKEY_ENV_' + missingRecommended.join(','));

  let predicted403Reason = null;
  if (!role.is_vercel2) predicted403Reason = 'vercel2_only_action_blocked';
  else if (url.present || !secret.valid_min_64_bytes || !allowedCaller.present || !allowedCaller.valid_ascii_token) predicted403Reason = 'recovery_worker_not_enabled';
  else predicted403Reason = 'if called directly without Server1 signature: recovery_worker_caller_invalid / timestamp_invalid / signature_missing';

  return {
    role_expected: 'server2 recovery worker executor',
    deployment_role: role,
    worker_url_should_be_absent: url.present ? url : { present: false, expected_absent: true },
    worker_secret: secret,
    allowed_caller: allowedCaller,
    caller_env_on_server2: caller.present ? caller : { present: false, expected_absent: true },
    lost_passkey_env_present: lostPasskeyEnv.filter(present),
    lost_passkey_env_missing_recommended: missingRecommended,
    problems,
    warnings,
    predicted_403_reason_for_action: WORKER_ACTION + ' -> ' + predicted403Reason,
    ok: problems.length === 0,
    direct_browser_test_note: 'Direct POST to Server2 worker action should be 403 unless signed by Server1.'
  };
}

function diagnoseAuto() {
  const s1 = diagnoseServer1();
  const s2 = diagnoseServer2();
  let guessed = 'unknown';
  if (present('DIRAC_RECOVERY_WORKER_URL') || present('DIRAC_RECOVERY_WORKER_CALLER')) guessed = 'server1';
  if (roleInfo().is_vercel2 || present('DIRAC_RECOVERY_WORKER_ALLOWED_CALLER')) guessed = present('DIRAC_RECOVERY_WORKER_URL') ? 'mixed_misconfigured' : 'server2';
  return { guessed_server: guessed, server1: s1, server2: s2 };
}

const output = {
  ok: true,
  script: 'dirac-recovery-env-diagnostic',
  mode: MODE,
  time: new Date().toISOString(),
  safe_output: true,
  secrets_plaintext_shown: false,
  diagnostic: MODE === 'server1' ? diagnoseServer1() : MODE === 'server2' ? diagnoseServer2() : diagnoseAuto()
};

console.log(JSON.stringify(output, null, 2));

if (MODE === 'server1' && !output.diagnostic.ok) process.exitCode = 2;
if (MODE === 'server2' && !output.diagnostic.ok) process.exitCode = 2;
if (MODE === 'auto') {
  const d = output.diagnostic;
  const guessedProblems = d.guessed_server === 'server2' ? d.server2.problems : d.server1.problems;
  if (guessedProblems && guessedProblems.length) process.exitCode = 2;
}
