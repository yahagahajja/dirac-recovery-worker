'use strict';

const http = require('node:http');

const DIRAC_RECOVERY_PATH_V262 = '/api/health';
const DIRAC_RECOVERY_RUNTIME_V262 = 'dirac-recovery-dedicated-compute-v262';

function diracRecoveryParseTargetV262(rawTarget) {
  const target = String(rawTarget || '');
  if (!target.startsWith('/') || target.startsWith('//') || target.includes('#')) return null;
  let parsed;
  try {
    parsed = new URL(target, 'http://dirac-recovery.invalid');
  } catch (_) {
    return null;
  }
  if (parsed.origin !== 'http://dirac-recovery.invalid' || parsed.pathname !== DIRAC_RECOVERY_PATH_V262) {
    return null;
  }
  const query = Object.create(null);
  for (const [key, value] of parsed.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(query, key)) {
      const current = query[key];
      query[key] = Array.isArray(current) ? current.concat(value) : [current, value];
    } else {
      query[key] = value;
    }
  }
  return { query };
}

function diracRecoveryAttachResponseV262(res) {
  if (typeof res.status !== 'function') {
    res.status = function diracRecoveryStatusV262(statusCode) {
      const value = Number(statusCode);
      if (!Number.isInteger(value) || value < 100 || value > 999) {
        throw new RangeError('DIRAC_RECOVERY_RESPONSE_STATUS_INVALID_V262');
      }
      this.statusCode = value;
      return this;
    };
  }
  if (typeof res.json !== 'function') {
    res.json = function diracRecoveryJsonV262(value) {
      const body = JSON.stringify(value);
      if (!this.headersSent && !this.hasHeader('Content-Type')) {
        this.setHeader('Content-Type', 'application/json; charset=utf-8');
      }
      if (!this.headersSent && body !== undefined && !this.hasHeader('Content-Length')) {
        this.setHeader('Content-Length', Buffer.byteLength(body, 'utf8'));
      }
      this.end(body === undefined ? '' : body);
      return this;
    };
  }
  return res;
}

function diracRecoverySendOuterFailureV262(res, statusCode, code) {
  if (res.writableEnded) return;
  if (res.headersSent) {
    res.destroy();
    return;
  }
  diracRecoveryAttachResponseV262(res)
    .status(statusCode)
    .json({ ok: false, code, message: 'Recovery belum dapat diproses.' });
}

function createDiracRecoveryServerV262(handler) {
  if (typeof handler !== 'function'
      || handler.__diracCentralSecurityGuardV146 !== true
      || handler.__diracRecoveryOnlyServer2V201 !== true
      || handler.__diracServer2RecoveryOnlyV220 !== true
      || handler.__diracServer2StrictRecoveryBoundaryV221 !== true) {
    throw new Error('DIRAC_RECOVERY_HANDLER_GUARD_INVARIANT_FAILED_V262');
  }
  return http.createServer(async (req, res) => {
    const target = diracRecoveryParseTargetV262(req.url);
    if (!target) {
      diracRecoverySendOuterFailureV262(res, 404, 'DIRAC_RECOVERY_ROUTE_NOT_FOUND_V262');
      return;
    }
    req.query = target.query;
    diracRecoveryAttachResponseV262(res);
    try {
      await handler(req, res);
      if (!res.writableEnded) {
        diracRecoverySendOuterFailureV262(res, 500, 'DIRAC_RECOVERY_HANDLER_RESPONSE_MISSING_V262');
      }
    } catch (error) {
      try {
        console.error('[dirac-recovery-runtime-failure-v262]', JSON.stringify({
          patch: DIRAC_RECOVERY_RUNTIME_V262,
          error_name: String(error && error.name || 'Error').slice(0, 80),
          error_code: String(error && error.code || 'DIRAC_RECOVERY_RUNTIME_FAILURE').slice(0, 120),
          secrets_logged: false
        }));
      } catch (_) {}
      diracRecoverySendOuterFailureV262(res, 500, 'DIRAC_RECOVERY_RUNTIME_FAILURE_V262');
    }
  });
}

function diracRecoveryStartV262() {
  const handler = require('./api/health.js');
  const port = Number(process.env.PORT || 3000);
  const host = String(process.env.HOST || '0.0.0.0');
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('DIRAC_RECOVERY_PORT_INVALID_V262');
  }
  const server = createDiracRecoveryServerV262(handler);
  server.listen(port, host, () => {
    console.log('[dirac-recovery-runtime-ready-v262]', JSON.stringify({
      patch: DIRAC_RECOVERY_RUNTIME_V262,
      node_version: String(process.version || '').slice(0, 32),
      port,
      secrets_logged: false
    }));
  });
  return server;
}

if (require.main === module) diracRecoveryStartV262();

module.exports = Object.freeze({
  createDiracRecoveryServerV262,
  diracRecoveryParseTargetV262
});
