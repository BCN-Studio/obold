import { existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { promises as dns } from 'node:dns';
import { loadConfigFile } from '../config/loader.ts';
import { OboldDatabase } from '../db/database.ts';
import { OboldCipher } from '../crypto/cipher.ts';
import { createDefaultPluginRegistry } from '../plugins/registry.ts';
import { validateTargetUrl } from '../plugins/network-guard.ts';

export interface DiagnosticResult {
  category: string;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  message: string;
  detail?: string;
}

export interface DoctorReport {
  timestamp: string;
  checks: DiagnosticResult[];
  passed: number;
  warnings: number;
  failed: number;
  overallStatus: 'HEALTHY' | 'WARNINGS' | 'CRITICAL';
}

export async function runDiagnostics(configPath: string = './obold.yaml', masterKey?: string): Promise<DoctorReport> {
  const checks: DiagnosticResult[] = [];

  let config: any = null;
  if (!existsSync(configPath)) {
    checks.push({
      category: 'CONFIGURATION',
      name: 'Config File Existence',
      status: 'FAIL',
      message: `Configuration file not found at: ${configPath}`,
      detail: 'Run "obold init" to generate a starter obold.yaml file.',
    });
  } else {
    try {
      config = loadConfigFile(configPath);
      checks.push({
        category: 'CONFIGURATION',
        name: 'Config Syntax & Schema',
        status: 'PASS',
        message: `Valid configuration (${config.switches.length} switches registered).`,
      });
    } catch (err: any) {
      checks.push({
        category: 'CONFIGURATION',
        name: 'Config Syntax & Schema',
        status: 'FAIL',
        message: `Schema error: ${err.message}`,
      });
    }
  }

  if (config) {
    const dbDir = dirname(config.storage.path);
    try {
      if (!existsSync(dbDir)) {
        checks.push({
          category: 'STORAGE',
          name: 'Storage Directory',
          status: 'WARN',
          message: `Storage directory "${dbDir}" does not exist yet (will be created automatically).`,
        });
      } else {
        const testFile = `${dbDir}/.obold_perm_test_${Date.now()}`;
        writeFileSync(testFile, 'test');
        unlinkSync(testFile);
        checks.push({
          category: 'STORAGE',
          name: 'Storage Permissions',
          status: 'PASS',
          message: `Storage directory "${dbDir}" is writable.`,
        });
      }

      const db = new OboldDatabase(config.storage.path, config.storage?.walMode !== false);
      const { integrity, journalMode } = db.checkIntegrity();

      if (integrity === 'ok') {
        checks.push({
          category: 'STORAGE',
          name: 'SQLite Database Integrity',
          status: 'PASS',
          message: 'SQLite database passed integrity check (0 corruption errors).',
        });
      } else {
        checks.push({
          category: 'STORAGE',
          name: 'SQLite Database Integrity',
          status: 'FAIL',
          message: `SQLite database integrity issue: ${integrity}`,
        });
      }

      if (journalMode.toLowerCase() === 'wal') {
        checks.push({
          category: 'STORAGE',
          name: 'SQLite WAL Mode',
          status: 'PASS',
          message: 'Write-Ahead Logging (WAL) is active for concurrent atomic reads.',
        });
      } else {
        checks.push({
          category: 'STORAGE',
          name: 'SQLite WAL Mode',
          status: 'WARN',
          message: `Journal mode is "${journalMode}". WAL mode is recommended.`,
        });
      }

      db.close();
    } catch (err: any) {
      checks.push({
        category: 'STORAGE',
        name: 'Database Access',
        status: 'FAIL',
        message: `Database error: ${err.message}`,
      });
    }
  }

  try {
    const cipher = new OboldCipher(masterKey);
    const testPlaintext = 'obold-diagnostics-roundtrip-test-payload';
    const encrypted = cipher.encryptToString({ test: testPlaintext });
    const decrypted = cipher.decryptFromString(encrypted);
    const parsed = JSON.parse(decrypted);

    if (parsed.test === testPlaintext) {
      checks.push({
        category: 'CRYPTO',
        name: 'ChaCha20-Poly1305 Roundtrip',
        status: 'PASS',
        message: 'Master key derivation (scrypt) and authenticated encryption verified.',
      });
    } else {
      checks.push({
        category: 'CRYPTO',
        name: 'ChaCha20-Poly1305 Roundtrip',
        status: 'FAIL',
        message: 'Decrypted plaintext mismatch during diagnostic test.',
      });
    }
    cipher.destroy();
  } catch (err: any) {
    checks.push({
      category: 'CRYPTO',
      name: 'Cryptographic Subsystem',
      status: 'FAIL',
      message: `Cipher validation failed: ${err.message}`,
    });
  }

  try {
    const hrStart = process.hrtime.bigint();
    let counter = 0;
    for (let i = 0; i < 10000; i++) counter += i;
    const hrElapsed = process.hrtime.bigint() - hrStart;

    if (hrElapsed > 0n) {
      checks.push({
        category: 'CLOCK',
        name: 'Monotonic Clock Resolution',
        status: 'PASS',
        message: `High-resolution monotonic timer operational (${Number(hrElapsed)}ns sample).`,
      });
    } else {
      checks.push({
        category: 'CLOCK',
        name: 'Monotonic Clock Resolution',
        status: 'FAIL',
        message: 'Monotonic clock resolution check failed.',
      });
    }
  } catch (err: any) {
    checks.push({
      category: 'CLOCK',
      name: 'Clock Subsystem',
      status: 'FAIL',
      message: `Clock test error: ${err.message}`,
    });
  }

  try {
    const localGuard = await validateTargetUrl('http://127.0.0.1:8080', false);
    const metaGuard = await validateTargetUrl('http://169.254.169.254/latest/meta-data', false);
    if (!localGuard.valid && !metaGuard.valid) {
      checks.push({
        category: 'SECURITY',
        name: 'SSRF & Private Network Guard',
        status: 'PASS',
        message: 'SSRF filter correctly intercepts loopback and cloud metadata endpoints.',
      });
    } else {
      checks.push({
        category: 'SECURITY',
        name: 'SSRF & Private Network Guard',
        status: 'FAIL',
        message: 'SSRF filter failed to block private network destinations.',
      });
    }
  } catch (err: any) {
    checks.push({
      category: 'SECURITY',
      name: 'SSRF Guard',
      status: 'FAIL',
      message: `SSRF filter error: ${err.message}`,
    });
  }

  try {
    await dns.lookup('bcnstudio.tech');
    checks.push({
      category: 'NETWORK',
      name: 'Outbound DNS Resolution',
      status: 'PASS',
      message: 'DNS resolution operational.',
    });
  } catch {
    checks.push({
      category: 'NETWORK',
      name: 'Outbound DNS Resolution',
      status: 'WARN',
      message: 'DNS resolution failed or isolated host without public internet access.',
    });
  }

  if (config) {
    const registry = createDefaultPluginRegistry();
    const registeredMap = new Map(registry.list().map((p) => [p.id, registry.get(p.id)!]));
    const missingPlugins: string[] = [];
    const configValidationErrors: string[] = [];

    for (const sw of config.switches) {
      if (sw.reminders) {
        for (const r of sw.reminders) {
          const plug = registeredMap.get(r.plugin);
          if (!plug) {
            missingPlugins.push(r.plugin);
          } else {
            const val = plug.validateConfig(r.config);
            if (!val.valid) configValidationErrors.push(`Reminder "${r.name || r.id}": ${val.error}`);
          }
        }
      }
      for (const st of sw.stages) {
        for (const act of st.actions) {
          const plug = registeredMap.get(act.plugin);
          if (!plug) {
            missingPlugins.push(act.plugin);
          } else {
            const val = plug.validateConfig(act.config);
            if (!val.valid) configValidationErrors.push(`Action "${act.id}" (${act.plugin}): ${val.error}`);
          }
        }
      }
      if (sw.duress?.actions) {
        for (const act of sw.duress.actions) {
          const plug = registeredMap.get(act.plugin);
          if (!plug) {
            missingPlugins.push(act.plugin);
          } else {
            const val = plug.validateConfig(act.config);
            if (!val.valid) configValidationErrors.push(`Duress action "${act.id}": ${val.error}`);
          }
        }
      }
    }

    if (missingPlugins.length === 0) {
      checks.push({
        category: 'PLUGINS',
        name: 'Plugin Registration',
        status: 'PASS',
        message: `All plugins referenced by configured switches (${registeredMap.size} available) are registered.`,
      });
    } else {
      checks.push({
        category: 'PLUGINS',
        name: 'Plugin Registration',
        status: 'FAIL',
        message: `Missing registered plugins: ${Array.from(new Set(missingPlugins)).join(', ')}`,
      });
    }

    if (configValidationErrors.length === 0) {
      checks.push({
        category: 'PLUGINS',
        name: 'Plugin Configuration Validation',
        status: 'PASS',
        message: 'All configured plugin actions passed schema and parameter validation.',
      });
    } else {
      checks.push({
        category: 'PLUGINS',
        name: 'Plugin Configuration Validation',
        status: 'FAIL',
        message: `${configValidationErrors.length} plugin configuration errors detected.`,
        detail: configValidationErrors.join(' | '),
      });
    }
  }

  const passed = checks.filter((c) => c.status === 'PASS').length;
  const warnings = checks.filter((c) => c.status === 'WARN').length;
  const failed = checks.filter((c) => c.status === 'FAIL').length;

  let overallStatus: 'HEALTHY' | 'WARNINGS' | 'CRITICAL' = 'HEALTHY';
  if (failed > 0) overallStatus = 'CRITICAL';
  else if (warnings > 0) overallStatus = 'WARNINGS';

  return {
    timestamp: new Date().toISOString(),
    checks,
    passed,
    warnings,
    failed,
    overallStatus,
  };
}

export function printDoctorReport(report: DoctorReport): void {
  const C = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    cyan: '\x1b[36m',
    gray: '\x1b[90m',
    white: '\x1b[97m',
  };

  console.log('\n================================================================================');
  console.log('🩺  obold Diagnostic Doctor & System Environment Assessment');
  console.log('================================================================================');

  let currentCategory = '';
  for (const check of report.checks) {
    if (check.category !== currentCategory) {
      currentCategory = check.category;
      console.log(`\n${C.bold}${C.white}• ${currentCategory}${C.reset}`);
    }

    let badge = `${C.green}✓ PASS${C.reset}`;
    if (check.status === 'WARN') badge = `${C.yellow}⚠ WARN${C.reset}`;
    else if (check.status === 'FAIL') badge = `${C.red}✖ FAIL${C.reset}`;

    console.log(`  ${badge}  ${C.bold}${check.name.padEnd(30, ' ')}${C.reset} ${check.message}`);
    if (check.detail) {
      console.log(`         ${C.dim}${check.detail}${C.reset}`);
    }
  }

  console.log('\n================================================================================');
  console.log(
    `Assessment Summary: ${report.passed} passed, ${report.warnings} warnings, ${report.failed} failed. Overall: ${
      report.overallStatus === 'HEALTHY'
        ? `${C.green}${C.bold}HEALTHY${C.reset}`
        : report.overallStatus === 'WARNINGS'
        ? `${C.yellow}${C.bold}WARNINGS DETECTED${C.reset}`
        : `${C.red}${C.bold}CRITICAL ISSUES DETECTED${C.reset}`
    }`
  );
  console.log('================================================================================\n');
}
