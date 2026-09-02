import { existsSync, writeFileSync, readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { loadConfigFile, generateStarterYamlTemplate, parseDurationToMs } from '../config/loader.ts';
import { OboldDatabase } from '../db/database.ts';
import { OboldCipher } from '../crypto/cipher.ts';
import { OboldTokenManager } from '../crypto/token.ts';
import { ShamirSecretSharing } from '../crypto/shamir.ts';
import { generateRescueBundle, verifyRescueBundle, generateRescueSignature, verifyRescueSignature } from '../crypto/rescue.ts';
import { installService, uninstallService, generateSystemdService, generateLaunchdPlist } from '../service/generator.ts';
import { startInteractiveMonitor } from '../tui/monitor.ts';
import { createDefaultPluginRegistry } from '../plugins/registry.ts';
import { scaffoldPlugin } from '../plugins/scaffold.ts';
import { OboldEngine } from '../core/engine.ts';
import { OboldWatchdog } from '../core/watchdog.ts';
import { OboldServer } from '../server/server.ts';
import { runDiagnostics, printDoctorReport } from '../doctor/diagnostics.ts';
import { resolveMasterKey as resolveKeyBuffer } from '../crypto/kdf.ts';

export async function runCli(args: string[]): Promise<void> {
  const command = args[0] || 'help';

  switch (command) {
    case 'run':
      await handleRunCommand(args.slice(1));
      break;
    case 'doctor':
      await handleDoctorCommand(args.slice(1));
      break;
    case 'init':
      handleInitCommand(args.slice(1));
      break;
    case 'status':
      await handleStatusCommand(args.slice(1));
      break;
    case 'top':
    case 'monitor':
      await handleTopCommand(args.slice(1));
      break;
    case 'checkin':
      await handleCheckinCommand(args.slice(1));
      break;
    case 'pause':
      await handlePauseCommand(args.slice(1));
      break;
    case 'resume':
      await handleResumeCommand(args.slice(1));
      break;
    case 'abort':
      await handleAbortCommand(args.slice(1));
      break;
    case 'service':
      handleServiceCommand(args.slice(1));
      break;
    case 'trigger':
      await handleTriggerCommand(args.slice(1));
      break;
    case 'secret':
      await handleSecretCommand(args.slice(1));
      break;
    case 'token':
      handleTokenCommand(args.slice(1));
      break;
    case 'rekey':
      await handleRekeyCommand(args.slice(1));
      break;
    case 'rescue':
      handleRescueCommand(args.slice(1));
      break;
    case 'plugin':
      handlePluginCommand(args.slice(1));
      break;
    case 'update':
    case 'upgrade':
      await handleUpdateCommand(args.slice(1));
      break;
    case 'version':
    case '-v':
    case '--version':
      console.log('obold v1.0.0-beta (BCN Studio)');
      break;
    case 'help':
    case '-h':
    case '--help':
    default:
      printHelp();
      break;
  }
}

async function handleDoctorCommand(args: string[]): Promise<void> {
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';
  const masterKey = resolveMasterKey(args);
  const report = await runDiagnostics(configPath, masterKey);
  printDoctorReport(report);
  if (report.failed > 0) {
    process.exit(1);
  }
}

async function handleUpdateCommand(args: string[]): Promise<void> {
  const currentVersion = '1.0.0-beta';
  console.log(`\n🔍 Checking for obold daemon updates (current: v${currentVersion})...`);

  try {
    const res = await fetch('https://api.github.com/repos/BCN-Studio/obold/releases/latest', {
      headers: {
        'User-Agent': 'obold-cli/1.0.0-beta (BCN Studio; +https://bcnstudio.tech)',
        'Accept': 'application/vnd.github.v3+json',
      },
    });

    if (!res.ok) {
      if (res.status === 404) {
        console.log(`✓ obold is up to date (current release: v${currentVersion}).\n`);
        return;
      }
      throw new Error(`GitHub API returned HTTP ${res.status}: ${res.statusText}`);
    }

    const data: any = await res.json();
    const latestTag = data.tag_name ? data.tag_name.replace(/^v/, '') : currentVersion;

    if (latestTag === currentVersion) {
      console.log(`✓ obold is up to date (version v${currentVersion}).\n`);
    } else {
      console.log(`\n🚀 New obold release available: v${currentVersion} → v${latestTag}`);
      console.log(`Release Notes: ${data.html_url || 'https://github.com/BCN-Studio/obold/releases'}`);
      console.log('\nTo update your local installation, run:');
      console.log('  curl -fsSL https://raw.githubusercontent.com/BCN-Studio/obold/main/install.sh | bash\n');
      console.log('Or if updating via Git:');
      console.log('  git pull && bun install\n');
    }
  } catch (err: any) {
    console.error(`\n⚠️ Update check failed: ${err?.message || err}`);
    console.error('Verify your network connection or visit: https://github.com/BCN-Studio/obold/releases\n');
  }
}

function resolveMasterKey(args: string[]): string {
  const cliKey = getArgValue(args, '--key') || getArgValue(args, '-k');
  const keyFile = getArgValue(args, '--key-file');
  const keyBuf = resolveKeyBuffer(cliKey, keyFile);
  return keyBuf.toString('hex');
}

async function promptHiddenPassword(promptText: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
      rl.question(promptText, (ans) => {
        rl.close();
        resolve(ans.trim());
      });
    });
  }

  process.stdout.write(promptText);
  return new Promise((resolve) => {
    let input = '';
    const onData = (char: Buffer) => {
      const str = char.toString('utf-8');
      for (const c of str) {
        if (c === '\n' || c === '\r' || c === '\u0004') {
          process.stdin.setRawMode(false);
          process.stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolve(input.trim());
          return;
        } else if (c === '\u0003') {
          process.stdin.setRawMode(false);
          process.exit(130);
        } else if (c === '\b' || c === '\x7f') {
          if (input.length > 0) {
            input = input.slice(0, -1);
          }
        } else {
          input += c;
        }
      }
    };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

async function handleRunCommand(args: string[]) {
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';
  const dryRun = args.includes('--dry-run');

  if (!existsSync(configPath)) {
    console.error(`\n❌ Error: Configuration file not found at: ${configPath}`);
    console.error('Run "obold init" to generate a starter configuration.\n');
    process.exit(1);
  }

  const config = loadConfigFile(configPath);
  if (dryRun) {
    console.log('⚠️ Running in DRY-RUN mode. Actions will be logged but not executed.');
  }

  const masterKey = resolveMasterKey(args);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher(masterKey);
  const tokenManager = new OboldTokenManager(masterKey);
  const plugins = createDefaultPluginRegistry();

  const watchdog = new OboldWatchdog(db);
  watchdog.installProcessGuards();
  watchdog.startHeartbeat(15000);

  const engine = new OboldEngine(config, db, cipher, plugins);
  await engine.start();

  let server: OboldServer | null = null;
  if (config.server.enabled) {
    server = new OboldServer(config, engine, tokenManager);
    server.start();
    console.log(`🌐 Web Dashboard & REST API live at: http://${config.server.host}:${config.server.port}`);
  }

  console.log(`🛡️  Engine armed with ${config.switches.length} active switch(es). Ready.`);
  console.log(`Press Ctrl+C to stop gracefully.\n`);

  let isShuttingDown = false;
  const shutdown = async (signal: string) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log(`\n🛑 Received ${signal}. Shutting down obold daemon gracefully...`);

    try {
      watchdog.stopHeartbeat();
      engine.stop();
      if (server) server.stop();
      db.logAudit('INFO', 'DAEMON_SHUTDOWN', `Daemon gracefully stopped on ${signal}.`);
      db.checkpoint();
      db.close();
      console.log('✓ Stopped safely. State preserved in SQLite WAL.\n');
    } catch (err: any) {
      console.error('Error during shutdown:', err?.message || err);
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));
}

function handleInitCommand(args: string[]) {
  const targetPath = getArgValue(args, '--out') || './obold.yaml';
  if (existsSync(targetPath)) {
    console.error(`\n⚠️ File already exists at: ${targetPath}. Please choose a different path or remove it first.`);
    return;
  }

  const yamlContent = generateStarterYamlTemplate();
  writeFileSync(targetPath, yamlContent, 'utf-8');
  console.log(`\n✨ Initialized starter configuration at: ${targetPath}`);
  console.log('You can now run:');
  console.log(`  bun run src/index.ts run --config ${targetPath}\n`);
}

async function handleStatusCommand(args: string[]) {
  const configPath = getArgValue(args, '--config') || './obold.yaml';
  if (!existsSync(configPath)) {
    console.error(`\n❌ Configuration file not found at: ${configPath}`);
    return;
  }

  const masterKey = resolveMasterKey(args);
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher(masterKey);
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  const states = engine.getRuntimeStates();
  console.log('\n================================================================================');
  console.log('🪙  obold Switch Status Ledger');
  console.log('================================================================================');

  for (const sw of states) {
    console.log(`Switch ID:        ${sw.id}`);
    console.log(`Name:             ${sw.name}`);
    if (sw.status === 'PAUSED') {
      console.log(`Status:           ⏸️  PAUSED`);
      console.log(`Paused Until:     ${sw.pausedUntil ? new Date(sw.pausedUntil).toLocaleString() : 'Indefinite'}`);
      if (sw.pauseReason) console.log(`Pause Reason:     ${sw.pauseReason}`);
    } else {
      console.log(`Status:           ${sw.status}`);
      console.log(`Next Deadline:    ${new Date(sw.nextDeadlineAt).toLocaleString()}`);
      console.log(`Remaining:        ${Math.round(sw.remainingMs / 1000)}s`);
    }
    console.log(`Active Stage:     ${sw.activeStageIndex === -1 ? 'None (Pre-Trigger)' : `Stage ${sw.activeStageIndex + 1}`}`);
    console.log('--------------------------------------------------------------------------------');
  }
  console.log('');
  db.close();
}

async function handleCheckinCommand(args: string[]) {
  const switchId = args[0];
  const isDuress = args.includes('--duress');
  const configPath = getArgValue(args, '--config') || './obold.yaml';

  if (!switchId) {
    console.error('\n❌ Usage: obold checkin <switch-id> [--duress] [--config <path>] [--key-file <path>]');
    return;
  }

  const masterKey = resolveMasterKey(args);
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher(masterKey);
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  try {
    const res = await engine.checkin(switchId, isDuress);
    console.log(`\n✓ Check-in successful for switch: [${switchId}]`);
    console.log(`Next deadline extended to: ${new Date(res.nextDeadlineAt).toLocaleString()}`);
    if (isDuress) {
      console.log('⚠️ DURESS mode acknowledged. Emergency protocol engaged.\n');
    } else {
      console.log('Status: ARMED\n');
    }
  } catch (err: any) {
    console.error(`\n❌ Check-in failed: ${err.message}\n`);
  } finally {
    db.close();
  }
}

async function handleTriggerCommand(args: string[]) {
  const switchId = args[0];
  const dryRun = args.includes('--dry-run');
  const forceReplay = args.includes('--force-replay') || args.includes('--force');
  const confirmDestructive = args.includes('--confirm-destructive') || args.includes('--confirm');
  const configPath = getArgValue(args, '--config') || './obold.yaml';

  if (!switchId) {
    console.error('\n❌ Usage: obold trigger <switch-id> [--dry-run] [--force-replay] [--confirm-destructive] [--config <path>] [--key-file <path>]');
    return;
  }

  const masterKey = resolveMasterKey(args);
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher(masterKey);
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  console.log(`\n⚠️ TRIPPING SWITCH [${switchId}] (Dry-Run: ${dryRun}, Force-Replay: ${forceReplay})...`);
  try {
    const res = await engine.triggerSwitch(switchId, dryRun, forceReplay, confirmDestructive);
    if (res.alreadyTriggered) {
      console.log(`⚠️ Switch [${switchId}] was already in ${res.status} state. Trigger ignored (idempotent). Pass --force-replay to re-execute.\n`);
    } else {
      console.log('✓ Trigger cascade executed.\n');
    }
  } catch (err: any) {
    console.error(`❌ Trigger failed: ${err.message}\n`);
  } finally {
    db.close();
  }
}

async function handleSecretCommand(args: string[]) {
  const sub = args[0];
  if (sub === 'split') {
    let text = args[1];
    const file = getArgValue(args, '--file') || getArgValue(args, '-f');
    if (file && existsSync(file)) {
      text = readFileSync(file, 'utf-8').trim();
    } else if (!text && process.stdin.isTTY) {
      text = await promptHiddenPassword('Enter secret to split: ');
    }

    if (!text) {
      console.error('\n❌ Usage: obold secret split ["<text>"] [--file <path>] [--total 5] [--threshold 3]');
      return;
    }

    const totalShares = parseInt(getArgValue(args, '--total') || getArgValue(args, '--shares') || '5', 10);
    const threshold = parseInt(getArgValue(args, '--threshold') || '3', 10);

    const shares = ShamirSecretSharing.split(text, totalShares, threshold);
    console.log(`\n🔐 Generated ${totalShares} Cryptographic Shares (Threshold: ${threshold} required to reconstruct):`);
    console.log('--------------------------------------------------------------------------------');
    shares.forEach((s, idx) => console.log(`Share ${idx + 1}: ${s}`));
    console.log('--------------------------------------------------------------------------------\n');
  } else if (sub === 'combine') {
    const shares = args.slice(1).filter((a) => !a.startsWith('--'));
    if (shares.length === 0) {
      console.error('\n❌ Usage: obold secret combine <share1> <share2> ... <shareK>');
      return;
    }

    try {
      const secret = ShamirSecretSharing.combine(shares);
      console.log(`\n🔓 RECONSTRUCTED SECRET:\n${secret}\n`);
    } catch (err: any) {
      console.error(`\n❌ Reconstruction failed: ${err.message}\n`);
    }
  } else {
    console.log('\nUsage: obold secret split [--file <path>] | obold secret combine <shares...>\n');
  }
}

function handleTokenCommand(args: string[]) {
  const switchId = args[1] || args[0];
  const isDuress = args.includes('--duress');
  const days = parseInt(getArgValue(args, '--ttl') || '30', 10);
  const configPath = getArgValue(args, '--config') || './obold.yaml';

  if (!switchId || switchId === 'generate') {
    console.error('\n❌ Usage: obold token generate <switch-id> [--ttl <days>] [--duress] [--key-file <path>]');
    return;
  }

  const masterKey = resolveMasterKey(args);
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const tokenManager = new OboldTokenManager(masterKey);

  const { rawToken, tokenRecord } = tokenManager.generateToken(switchId, days * 86400000, isDuress);
  db.saveHeartbeatToken(tokenRecord);

  console.log(`\n🔑 Single-Use Ephemeral Token Generated for Switch [${switchId}]`);
  console.log(`Token:      ${rawToken}`);
  console.log(`Link:       http://${config.server.host}:${config.server.port}/checkin?token=${rawToken}`);
  console.log(`Expires At: ${new Date(tokenRecord.expiresAt).toLocaleString()}`);
  console.log(`Duress:     ${isDuress ? 'YES (Silent Alert)' : 'NO (Normal)'}\n`);
  db.close();
}

function handlePluginCommand(args: string[]) {
  const sub = args[0];
  if (sub === 'new') {
    const name = args[1] || 'my-plugin';
    const lang = (getArgValue(args, '--lang') || 'ts') as 'ts' | 'python' | 'sh';
    const outDir = getArgValue(args, '--out') || './plugins';
    const dir = scaffoldPlugin(name, lang, outDir);
    console.log(`\n✨ Scaffolded new community plugin [${name}] in: ${dir}`);
    console.log(`Entrypoint: ${dir}/${lang === 'python' ? 'plugin.py' : lang === 'sh' ? 'plugin.sh' : 'index.ts'}\n`);
  } else if (sub === 'list') {
    const plugins = createDefaultPluginRegistry();
    console.log('\n================================================================================');
    console.log('🔌 Registered Core & Community Plugins');
    console.log('================================================================================');
    for (const p of plugins.list()) {
      console.log(`ID:          ${p.id}`);
      console.log(`Name:        ${p.name}`);
      console.log(`Version:     ${p.version}`);
      console.log(`Description: ${p.description}`);
      console.log('--------------------------------------------------------------------------------');
    }
    console.log('');
  } else {
    console.log('\nUsage: obold plugin list | obold plugin new <name> [--lang ts|python|sh]\n');
  }
}

async function handleRekeyCommand(args: string[]) {
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';
  
  let oldKey = getArgValue(args, '--old-key') || getArgValue(args, '-o');
  const oldKeyFile = getArgValue(args, '--old-key-file');
  if (oldKeyFile && existsSync(oldKeyFile)) {
    oldKey = readFileSync(oldKeyFile, 'utf-8').trim();
  } else if (!oldKey) {
    oldKey = process.env.OBOLD_OLD_MASTER_KEY || process.env.OBOLD_MASTER_KEY;
  }

  let newKey = getArgValue(args, '--new-key') || getArgValue(args, '-n');
  const newKeyFile = getArgValue(args, '--new-key-file');
  if (newKeyFile && existsSync(newKeyFile)) {
    newKey = readFileSync(newKeyFile, 'utf-8').trim();
  } else if (!newKey) {
    newKey = process.env.OBOLD_NEW_MASTER_KEY;
  }

  if (getArgValue(args, '--old-key') || getArgValue(args, '--new-key')) {
    console.warn('⚠️ Security Warning: Passing encryption keys via command line arguments is insecure. Prefer --old-key-file, --new-key-file, or interactive prompts.');
  }

  if (!oldKey && process.stdin.isTTY) {
    oldKey = await promptHiddenPassword('Enter current master encryption key: ');
  }

  if (!newKey && process.stdin.isTTY) {
    newKey = await promptHiddenPassword('Enter new master encryption key: ');
    const confirmKey = await promptHiddenPassword('Confirm new master encryption key: ');
    if (newKey !== confirmKey) {
      console.error('\n❌ Error: New master encryption keys do not match.');
      process.exit(1);
    }
  }

  if (!oldKey) {
    console.error('\n❌ Error: Missing required current master key. Provide via interactive prompt, --old-key-file, or OBOLD_MASTER_KEY.');
    process.exit(1);
  }

  if (!newKey) {
    console.error('\n❌ Error: Missing required new master key. Provide via interactive prompt, --new-key-file, or OBOLD_NEW_MASTER_KEY.');
    process.exit(1);
  }

  if (oldKey === newKey) {
    console.error('\n⚠️ Error: The new master key cannot be the same as the old master key.');
    process.exit(1);
  }

  if (!existsSync(configPath)) {
    console.error(`\n❌ Error: Configuration file not found at: ${configPath}`);
    process.exit(1);
  }

  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const oldCipher = new OboldCipher(oldKey);
  const newCipher = new OboldCipher(newKey);

  console.log('\n🔐 Rotating Master Encryption Key...');
  console.log(`Database: ${config.storage.path}`);

  try {
    const result = db.rekeyDatabase(oldCipher, newCipher);
    console.log(`✓ Master key rotation completed successfully.`);
    console.log(`✓ ${result.reencryptedRecords} ledger record(s) decrypted and re-encrypted with the new key.`);
    console.log(`✓ SQLite WAL journal flushed and checkpointed.\n`);
    console.log(`⚠️ Important: Update your OBOLD_MASTER_KEY environment variable or keyfile with the new key.\n`);
  } catch (err: any) {
    console.error(`\n❌ Rekeying Failed: ${err.message}`);
    process.exit(1);
  } finally {
    oldCipher.destroy();
    newCipher.destroy();
    db.close();
  }
}

function handleRescueCommand(args: string[]) {
  const sub = args[0] || 'generate';
  if (sub === 'generate' || sub === 'create' || sub === 'pack') {
    const payloadText = getArgValue(args, '--payload') || getArgValue(args, '-p') || getArgValue(args, '--secret') || getArgValue(args, '-s');
    const payloadFile = getArgValue(args, '--file') || getArgValue(args, '-f');
    const totalShares = parseInt(getArgValue(args, '--total') || getArgValue(args, '-n') || '5', 10);
    const threshold = parseInt(getArgValue(args, '--threshold') || getArgValue(args, '-k') || '3', 10);
    const outPath = getArgValue(args, '--out') || getArgValue(args, '-o') || './rescue.html';
    const title = getArgValue(args, '--title') || 'Sovereign Emergency Recovery Vault';
    const signKey = getArgValue(args, '--sign-key') || getArgValue(args, '--key') || process.env.OBOLD_MASTER_KEY;
    const signKeyFile = getArgValue(args, '--sign-key-file') || getArgValue(args, '--key-file');

    let payloadBuffer: Buffer;
    let filename = 'decrypted_vault.txt';

    if (payloadFile) {
      if (!existsSync(payloadFile)) {
        console.error(`\n❌ Error: Payload file not found at: ${payloadFile}`);
        process.exit(1);
      }
      payloadBuffer = readFileSync(payloadFile);
      filename = payloadFile.split(/[/\\]/).pop() || 'decrypted_vault.txt';
    } else if (payloadText) {
      payloadBuffer = Buffer.from(payloadText, 'utf-8');
    } else {
      console.error('\n❌ Error: Missing payload. Provide plaintext with --payload <text> or a file with --file <path>.');
      console.error('Example: obold rescue generate --payload "Vault Master Recovery Secret" --threshold 3 --total 5 --out ./rescue.html\n');
      process.exit(1);
    }

    const bundle = generateRescueBundle({
      payload: payloadBuffer,
      totalShares,
      threshold,
      title,
      filename,
    });

    writeFileSync(outPath, bundle.html, 'utf-8');

    let sigPath = '';
    let signingSecret = signKey;
    if (signKeyFile && existsSync(signKeyFile)) {
      signingSecret = readFileSync(signKeyFile, 'utf-8').trim();
    }
    if (signingSecret) {
      const sig = generateRescueSignature(bundle.html, signingSecret);
      sigPath = `${outPath}.sig`;
      writeFileSync(sigPath, sig, 'utf-8');
    }

    console.log('\n================================================================================');
    console.log('📦 Standalone Offline Emergency Rescue Vault Created');
    console.log('================================================================================');
    console.log(`Target File:        ${outPath}`);
    if (sigPath) {
      console.log(`Detached Signature: ${sigPath}`);
    }
    console.log(`Required Shares:    ${bundle.threshold} of ${bundle.totalShares}`);
    console.log(`Vault Title:        ${title}`);
    console.log('--------------------------------------------------------------------------------');
    console.log('🔑 Distribute each of the following shares to separate trusted heirs/parties:');
    console.log('--------------------------------------------------------------------------------');
    bundle.shares.forEach((s, idx) => {
      console.log(`Share #${idx + 1}: ${s}`);
    });
    console.log('================================================================================');
    console.log(`✓ Heirs can double-click "${outPath}" in any browser offline without software to decrypt.\n`);
  } else if (sub === 'verify' || sub === 'check' || sub === 'inspect') {
    const targetFile = args[1] || getArgValue(args, '--file') || getArgValue(args, '-f') || './rescue.html';
    if (!existsSync(targetFile)) {
      console.error(`\n❌ Error: Rescue bundle file not found at: ${targetFile}\n`);
      process.exit(1);
    }

    const htmlContent = readFileSync(targetFile, 'utf-8');
    const result = verifyRescueBundle(htmlContent);

    if (result.valid && result.manifest) {
      console.log('\n================================================================================');
      console.log('🛡️  Offline Rescue Bundle Cryptographic Verification');
      console.log('================================================================================');
      console.log(`Bundle File:       ${targetFile}`);
      console.log(`Integrity Status:  ✓ PASS (SHA-256 Digest & Manifest Verified)`);
      console.log(`Version:           ${result.manifest.version}`);
      console.log(`Bundle ID:         ${result.manifest.bundleId}`);
      console.log(`Created At:        ${result.manifest.createdAt}`);
      console.log(`Title:             ${result.manifest.title}`);
      console.log(`Threshold:         ${result.manifest.threshold} of ${result.manifest.totalShares} Shares`);
      console.log(`Target Filename:   ${result.manifest.filename}`);
      console.log(`Cipher SHA-256:    ${result.manifest.cipherSha256}`);

      const verifyKey = getArgValue(args, '--key') || getArgValue(args, '--sign-key') || process.env.OBOLD_MASTER_KEY;
      const verifyKeyFile = getArgValue(args, '--key-file') || getArgValue(args, '--sign-key-file');
      const sigFile = getArgValue(args, '--sig-file') || `${targetFile}.sig`;
      let sigSecret = verifyKey;
      if (verifyKeyFile && existsSync(verifyKeyFile)) {
        sigSecret = readFileSync(verifyKeyFile, 'utf-8').trim();
      }

      if (existsSync(sigFile) && sigSecret) {
        const sigHex = readFileSync(sigFile, 'utf-8').trim();
        const sigValid = verifyRescueSignature(htmlContent, sigHex, sigSecret);
        if (sigValid) {
          console.log(`Signature Status:  ✓ PASS (Detached HMAC-SHA256 Signature Verified)`);
        } else {
          console.error(`Signature Status:  ❌ FAIL (Detached Signature Mismatch or Tampered Bundle!)`);
          console.error('================================================================================\n');
          process.exit(1);
        }
      }

      console.log('================================================================================\n');
    } else {
      console.error('\n================================================================================');
      console.error('❌ Rescue Bundle Verification FAILED');
      console.error('================================================================================');
      console.error(`Error: ${result.error}`);
      console.error('================================================================================\n');
      process.exit(1);
    }
  } else {
    console.log('\nUsage: obold rescue generate --payload <text> | --file <path> [--threshold 3] [--total 5] [--out ./rescue.html] [--sign-key <key>]');
    console.log('       obold rescue verify <file> [--key <key>] [--sig-file <file.sig>]\n');
  }
}

async function handlePauseCommand(args: string[]) {
  const switchId = args[0];
  const isAll = args.includes('--all') || switchId === 'all';
  const durationStr = getArgValue(args, '--duration') || getArgValue(args, '-d') || getArgValue(args, '--for');
  const reason = getArgValue(args, '--reason') || getArgValue(args, '-r') || 'Manual operator pause';
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';

  if (!switchId && !isAll) {
    console.error('\n❌ Usage: obold pause <switch-id> [--duration <duration>] [--reason <reason>] [--all]');
    console.error('Example: obold pause main-vault --duration 14d --reason "Vacation off-grid"\n');
    return;
  }

  if (!existsSync(configPath)) {
    console.error(`\n❌ Configuration file not found at: ${configPath}`);
    return;
  }

  const durationMs = durationStr ? parseDurationToMs(durationStr) : undefined;
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher();
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  const targets = isAll ? config.switches.map((s) => s.id) : [switchId];
  console.log('\n================================================================================');
  console.log('⏸️  obold Switch Vacation & Maintenance Pause');
  console.log('================================================================================');

  for (const tid of targets) {
    const success = engine.pauseSwitch(tid, durationMs, reason);
    if (success) {
      const untilStr = durationMs ? new Date(Date.now() + durationMs).toLocaleString() : 'Indefinite (until obold resume)';
      console.log(`✓ Switch "${tid}" PAUSED until: ${untilStr}`);
      if (reason) console.log(`  Reason: ${reason}`);
    } else {
      console.error(`❌ Failed to pause switch "${tid}": Switch not found.`);
    }
  }
  console.log('================================================================================\n');

  cipher.destroy();
  db.close();
}

async function handleResumeCommand(args: string[]) {
  const switchId = args[0];
  const isAll = args.includes('--all') || switchId === 'all';
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';

  if (!switchId && !isAll) {
    console.error('\n❌ Usage: obold resume <switch-id> [--all]');
    console.error('Example: obold resume main-vault\n');
    return;
  }

  if (!existsSync(configPath)) {
    console.error(`\n❌ Configuration file not found at: ${configPath}`);
    return;
  }

  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher();
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  const targets = isAll ? config.switches.map((s) => s.id) : [switchId];
  console.log('\n================================================================================');
  console.log('▶️  obold Switch Active Countdown Resume');
  console.log('================================================================================');

  for (const tid of targets) {
    const success = engine.resumeSwitch(tid);
    if (success) {
      const sw = db.getSwitch(tid);
      console.log(`✓ Switch "${tid}" RESUMED. Active deadline: ${sw ? new Date(sw.next_deadline_at).toLocaleString() : 'Active'}`);
    } else {
      console.error(`❌ Failed to resume switch "${tid}": Switch not found.`);
    }
  }
  console.log('================================================================================\n');

  cipher.destroy();
  db.close();
}

async function handleAbortCommand(args: string[]) {
  const switchId = args[0];
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';
  const reason = getArgValue(args, '--reason') || getArgValue(args, '-r') || 'Manual operator abort via CLI';

  if (!switchId) {
    console.error('\n❌ Usage: obold abort <switch-id> [--reason <reason>] [--config <path>]');
    console.error('Example: obold abort main-vault --reason "False alarm / operator recovery"\n');
    return;
  }

  if (!existsSync(configPath)) {
    console.error(`\n❌ Configuration file not found at: ${configPath}`);
    return;
  }

  const masterKey = resolveMasterKey(args);
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, false);
  const cipher = new OboldCipher(masterKey);
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  const ok = engine.abortSwitch(switchId, reason);
  if (ok) {
    console.log('\n================================================================================');
    console.log(`🛑 EMERGENCY CASCADE ABORT ENGAGED`);
    console.log('================================================================================');
    console.log(`✓ Switch "${switchId}" status set to ABORTED.`);
    console.log(`✓ Pending cascade stages and unacknowledged retries HALTED.`);
    console.log(`✓ Reason: ${reason}`);
    console.log('================================================================================\n');
  } else {
    console.error(`\n❌ Failed to abort switch "${switchId}": Switch not found.\n`);
  }

  cipher.destroy();
  db.close();
}

function handleServiceCommand(args: string[]) {
  const sub = args[0] || 'help';
  const isSystem = args.includes('--system');
  const dryRun = args.includes('--dry-run');
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';
  const outPath = getArgValue(args, '--out') || getArgValue(args, '-o');
  const masterKey = resolveMasterKey(args);

  if (sub === 'install') {
    console.log('\n⚙️  Installing obold daemon as background service...');
    const res = installService({
      configPath,
      isSystem,
      dryRun,
      masterKey,
    });
    if (res.success) {
      console.log(`✓ ${res.message || 'Service installed successfully.'}`);
      if (res.servicePath) console.log(`  Path: ${res.servicePath}`);
    } else {
      console.error(`\n❌ Installation Error: ${res.error}`);
    }
    console.log('');
  } else if (sub === 'uninstall') {
    console.log('\n⚙️  Removing obold daemon background service...');
    const res = uninstallService({
      isSystem,
    });
    if (res.success) {
      console.log(`✓ ${res.message || 'Service removed successfully.'}`);
    } else {
      console.error(`\n❌ Uninstallation Error: ${res.error}`);
    }
    console.log('');
  } else if (sub === 'generate') {
    const type = (getArgValue(args, '--type') || (process.platform === 'darwin' ? 'launchd' : 'systemd')) as 'systemd' | 'launchd';
    const content = type === 'systemd'
      ? generateSystemdService({ configPath, masterKey })
      : generateLaunchdPlist({ configPath, masterKey });

    if (outPath) {
      writeFileSync(outPath, content, 'utf-8');
      console.log(`\n✓ Generated ${type} service configuration file: ${outPath}\n`);
    } else {
      console.log('\n================================================================================');
      console.log(`📄 Generated ${type.toUpperCase()} Daemon Unit`);
      console.log('================================================================================');
      console.log(content.trim());
      console.log('================================================================================\n');
    }
  } else {
    console.log(`
Usage:
  obold service install [--system] [--config <path>] [--dry-run]
  obold service uninstall [--system]
  obold service generate [--type systemd|launchd] [--config <path>] [--out <path>]
`);
  }
}

async function handleTopCommand(args: string[]) {
  const configPath = getArgValue(args, '--config') || getArgValue(args, '-c') || './obold.yaml';
  if (!existsSync(configPath)) {
    console.error(`\n❌ Configuration file not found at: ${configPath}`);
    return;
  }

  const masterKey = resolveMasterKey(args);
  const config = loadConfigFile(configPath);
  const db = new OboldDatabase(config.storage.path, true);
  const cipher = new OboldCipher(masterKey);
  const plugins = createDefaultPluginRegistry();
  const engine = new OboldEngine(config, db, cipher, plugins);

  await startInteractiveMonitor({
    engine,
    db,
    refreshIntervalMs: 1000,
  });
}

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return undefined;
}

function printHelp(): void {
  console.log(`
🪙  obold (Beta) — Sovereign Emergency Continuity & Dead Man's Switch Daemon
    A Source-Available Sovereign Standard by BCN Studio (https://bcnstudio.tech)

USAGE:
  obold <command> [options]

COMMANDS:
  run                         Start the dead man switch daemon and embedded web dashboard
  doctor                      Run comprehensive environment and diagnostics check
  top, monitor                Launch real-time interactive terminal dashboard monitor
  status                      View current switch countdowns, deadlines, and status
  init                        Generate a starter obold.yaml configuration file
  checkin <switch-id>         Check in to extend a switch countdown timer
  pause <switch-id>           Suspend countdown for vacation or maintenance
  resume <switch-id>          Resume active dead man switch countdown timer
  abort <switch-id>           Engage emergency abort to halt switch cascade execution
  trigger <switch-id>         Trip a switch manually or test with --dry-run
  rekey                       Rotate master encryption key and re-encrypt all SQLite records
  rescue generate             Generate standalone offline HTML emergency rescue bundle for heirs
  rescue verify <file>        Cryptographically inspect and verify offline rescue bundle manifest
  service install             Install and enable 24/7 background systemd/launchd daemon service
  service uninstall           Remove installed background service
  service generate            Generate systemd unit or launchd plist configuration file
  secret split                Split a master passphrase into k-of-n Shamir shares
  secret combine <shares...>  Reconstruct secret from Shamir shares
  token generate <switch-id>  Generate a single-use 1-click check-in link
  plugin list                 List all registered plugins
  plugin new <name>           Scaffold a new community plugin template (ts/python/sh)
  update                      Check for updates and download latest release
  version                     Print version information

OPTIONS:
  -c, --config <path>         Path to obold configuration file (default: ./obold.yaml)
  -p, --port <port>           Web dashboard port (default: 8080)
  --key-file <path>           Path to master encryption key file
  --old-key-file <path>       Path to file containing previous master key for rekeying
  --new-key-file <path>       Path to file containing new master key for rekeying
  --system                    Install/uninstall as root/system service instead of user
  --duration, -d <time>       Pause duration (e.g. 7d, 14d, 48h, 30m)
  --reason, -r <text>         Reason for vacation/maintenance pause
  --all                       Apply pause or resume across all configured switches
  --payload, -p <text>        Plaintext payload for rescue bundle
  --file, -f <path>           File payload for rescue bundle or secret split
  --out, -o <path>            Output destination file
  --dry-run                   Simulate execution without firing external network/shell actions
  --duress                    Trigger silent distress beacon check-in
  --total <N>                 Total shares to generate in Shamir split (default: 5)
  --threshold <K>             Threshold shares required to combine (default: 3)
  --ttl <days>                Validity duration in days for token (default: 30)
`);
}
