import { resolve, dirname } from 'node:path';
import { existsSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import os from 'node:os';

export interface ServiceGeneratorOptions {
  binPath?: string;
  configPath?: string;
  workingDir?: string;
  user?: string;
  logDir?: string;
  masterKey?: string;
}

export interface ServiceInstallOptions extends ServiceGeneratorOptions {
  isSystem?: boolean;
  dryRun?: boolean;
  type?: 'systemd' | 'launchd' | 'auto';
}

export interface ServiceResult {
  success: boolean;
  type: 'systemd' | 'launchd' | 'unsupported';
  servicePath?: string;
  content?: string;
  message?: string;
  error?: string;
}

function sanitizePath(p?: string, fallback: string = ''): string {
  if (!p) return resolve(fallback);
  if (p.startsWith('/') && !p.includes(':')) return p;
  return resolve(p);
}

export function generateSystemdService(options: ServiceGeneratorOptions): string {
  const binPath = sanitizePath(options.binPath, process.execPath);
  const configPath = sanitizePath(options.configPath, './obold.yaml');
  const workingDir = sanitizePath(options.workingDir, process.cwd());
  const user = options.user || os.userInfo().username || 'root';

  const envLines: string[] = [];
  if (options.masterKey) {
    envLines.push(`Environment="OBOLD_MASTER_KEY=${options.masterKey}"`);
  }

  return `[Unit]
Description=obold — Sovereign Emergency Continuity & Dead Man's Switch Daemon
Documentation=https://bcnstudio.tech https://github.com/BCN-Studio/obold
After=network.target network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
Type=simple
User=${user}
WorkingDirectory=${workingDir}
ExecStart=${binPath} run --config ${configPath}
Restart=always
RestartSec=5s
TimeoutStopSec=30s
KillMode=mixed
LimitNOFILE=65536
Environment=NODE_ENV=production
${envLines.join('\n')}

[Install]
WantedBy=multi-user.target
`;
}

export function generateLaunchdPlist(options: ServiceGeneratorOptions): string {
  const binPath = sanitizePath(options.binPath, process.execPath);
  const configPath = sanitizePath(options.configPath, './obold.yaml');
  const workingDir = sanitizePath(options.workingDir, process.cwd());
  const homeDir = os.homedir();
  const logDir = sanitizePath(options.logDir, `${homeDir}/Library/Logs/obold`);

  const envDict = options.masterKey ? `
    <key>EnvironmentVariables</key>
    <dict>
        <key>OBOLD_MASTER_KEY</key>
        <string>${escapeXml(options.masterKey)}</string>
        <key>NODE_ENV</key>
        <string>production</string>
    </dict>` : `
    <key>EnvironmentVariables</key>
    <dict>
        <key>NODE_ENV</key>
        <string>production</string>
    </dict>`;

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>tech.bcnstudio.obold</string>
    <key>ProgramArguments</key>
    <array>
        <string>${escapeXml(binPath)}</string>
        <string>run</string>
        <string>--config</string>
        <string>${escapeXml(configPath)}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${escapeXml(workingDir)}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>${envDict}
    <key>StandardOutPath</key>
    <string>${escapeXml(logDir)}/obold.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${escapeXml(logDir)}/obold.stderr.log</string>
</dict>
</plist>
`;
}

export function getServiceTargetPath(isSystem: boolean, platform: string = process.platform): { type: 'systemd' | 'launchd' | 'unsupported'; path: string } {
  const homeDir = os.homedir();

  if (platform === 'darwin') {
    const launchAgentsDir = `${homeDir}/Library/LaunchAgents`;
    return {
      type: 'launchd',
      path: isSystem ? '/Library/LaunchDaemons/tech.bcnstudio.obold.plist' : `${launchAgentsDir}/tech.bcnstudio.obold.plist`,
    };
  }

  if (platform === 'linux') {
    const userSystemdDir = `${homeDir}/.config/systemd/user`;
    return {
      type: 'systemd',
      path: isSystem ? '/etc/systemd/system/obold.service' : `${userSystemdDir}/obold.service`,
    };
  }

  return {
    type: 'unsupported',
    path: '',
  };
}

export function installService(options: ServiceInstallOptions): ServiceResult {
  const platform = process.platform;
  const target = getServiceTargetPath(options.isSystem ?? false, platform);

  if (target.type === 'unsupported') {
    return {
      success: false,
      type: 'unsupported',
      error: `Automated service installation is supported on Linux (systemd) and macOS (launchd). On Windows, run "obold run" directly or via NSSM/Task Scheduler.`,
    };
  }

  const content = target.type === 'systemd'
    ? generateSystemdService(options)
    : generateLaunchdPlist(options);

  if (options.dryRun) {
    return {
      success: true,
      type: target.type,
      servicePath: target.path,
      content,
      message: `[DRY-RUN] Would write service unit to: ${target.path}`,
    };
  }

  try {
    const parentDir = dirname(target.path);
    if (!existsSync(parentDir)) {
      mkdirSync(parentDir, { recursive: true });
    }

    if (target.type === 'launchd') {
      const logDir = resolve(options.logDir || `${os.homedir()}/Library/Logs/obold`);
      if (!existsSync(logDir)) {
        mkdirSync(logDir, { recursive: true });
      }
    }

    writeFileSync(target.path, content, 'utf-8');

    if (target.type === 'systemd') {
      const isSystem = options.isSystem ?? false;
      const cmdPrefix = isSystem ? 'systemctl' : 'systemctl --user';
      try {
        execSync(`${cmdPrefix} daemon-reload`);
        execSync(`${cmdPrefix} enable --now obold.service`);
      } catch (cmdErr: any) {
        return {
          success: true,
          type: 'systemd',
          servicePath: target.path,
          content,
          message: `Unit file written to ${target.path}. Run "${cmdPrefix} daemon-reload && ${cmdPrefix} enable --now obold" to activate.`,
        };
      }
    } else if (target.type === 'launchd') {
      try {
        execSync(`launchctl unload "${target.path}" 2>/dev/null || true`);
        execSync(`launchctl load -w "${target.path}"`);
      } catch (cmdErr: any) {
        return {
          success: true,
          type: 'launchd',
          servicePath: target.path,
          content,
          message: `Plist written to ${target.path}. Run "launchctl load -w ${target.path}" to activate.`,
        };
      }
    }

    return {
      success: true,
      type: target.type,
      servicePath: target.path,
      content,
      message: `Successfully installed and started obold background service (${target.type}).`,
    };
  } catch (err: any) {
    return {
      success: false,
      type: target.type,
      servicePath: target.path,
      error: `Failed to install service: ${err.message}`,
    };
  }
}

export function uninstallService(options: ServiceInstallOptions): ServiceResult {
  const platform = process.platform;
  const target = getServiceTargetPath(options.isSystem ?? false, platform);

  if (target.type === 'unsupported') {
    return {
      success: false,
      type: 'unsupported',
      error: `Service uninstallation is supported on Linux (systemd) and macOS (launchd).`,
    };
  }

  if (!existsSync(target.path)) {
    return {
      success: false,
      type: target.type,
      error: `Service file not found at: ${target.path}`,
    };
  }

  try {
    if (target.type === 'systemd') {
      const isSystem = options.isSystem ?? false;
      const cmdPrefix = isSystem ? 'systemctl' : 'systemctl --user';
      try {
        execSync(`${cmdPrefix} stop obold.service 2>/dev/null || true`);
        execSync(`${cmdPrefix} disable obold.service 2>/dev/null || true`);
        execSync(`${cmdPrefix} daemon-reload 2>/dev/null || true`);
      } catch {}
    } else if (target.type === 'launchd') {
      try {
        execSync(`launchctl unload -w "${target.path}" 2>/dev/null || true`);
      } catch {}
    }

    unlinkSync(target.path);

    return {
      success: true,
      type: target.type,
      servicePath: target.path,
      message: `Successfully stopped and removed obold background service from ${target.path}.`,
    };
  } catch (err: any) {
    return {
      success: false,
      type: target.type,
      servicePath: target.path,
      error: `Failed to uninstall service: ${err.message}`,
    };
  }
}

function escapeXml(unsafe: string): string {
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}
