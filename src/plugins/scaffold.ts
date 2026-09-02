import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export function scaffoldPlugin(name: string, lang: 'ts' | 'python' | 'sh' = 'ts', outDir: string = './plugins'): string {
  const pluginDir = join(outDir, name);
  if (!existsSync(pluginDir)) {
    mkdirSync(pluginDir, { recursive: true });
  }

  const manifest = {
    id: `community:${name}`,
    name: name.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
    version: '1.0.0',
    description: `Community plugin for ${name}`,
    author: 'Community Contributor',
    entrypoint: lang === 'python' ? 'plugin.py' : lang === 'sh' ? 'plugin.sh' : 'index.ts',
  };

  writeFileSync(join(pluginDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf-8');

  if (lang === 'python') {
    const pythonCode = `#!/usr/bin/env python3
import sys
import json

def main():
    raw_input = sys.stdin.read()
    if not raw_input:
        print(json.dumps({"success": False, "error": "No input received"}))
        return
    
    req = json.loads(raw_input)
    config = req.get("params", {}).get("config", {})
    context = req.get("params", {}).get("context", {})
    
    print(json.dumps({
        "success": True,
        "output": {
            "message": "Custom python plugin executed successfully!",
            "switch_id": context.get("switchId")
        }
    }))

if __name__ == "__main__":
    main()
`;
    writeFileSync(join(pluginDir, 'plugin.py'), pythonCode, 'utf-8');
  } else if (lang === 'sh') {
    const shCode = `#!/usr/bin/env bash
read -r JSON_INPUT
echo '{"success": true, "output": {"message": "Custom shell plugin executed successfully"}}'
`;
    writeFileSync(join(pluginDir, 'plugin.sh'), shCode, 'utf-8');
  } else {
    const tsCode = `import type { IPluginExecutor, PluginExecutionContext } from '../../src/plugins/types.ts';
import type { ExecutionResult } from '../../src/config/types.ts';

export class CustomPlugin implements IPluginExecutor {
  readonly id = 'community:${name}';
  readonly name = '${name}';
  readonly description = 'Community plugin for ${name}';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>) {
    return { valid: true };
  }

  async execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> {
    return {
      success: true,
      actionId: context.actionId,
      plugin: this.id,
      durationMs: 10,
      output: { message: '${name} executed successfully' }
    };
  }
}
`;
    writeFileSync(join(pluginDir, 'index.ts'), tsCode, 'utf-8');
  }

  return pluginDir;
}
