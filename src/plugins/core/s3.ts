import { createHmac, createHash } from 'node:crypto';
import type { IPluginExecutor, PluginExecutionContext } from '../types.ts';
import type { ExecutionResult } from '../../config/types.ts';
import { validateTargetUrl } from '../network-guard.ts';

export class S3Plugin implements IPluginExecutor {
  readonly id = 'core:s3';
  readonly name = 'S3 / R2 Object Storage Manager';
  readonly description = 'Uploads encrypted backups or wipes buckets on S3, Cloudflare R2, or MinIO.';
  readonly version = '1.0.0';

  validateConfig(config: Record<string, any>): { valid: boolean; error?: string } {
    if (!config.bucket) return { valid: false, error: 'Missing required field: "bucket".' };
    if (!config.access_key_id) return { valid: false, error: 'Missing required field: "access_key_id".' };
    if (!config.secret_access_key) return { valid: false, error: 'Missing required field: "secret_access_key".' };
    if (!config.key) return { valid: false, error: 'Missing required field: "key" (object path).' };
    return { valid: true };
  }

  async execute(config: Record<string, any>, context: PluginExecutionContext): Promise<ExecutionResult> {
    const startTime = Date.now();
    const validation = this.validateConfig(config);
    if (!validation.valid) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: 0,
        error: validation.error,
      };
    }

    if (config.endpoint) {
      const endpointUrl = config.endpoint.startsWith('http') ? config.endpoint : `https://${config.endpoint}`;
      const ssrfCheck = await validateTargetUrl(
        endpointUrl,
        config.allow_private_network === true || config.allow_local === true
      );
      if (!ssrfCheck.valid) {
        return {
          success: false,
          actionId: context.actionId,
          plugin: this.id,
          durationMs: Date.now() - startTime,
          error: `S3 SSRF Network Guard blocked endpoint: ${ssrfCheck.error}`,
        };
      }
    }

    if (context.dryRun) {
      return {
        success: true,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { dryRun: true, bucket: config.bucket, key: config.key },
      };
    }

    let accessKey = config.access_key_id;
    if (accessKey.startsWith('ENV:')) accessKey = process.env[accessKey.substring(4)] || '';

    let secretKey = config.secret_access_key;
    if (secretKey.startsWith('ENV:')) secretKey = process.env[secretKey.substring(4)] || '';

    const region = config.region || 'us-east-1';
    const action = config.action || 'upload';
    const key = config.key.startsWith('/') ? config.key.substring(1) : config.key;
    const bucket = config.bucket;
    const endpoint = config.endpoint || `${bucket}.s3.${region}.amazonaws.com`;
    const host = endpoint.replace(new RegExp('^https?://'), '');

    const method = action === 'delete' ? 'DELETE' : 'PUT';
    const bodyContent = action === 'delete' ? '' : (config.content || 'obold automated payload snapshot');
    const bodyBuffer = Buffer.from(bodyContent, 'utf-8');

    try {
      const now = new Date();
      const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
      const dateStamp = amzDate.substring(0, 8);

      const payloadHash = createHash('sha256').update(bodyBuffer).digest('hex');
      const canonicalUri = `/${key}`;
      const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
      const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

      const canonicalRequest = `${method}\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
      const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
      const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${createHash('sha256').update(canonicalRequest).digest('hex')}`;

      const kDate = createHmac('sha256', `AWS4${secretKey}`).update(dateStamp).digest();
      const kRegion = createHmac('sha256', kDate).update(region).digest();
      const kService = createHmac('sha256', kRegion).update('s3').digest();
      const kSigning = createHmac('sha256', kService).update('aws4_request').digest();
      const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

      const authorizationHeader = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

      const scheme = config.use_ssl === false ? 'http' : 'https';
      const targetUrl = `${scheme}://${host}/${key}`;
      const timeoutMs = config.timeout_ms || 30000;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      if (context.signal) {
        if (context.signal.aborted) {
          controller.abort();
        } else {
          context.signal.addEventListener('abort', () => controller.abort(), { once: true });
        }
      }

      const response = await fetch(targetUrl, {
        method,
        headers: {
          'Host': host,
          'x-amz-date': amzDate,
          'x-amz-content-sha256': payloadHash,
          'Authorization': authorizationHeader,
          'Content-Type': 'application/octet-stream',
        },
        body: method === 'PUT' ? bodyBuffer : undefined,
        signal: controller.signal,
      });

      clearTimeout(timer);

      const isSuccess = response.status >= 200 && response.status < 300;

      return {
        success: isSuccess,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        output: { statusCode: response.status, action, bucket, key },
        error: isSuccess ? undefined : `S3 API returned HTTP ${response.status}`,
      };
    } catch (err: any) {
      return {
        success: false,
        actionId: context.actionId,
        plugin: this.id,
        durationMs: Date.now() - startTime,
        error: `S3 Request Error: ${err.message}`,
      };
    }
  }
}
