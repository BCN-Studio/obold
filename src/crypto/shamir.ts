import { randomBytes, createHash } from 'node:crypto';

const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256);

(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;

    let next = (x << 1) ^ x;
    if (next & 0x100) next ^= 0x11b;
    x = next & 0xff;
  }
  for (let i = 255; i < 512; i++) {
    EXP_TABLE[i] = EXP_TABLE[i - 255];
  }
  LOG_TABLE[0] = 0;
})();

function gfMultiply(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
}

function gfDivide(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(2^8)');
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
}

function evalPolynomial(coefficients: number[], x: number): number {
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfMultiply(result, x) ^ coefficients[i];
  }
  return result;
}

export class ShamirSecretSharing {
  public static split(secret: string | Buffer, totalShares: number, threshold: number): string[] {
    if (threshold < 2) throw new Error('Threshold K must be at least 2.');
    if (totalShares < threshold) throw new Error('Total shares N must be >= threshold K.');
    if (totalShares > 255) throw new Error('Total shares N cannot exceed 255.');

    const secretBytes = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'utf-8');
    const sharesY: number[][] = Array.from({ length: totalShares }, () => []);
    const setId = randomBytes(4).toString('hex');

    for (let byteIndex = 0; byteIndex < secretBytes.length; byteIndex++) {
      const secretByte = secretBytes[byteIndex];
      const coefficients = [secretByte];

      const randomCoefs = randomBytes(threshold - 1);
      for (let i = 0; i < threshold - 1; i++) {
        coefficients.push(randomCoefs[i] || 1);
      }

      for (let shareIndex = 0; shareIndex < totalShares; shareIndex++) {
        const x = shareIndex + 1;
        const y = evalPolynomial(coefficients, x);
        sharesY[shareIndex].push(y);
      }
    }

    return sharesY.map((yVals, idx) => {
      const x = idx + 1;
      const hex = Buffer.from(yVals).toString('hex');
      const checksum = createHash('sha256')
        .update(`${setId}:${threshold}:${totalShares}:${x}:${hex}`)
        .digest('hex')
        .substring(0, 8);
      return `obold-shamir-v1-${setId}-${threshold}-of-${totalShares}-${x}-${hex}-${checksum}`;
    });
  }

  public static combine(shares: string[]): string {
    if (!shares || shares.length === 0) {
      throw new Error('At least one share is required.');
    }

    const parsedShares: { x: number; y: number[]; setId?: string }[] = [];
    const seenX = new Set<number>();
    let expectedThreshold = 0;
    let commonSetId: string | null = null;

    for (const shareStr of shares) {
      const trimmed = shareStr.trim();
      const v1Match = trimmed.match(/^obold-shamir-v1-([0-9a-fA-F]{8})-(\d+)-of-(\d+)-(\d+)-([0-9a-fA-F]+)-([0-9a-fA-F]{8})$/);
      const legacyMatch = trimmed.match(/^obold-share-(\d+)-of-(\d+)-(\d+)-([0-9a-fA-F]+)$/);

      if (!v1Match && !legacyMatch) {
        throw new Error(`Invalid share string format: "${shareStr}".`);
      }

      let setId: string | undefined;
      let t: number;
      let totalN: number;
      let xVal: number;
      let hexData: string;

      if (v1Match) {
        setId = v1Match[1];
        t = parseInt(v1Match[2], 10);
        totalN = parseInt(v1Match[3], 10);
        xVal = parseInt(v1Match[4], 10);
        hexData = v1Match[5];
        const checksum = v1Match[6];

        const expectedChecksum = createHash('sha256')
          .update(`${setId}:${t}:${totalN}:${xVal}:${hexData}`)
          .digest('hex')
          .substring(0, 8);

        if (checksum.toLowerCase() !== expectedChecksum.toLowerCase()) {
          throw new Error(`Invalid share checksum for share ${xVal}: share data corrupted or tampered.`);
        }

        if (commonSetId === null) {
          commonSetId = setId;
        } else if (commonSetId !== setId) {
          throw new Error(`Mismatched share sets: share ${xVal} belongs to set ${setId} but expected ${commonSetId}.`);
        }
      } else {
        t = parseInt(legacyMatch![1], 10);
        xVal = parseInt(legacyMatch![3], 10);
        hexData = legacyMatch![4];
      }

      if (seenX.has(xVal)) {
        continue;
      }
      seenX.add(xVal);
      expectedThreshold = t;

      const yVals = Array.from(Buffer.from(hexData, 'hex'));
      parsedShares.push({ x: xVal, y: yVals, setId });
    }

    if (parsedShares.length < expectedThreshold) {
      throw new Error(
        `Insufficient shares provided. Needed ${expectedThreshold}, but received ${parsedShares.length} unique shares.`
      );
    }

    const subset = parsedShares.slice(0, expectedThreshold);
    const secretLength = subset[0].y.length;
    const reconstructedBytes = Buffer.alloc(secretLength);

    for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
      let secretByte = 0;

      for (let i = 0; i < subset.length; i++) {
        const xi = subset[i].x;
        const yi = subset[i].y[byteIndex];

        let basis = 1;
        for (let j = 0; j < subset.length; j++) {
          if (i === j) continue;
          const xj = subset[j].x;
          const numerator = xj;
          const denominator = xi ^ xj;
          basis = gfMultiply(basis, gfDivide(numerator, denominator));
        }

        secretByte ^= gfMultiply(yi, basis);
      }

      reconstructedBytes[byteIndex] = secretByte;
    }

    return reconstructedBytes.toString('utf-8');
  }
}
