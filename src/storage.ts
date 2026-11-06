import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { statfsSync } from "node:fs";
import path from "node:path";

// Nota Cloud storage layer — Phase A: local disk. R2 later implements
// the same StorageBackend behind STORAGE_BACKEND, with identical keys.

export const BLOBS_DIR = process.env.BLOBS_DIR ?? "/var/nota-blobs";
export const FREE_QUOTA_BYTES = Number(process.env.FREE_QUOTA_MB ?? 100) * 1024 * 1024;
export const PRO_QUOTA_BYTES = Number(process.env.PRO_QUOTA_MB ?? 5120) * 1024 * 1024;
export const MAX_FILE_BYTES = Number(process.env.MAX_FILE_MB ?? 32) * 1024 * 1024;
// Refuse writes when the disk is this low — graceful 507 instead of corrupt half-files.
const DISK_FLOOR_BYTES = 256 * 1024 * 1024;

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Storage key: <accountHash>/<blobSha> — hex only, so no path traversal is possible. */
export function blobKey(accountId: string, sha256: string): string {
  return `${sha256Hex(accountId)}/${sha256}`;
}

export interface StorageBackend {
  put(accountId: string, sha256: string, bytes: Buffer): Promise<void>;
  get(accountId: string, sha256: string): Promise<Buffer | null>;
  remove(accountId: string, sha256: string): Promise<void>;
}

export class FilesystemBackend implements StorageBackend {
  constructor(private readonly root: string = BLOBS_DIR) {}

  private abs(accountId: string, sha256: string): string {
    return path.join(this.root, blobKey(accountId, sha256));
  }

  async put(accountId: string, sha256: string, bytes: Buffer): Promise<void> {
    ensureDiskSpace(bytes.length);
    const dest = this.abs(accountId, sha256);
    await mkdir(path.dirname(dest), { recursive: true });
    const tmp = `${dest}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
    await writeFile(tmp, bytes);
    await rename(tmp, dest);
  }

  async get(accountId: string, sha256: string): Promise<Buffer | null> {
    try {
      return await readFile(this.abs(accountId, sha256));
    } catch {
      return null;
    }
  }

  async remove(accountId: string, sha256: string): Promise<void> {
    await rm(this.abs(accountId, sha256), { force: true });
  }
}

export function ensureDiskSpace(needBytes: number): void {
  let avail = 0;
  try {
    const st = statfsSync(BLOBS_DIR);
    avail = st.bavail * st.bsize;
  } catch {
    // Directory may not exist yet on first boot — the write will surface real errors.
    return;
  }
  if (avail - needBytes < DISK_FLOOR_BYTES) {
    throw new DiskFullError();
  }
}

export class DiskFullError extends Error {}

// Plan-derived quota: the base follows the subscription itself (pro -> 5G, else 100M),
// and storage_* packs always add on top. No per-user backfill needed — quota follows the plan.
const QUOTA_FEATURE_RE = /^storage_(\d+)([mg])$/i;

export function quotaPacksBytes(features: string[]): number {
  let sum = 0;
  for (const f of features) {
    const m = QUOTA_FEATURE_RE.exec(f.trim());
    if (!m) continue;
    const n = Number(m[1]);
    if (!Number.isSafeInteger(n) || n <= 0 || n > 1024) continue;
    sum += m[2].toLowerCase() === "g" ? n * 1024 * 1024 * 1024 : n * 1024 * 1024;
  }
  return sum;
}

export function quotaForAccount(isPro: boolean, features: string[]): number {
  return (isPro ? PRO_QUOTA_BYTES : FREE_QUOTA_BYTES) + quotaPacksBytes(features);
}

// Legacy: bare features with no plan context = free base + packs.
export function quotaFromFeatures(features: string[]): number {
  return quotaForAccount(false, features);
}
