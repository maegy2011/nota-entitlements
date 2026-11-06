"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DiskFullError = exports.FilesystemBackend = exports.MAX_FILE_BYTES = exports.PRO_QUOTA_BYTES = exports.FREE_QUOTA_BYTES = exports.BLOBS_DIR = void 0;
exports.sha256Hex = sha256Hex;
exports.blobKey = blobKey;
exports.ensureDiskSpace = ensureDiskSpace;
exports.quotaPacksBytes = quotaPacksBytes;
exports.quotaForAccount = quotaForAccount;
exports.quotaFromFeatures = quotaFromFeatures;
const node_crypto_1 = require("node:crypto");
const promises_1 = require("node:fs/promises");
const node_fs_1 = require("node:fs");
const node_path_1 = __importDefault(require("node:path"));
// Nota Cloud storage layer — Phase A: local disk. R2 later implements
// the same StorageBackend behind STORAGE_BACKEND, with identical keys.
exports.BLOBS_DIR = process.env.BLOBS_DIR ?? "/var/nota-blobs";
exports.FREE_QUOTA_BYTES = Number(process.env.FREE_QUOTA_MB ?? 100) * 1024 * 1024;
exports.PRO_QUOTA_BYTES = Number(process.env.PRO_QUOTA_MB ?? 5120) * 1024 * 1024;
exports.MAX_FILE_BYTES = Number(process.env.MAX_FILE_MB ?? 32) * 1024 * 1024;
// Refuse writes when the disk is this low — graceful 507 instead of corrupt half-files.
const DISK_FLOOR_BYTES = 256 * 1024 * 1024;
function sha256Hex(data) {
    return (0, node_crypto_1.createHash)("sha256").update(data).digest("hex");
}
/** Storage key: <accountHash>/<blobSha> — hex only, so no path traversal is possible. */
function blobKey(accountId, sha256) {
    return `${sha256Hex(accountId)}/${sha256}`;
}
class FilesystemBackend {
    root;
    constructor(root = exports.BLOBS_DIR) {
        this.root = root;
    }
    abs(accountId, sha256) {
        return node_path_1.default.join(this.root, blobKey(accountId, sha256));
    }
    async put(accountId, sha256, bytes) {
        ensureDiskSpace(bytes.length);
        const dest = this.abs(accountId, sha256);
        await (0, promises_1.mkdir)(node_path_1.default.dirname(dest), { recursive: true });
        const tmp = `${dest}.tmp-${process.pid}-${(0, node_crypto_1.randomBytes)(8).toString("hex")}`;
        await (0, promises_1.writeFile)(tmp, bytes);
        await (0, promises_1.rename)(tmp, dest);
    }
    async get(accountId, sha256) {
        try {
            return await (0, promises_1.readFile)(this.abs(accountId, sha256));
        }
        catch {
            return null;
        }
    }
    async remove(accountId, sha256) {
        await (0, promises_1.rm)(this.abs(accountId, sha256), { force: true });
    }
}
exports.FilesystemBackend = FilesystemBackend;
function ensureDiskSpace(needBytes) {
    let avail = 0;
    try {
        const st = (0, node_fs_1.statfsSync)(exports.BLOBS_DIR);
        avail = st.bavail * st.bsize;
    }
    catch {
        // Directory may not exist yet on first boot — the write will surface real errors.
        return;
    }
    if (avail - needBytes < DISK_FLOOR_BYTES) {
        throw new DiskFullError();
    }
}
class DiskFullError extends Error {
}
exports.DiskFullError = DiskFullError;
// Plan-derived quota: the base follows the subscription itself (pro -> 5G, else 100M),
// and storage_* packs always add on top. No per-user backfill needed — quota follows the plan.
const QUOTA_FEATURE_RE = /^storage_(\d+)([mg])$/i;
function quotaPacksBytes(features) {
    let sum = 0;
    for (const f of features) {
        const m = QUOTA_FEATURE_RE.exec(f.trim());
        if (!m)
            continue;
        const n = Number(m[1]);
        if (!Number.isSafeInteger(n) || n <= 0 || n > 1024)
            continue;
        sum += m[2].toLowerCase() === "g" ? n * 1024 * 1024 * 1024 : n * 1024 * 1024;
    }
    return sum;
}
function quotaForAccount(isPro, features) {
    return (isPro ? exports.PRO_QUOTA_BYTES : exports.FREE_QUOTA_BYTES) + quotaPacksBytes(features);
}
// Legacy: bare features with no plan context = free base + packs.
function quotaFromFeatures(features) {
    return quotaForAccount(false, features);
}
