"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.trialGrantFor = trialGrantFor;
const INACTIVE = { active: false, features: [], expiresAt: null };
const ACCOUNT_RE = /^[A-Za-z0-9._@|-]{1,128}$/;
// Beta-only trial grant for exactly one account. Everything is server-side:
// the client never sees the allowlist, and a missing/malformed/expired grant
// fails closed to a normal non-pro account.
function trialGrantFor(accountId) {
    const configured = (process.env.TRIAL_ACCOUNT_ID ?? "").trim();
    if (configured.length === 0 || !ACCOUNT_RE.test(configured))
        return INACTIVE;
    if (accountId !== configured)
        return INACTIVE;
    const expiresAt = Date.parse((process.env.TRIAL_EXPIRES_AT ?? "").trim());
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now())
        return INACTIVE;
    const defaultFeatures = [
        "folders",
        "location",
        "tags",
        "reminders",
        "pdf",
        "lock",
        "favorites",
        "pin",
        "widget",
        "cloud",
        "backgrounds",
        "media",
        "shred",
    ];
    const features = (process.env.TRIAL_FEATURES ?? defaultFeatures.join(","))
        .split(",")
        .map((f) => f.trim())
        .filter((f) => f.length >= 1 && f.length <= 64)
        .slice(0, 32);
    return {
        active: true,
        features: features.length > 0 ? features : defaultFeatures,
        expiresAt: new Date(expiresAt).toISOString(),
    };
}
