// Canonical policy source. generate-kovya-budget-policy.mjs derives native constants.
export const COLD_PATH_WORK_MS = 3000;
export const WARM_WORK_MS = 1000;
export const ORDINARY_STARTUP_MS = COLD_PATH_WORK_MS;
export const WORKER_EXIT_MS = COLD_PATH_WORK_MS + 1500;
export const HOOK_FALLBACK_MS = WORKER_EXIT_MS + 500;
export const HOST_HOOK_TIMEOUT_SECONDS = Math.ceil((ORDINARY_STARTUP_MS + HOOK_FALLBACK_MS + 1000) / 1000);
