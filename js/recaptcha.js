/* ============================================================
   reCAPTCHA removed — stubs kept so no import sites break.
   Both functions resolve immediately with safe no-op values.
   ============================================================ */

/** Always returns null — callers already handle null gracefully. */
export async function getToken(_action = 'DEFAULT') {
  return null;
}

/** Always returns success — no server round-trip needed. */
export async function verifyWithServer(_token, _action = 'DEFAULT') {
  return { success: true };
}
