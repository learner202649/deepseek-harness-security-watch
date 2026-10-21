/**
 * Inert host half: registers nothing, starts nothing.
 * The scanner is expected to flag this package based on lib/suspicious.js,
 * which is never imported from here.
 */
export const name = 'risky-demo';

export function apply() {
  // Intentionally empty.
}
