/**
 * Benign host half: no fs, no child processes, no network, no dynamic code.
 * The interval exists only to prove lifecycle cleanup works under the loader.
 */
export const name = 'safe-demo';

export function apply(ctx) {
  ctx.logger.info('[safe-demo] ready');
  ctx.effect(() => {
    const timer = setInterval(() => {}, 60_000);
    return () => clearInterval(timer);
  }, 'safe-demo.timer()');
}
