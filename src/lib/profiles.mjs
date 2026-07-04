// profiles — one-flag source presets (--profile) for the product's target users.
// A profile is a THIN VENEER over the existing --dir assembly: it only RESOLVES
// a list of source paths, which snapshot() then stages exactly as explicit
// --dir flags would (one tar.gz per path — the stage tar handles files as well
// as directories). No new snapshot machinery. Explicit --dir flags compose with
// a profile: they are appended AFTER the profile's paths. Every profile fails
// fast with an actionable error when its inputs are missing, so a mistyped run
// can never produce an empty "backup".
import { readdir, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { exists } from './util.mjs';

export const PROFILE_NAMES = ['claude-code', 'obsidian', 'chatgpt-export'];

// Resolve --profile to the concrete source paths it snapshots.
export async function resolveProfilePaths(o) {
  switch (o.profile) {
    case 'claude-code': return claudeCodePaths();
    case 'obsidian': return obsidianPaths(o);
    case 'chatgpt-export': return chatgptExportPaths(o);
    default:
      throw new Error(`unknown profile "${o.profile}" — valid profiles: ${PROFILE_NAMES.join(', ')}`);
  }
}

// claude-code: every ~/.claude/projects/*/memory/ dir (per-project auto-memory)
// plus ~/.claude/CLAUDE.md (global instructions), whichever of those exist. If
// NONE exist the profile errors listing what it looked for — a silently-empty
// snapshot would be worse than a refusal. homedir() honors $HOME, so tests
// point the profile at a synthetic home by faking that env var.
async function claudeCodePaths() {
  const claude = join(homedir(), '.claude');
  const projects = join(claude, 'projects');
  const claudeMd = join(claude, 'CLAUDE.md');
  const paths = [];
  let entries = [];
  try { entries = await readdir(projects, { withFileTypes: true }); } catch { /* no projects dir — CLAUDE.md may still exist */ }
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!e.isDirectory()) continue;
    const mem = join(projects, e.name, 'memory');
    if (await exists(mem)) paths.push(mem);
  }
  if (await exists(claudeMd)) paths.push(claudeMd);
  if (paths.length === 0) {
    throw new Error(`profile claude-code found nothing to snapshot — looked for ${join(projects, '*', 'memory')} and ${claudeMd}`);
  }
  return paths;
}

// obsidian: the vault directory, whole. A real vault contains .obsidian/; a
// path without it is probably a typo (snapshotting the wrong tree feels like
// success until restore day), so refuse unless --force-vault says "I know".
async function obsidianPaths(o) {
  if (!o.vault) throw new Error('profile obsidian requires --vault <path> (the vault directory)');
  const vault = resolve(o.vault);
  const st = await stat(vault).catch(() => null);
  if (!st) throw new Error(`no vault at ${vault} — profile obsidian snapshots the vault directory`);
  if (!st.isDirectory()) throw new Error(`${vault} is not a directory — profile obsidian expects the vault directory`);
  if (!(await exists(join(vault, '.obsidian'))) && !o.force_vault) {
    throw new Error(`${vault} does not look like an Obsidian vault (no .obsidian/ inside) — pass --force-vault to snapshot it anyway`);
  }
  return [vault];
}

// chatgpt-export: the official ChatGPT data-export zip, taken AS-IS. It is
// archived as one component file and never extracted, so the restored zip is
// byte-identical to what ChatGPT handed out.
async function chatgptExportPaths(o) {
  if (!o.zip) throw new Error('profile chatgpt-export requires --zip <path> (the official ChatGPT export zip)');
  const zip = resolve(o.zip);
  const st = await stat(zip).catch(() => null);
  if (!st || !st.isFile()) throw new Error(`no export zip at ${zip} — profile chatgpt-export takes the official ChatGPT export zip`);
  if (!zip.endsWith('.zip')) throw new Error(`${zip} does not end in .zip — profile chatgpt-export takes the official export zip as-is (not an extracted tree; use --dir for that)`);
  return [zip];
}
