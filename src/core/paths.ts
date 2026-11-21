import { homedir } from 'node:os';
import { join } from 'node:path';

/** Where Oculon keeps its database and files: OCULON_HOME, default ~/.oculon. */
export function oculonHome(): string {
  return process.env.OCULON_HOME || join(homedir(), '.oculon');
}
