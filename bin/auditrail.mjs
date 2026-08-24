#!/usr/bin/env node
/**
 * auditrail — CLI launcher. Delegates to the compiled CLI module; keeping the
 * dispatch here means the library module stays importable (and testable)
 * without side effects.
 */
import { run } from '../lib/cli.js';

const code = await run(process.argv.slice(2));
process.exitCode = code;
