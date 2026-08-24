/**
 * Shared test utilities. Node's test runner type-strips these files, so import
 * specifiers carry the real `.ts` extension.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** A minimal stand-in for `ctx` that records handler registrations. */
export interface FakeCtx {
  handlers: Map<string, Array<(...args: unknown[]) => void>>;
  tools: {
    register(def: { name: string }): () => void;
    schemas(): Array<{ name: string }>;
  };
  logger: (name: string) => { warn(...args: unknown[]): void };
  on(event: string, handler: (...args: unknown[]) => void): () => void;
  emit(event: string, ...args: unknown[]): void;
  registeredTools: string[];
  lifecycles: Array<() => void>;
}

/** Build a fresh fake context with an event bus and tool registry. */
export function makeFakeCtx(): FakeCtx {
  const handlers = new Map<string, Array<(...args: unknown[]) => void>>();
  const registeredTools: string[] = [];
  const lifecycles: Array<() => void> = [];
  const ctx: FakeCtx = {
    handlers,
    registeredTools,
    lifecycles,
    tools: {
      register(def) {
        registeredTools.push(def.name);
        return () => undefined;
      },
      schemas() {
        return registeredTools.map((name) => ({ name }));
      },
    },
    logger: () => ({
      warn: (..._args: unknown[]) => undefined,
    }),
    on(event, handler) {
      if (event === 'dispose') {
        lifecycles.push(() => handler());
        return () => undefined;
      }
      const list = handlers.get(event) ?? [];
      list.push(handler);
      handlers.set(event, list);
      return () => undefined;
    },
    emit(event, ...args) {
      for (const handler of handlers.get(event) ?? []) handler(...args);
    },
  };
  return ctx;
}

/** A writable scratch SQLite path under the OS temp dir. */
export function tempFilePath(ext = 'sqlite'): string {
  const dir = mkdtempSync(join(tmpdir(), 'auditrail-test-'));
  return join(dir, `scratch.${ext}`);
}
