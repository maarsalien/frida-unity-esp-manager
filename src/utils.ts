import { log } from './Logger.js';

export function sleep(ms: number): Promise<number> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function getScreenResolution(): [number, number] {
  const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  const display = context.getResources().getDisplayMetrics();

  return [display.widthPixels.value, display.heightPixels.value];
}

export async function getActivity(activityName: string) {
  let activity: Java.Wrapper | undefined;

  Java.choose(activityName, {
    onMatch(instance) {
      activity = instance;
    },
    onComplete() {},
  });

  return activity;
}

export async function ensureModulesInitialized(...modules: string[]) {
  while (modules.length > 0) {
    const md = modules.pop();
    if (!md) return;

    if (!Module.findBaseAddress(md)) {
      log(`Waiting for ${md} to be initialized...`);
      await sleep(100);
      modules.push(md);
    }
  }
}
