export default class ESPManager {
  public static readonly MIN_AUTO_CLEAN_INTERVAL = 500;
  public static readonly DEFAULT_AUTO_CLEAN_INTERVAL = 1000;
  private _enemies: NativePointer[] = [];
  private autoCleanInterval: number;
  private autoCleanIntervalId: NodeJS.Timer | undefined;

  public constructor(isAutoClean = true, autoCleanInterval = ESPManager.DEFAULT_AUTO_CLEAN_INTERVAL) {
    this.autoCleanInterval = autoCleanInterval;
    if (isAutoClean) this.startAutoClean();
  }

  private set enemies(value: NativePointer[]) {
    this._enemies = value;
  }

  public get enemies() {
    return this._enemies;
  }

  public getAutoCleanInterval() {
    return this.autoCleanInterval;
  }

  public setAutoCleanInterval(intval: number): void {
    this.autoCleanInterval = Math.max(intval, ESPManager.MIN_AUTO_CLEAN_INTERVAL);
  }

  public isAutoCleanEnabled(): boolean {
    return this.autoCleanIntervalId !== undefined;
  }

  public startAutoClean(): void {
    if (this.isAutoCleanEnabled()) return;
    this.autoCleanIntervalId = setInterval(() => this.cleanEnemies(), this.autoCleanInterval);
  }

  public stopAutoClean(): void {
    if (!this.isAutoCleanEnabled()) return;
    clearInterval(this.autoCleanIntervalId);
    this.autoCleanIntervalId = undefined;
  }

  public isEnemyPresent(enemy: NativePointer): boolean {
    return this.enemies.find((e) => e.equals(enemy)) !== undefined;
  }

  public tryAddEnemy(enemy: NativePointer): boolean {
    if (enemy.isNull() || this.isEnemyPresent(enemy)) return false;
    this.enemies.push(enemy);
    return true;
  }

  public tryRemoveEnemy(enemy: NativePointer): void {
    this.enemies = this.enemies.filter((e) => !e.equals(enemy));
  }

  public getEnemiesCount(): number {
    return this.enemies.length;
  }

  public cleanEnemies(): void {
    this.enemies = this.enemies.filter((e) => !e.isNull());
  }

  public reset(): void {
    this.enemies = [];
  }

  public at(index: number): NativePointer | undefined {
    return this.enemies[index];
  }
}
