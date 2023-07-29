export default class ESPManager {
  public static readonly MIN_AUTO_CLEAN_INTERVAL = 500;
  public static readonly DEFAULT_AUTO_CLEAN_INTERVAL = 1000;
  private _enemies: NativePointer[] = [];
  private _autoCleanInterval: number = ESPManager.DEFAULT_AUTO_CLEAN_INTERVAL;
  private _autoCleanIntervalId: NodeJS.Timer | undefined;

  public constructor(autoClean = true, autoCleanInterval = ESPManager.DEFAULT_AUTO_CLEAN_INTERVAL) {
    this._autoCleanInterval = autoCleanInterval;
    if (autoClean) this.startAutoClean();
  }

  private set enemies(value: NativePointer[]) {
    this._enemies = value;
  }

  public get enemies(): NativePointer[] {
    return this._enemies;
  }

  public getAutoCleanInterval(): number {
    return this._autoCleanInterval;
  }

  public setAutoCleanInterval(intval: number): void {
    this._autoCleanInterval = Math.max(intval, ESPManager.MIN_AUTO_CLEAN_INTERVAL);
  }

  public isAutoCleanEnabled(): boolean {
    return this._autoCleanIntervalId !== undefined;
  }

  public startAutoClean(): void {
    if (this.isAutoCleanEnabled()) return;
    this._autoCleanIntervalId = setInterval(() => this.cleanEnemies(), this._autoCleanInterval);
  }

  public stopAutoClean(): void {
    if (!this.isAutoCleanEnabled()) return;
    clearInterval(this._autoCleanIntervalId);
    this._autoCleanIntervalId = undefined;
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
