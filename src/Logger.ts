export class Logger {
  private loggin = false;
  private showTimer = false;

  constructor(loggin = false) {
    this.loggin = loggin;
  }

  private getTime(): string {
    const date = new Date();
    const time = [date.getHours(), date.getMinutes(), date.getSeconds()]
      .map((v) => v.toString().padStart(2, '0'))
      .join(':');

    return time;
  }

  get isLoggin(): boolean {
    return this.loggin;
  }

  get isShowTime(): boolean {
    return this.showTimer;
  }

  private display(...args: any[]): void {
    if (!this.loggin) return;
    const time = this.showTimer ? `\x1b[36m[${this.getTime()}]\x1b[0m` : '';
    time ? console.log(`${time}`, ...args) : console.log(...args);
  }

  public setLoggin(loggin: boolean): this {
    this.loggin = loggin;
    return this;
  }

  public setShowTime(show: boolean): this {
    this.showTimer = show;
    return this;
  }

  public log(...args: any[]): this {
    this.display(...args);
    return this;
  }
}

const logger = new Logger(true).setShowTime(true);
const log = logger.log.bind(logger);

export { log };
