import * as vscode from 'vscode';

const spinners = {
  dots: {
    interval: 80,
    frames: ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
  },
};

enum Status {
  ok = 1,
  warn,
  error,
}

export default class StatusBarItem {
  static Status = Status;

  private _name: () => string | string;
  private tooltip: string;
  private statusBarItem: vscode.StatusBarItem;
  private spinnerTimer: any = null;
  private resetTimer: any = null;
  private curFrameOfSpinner: number = 0;
  private text: string;
  private status: Status = Status.ok;
  private spinner: {
    interval: number;
    frames: string[];
  };

  constructor(name, tooltip, command) {
    this._name = name;
    this.tooltip = tooltip;
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    this.statusBarItem.command = command;
    this.spinner = spinners.dots;
    this.reset = this.reset.bind(this);
    this.reset();
  }

  private get name() {
    return typeof this._name === 'function' ? this._name() : this._name;
  }

  updateStatus(status: Status) {
    this.status = status;
    this._render();
  }

  getText() {
    return this.statusBarItem.text;
  }

  show() {
    this.statusBarItem.show();
  }

  isSpinning() {
    return this.spinnerTimer !== null;
  }

  startSpinner() {
    if (this.spinnerTimer) {
      return;
    }

    const totalFrame = this.spinner.frames.length;
    this.spinnerTimer = setInterval(() => {
      this.curFrameOfSpinner = (this.curFrameOfSpinner + 1) % totalFrame;
      this._render();
    }, this.spinner.interval);
    this._render();
  }

  stopSpinner() {
    clearInterval(this.spinnerTimer);
    this.spinnerTimer = null;
    this.curFrameOfSpinner = 0;
    this._render();
  }

  showMsg(text: string, hideAfterTimeout?: number);
  showMsg(text: string, tooltip: string, hideAfterTimeout?: number);
  showMsg(text: string, tooltip?: string | number, hideAfterTimeout?: number) {
    if (typeof tooltip === 'number') {
      hideAfterTimeout = tooltip;
      tooltip = text;
    }

    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = null;
    }

    this.text = text;
    this.statusBarItem.tooltip = tooltip;
    this._render();
    if (hideAfterTimeout) {
      this.resetTimer = setTimeout(this.reset, hideAfterTimeout);
    }
  }

  private _render() {
    if (this.isSpinning()) {
      this.statusBarItem.text = this.spinner.frames[this.curFrameOfSpinner] + ' ' + this.text;
    } else if (this.name === this.text) {
      switch (this.status) {
        case Status.ok:
          this.statusBarItem.text = this.text;
          break;
        case Status.warn:
          this.statusBarItem.text = `$(alert) ${this.text}`;
          break;
        case Status.error:
          this.statusBarItem.text = `$(issue-opened) ${this.text}`;
          break;
        default:
          this.statusBarItem.text = this.text;
      }
    } else {
      this.statusBarItem.text = this.text;
    }
  }

  showProgress(fileName: string, bytesTransferred: number, totalBytes: number, startTime: number) {
    const percent = totalBytes > 0 ? Math.round((bytesTransferred / totalBytes) * 100) : 0;
    const elapsed = (Date.now() - startTime) / 1000;
    const speed = elapsed > 0 ? bytesTransferred / elapsed : 0;
    const eta = speed > 0 && totalBytes > 0
      ? Math.round((totalBytes - bytesTransferred) / speed)
      : 0;

    const progressText = totalBytes > 0
      ? `${fileName} ${percent}% | ${StatusBarItem._formatBytes(speed)}/s | ~${eta}s`
      : `${fileName} ${StatusBarItem._formatBytes(bytesTransferred)}`;

    const tooltipText = totalBytes > 0
      ? `${StatusBarItem._formatBytes(bytesTransferred)} / ${StatusBarItem._formatBytes(totalBytes)}`
      : `${StatusBarItem._formatBytes(bytesTransferred)} transferred`;

    this.text = progressText;
    this.statusBarItem.tooltip = tooltipText;
    this._render();
  }

  private static _formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }

  reset() {
    this.text = this.name;
    this.statusBarItem.tooltip = this.tooltip;
    this._render();
  }
}
