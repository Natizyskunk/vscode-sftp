// ponytail: was a global profile holder; profile is now per-FileService.
// This stays as a tiny "UI needs refresh" signal (status bar + remote explorer).
class AppState {
  private _observer: () => void = () => {
    /* no-op until subscribed */
  };

  subscribe(observer: () => void) {
    this._observer = observer;
  }

  notify() {
    this._observer();
  }
}

export default AppState;
