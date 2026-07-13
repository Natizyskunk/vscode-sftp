class AppState {
  private _profile: string | null = null;
  private _availableProfiles: string[] = [];
  private _observer: (x: any) => void;

  get profile(): string | null {
    return this._profile;
  }

  set profile(newProfile: string | null) {
    if (this._profile === newProfile) {
      return;
    }

    this._profile = newProfile;
    this._notify();
  }

  // every profile name defined across the workspace's sftp configs
  get availableProfiles(): string[] {
    return this._availableProfiles;
  }

  set availableProfiles(newProfiles: string[]) {
    if (
      this._availableProfiles.length === newProfiles.length &&
      this._availableProfiles.every((profile, index) => profile === newProfiles[index])
    ) {
      return;
    }

    this._availableProfiles = newProfiles;
    this._notify();
  }

  getStateSnapshot() {
    return {
      profile: this._profile,
      availableProfiles: this._availableProfiles,
    };
  }

  subscribe(observer) {
    this._observer = observer;
  }

  private _notify() {
    if (this._observer) {
      this._observer(this.getStateSnapshot());
    }
  }
}

export default AppState;
