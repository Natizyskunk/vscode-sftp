import { Client, FTPContext, FTPResponse } from 'basic-ftp';
import { connect as netConnect } from 'net';
import { ConnectionOptions as TLSConnectionOptions } from 'tls';
import RemoteClient, { ConnectOption } from './remoteClient';

// Passive-mode transfer strategy that never upgrades the data connection
// to TLS. basic-ftp's built-in strategy encrypts data connections whenever
// the control connection is TLS, but with the legacy `secure: 'control'`
// option (PROT C) the server expects clear-text data connections.
async function enterPassiveModePlainData(ftp: FTPContext): Promise<FTPResponse> {
  const res = await ftp.request('EPSV');
  const match = res.message.match(/\(\|\|\|(\d+)\|\)/);
  if (!match) {
    throw new Error(`Can't parse response to 'EPSV': ${res.message}`);
  }
  const port = parseInt(match[1], 10);

  await new Promise<void>((resolve, reject) => {
    const handleConnErr = (err: Error) => {
      err.message = "Can't open data connection in passive mode: " + err.message;
      reject(err);
    };
    const socket = netConnect({ host: ftp.socket.remoteAddress, port }, () => {
      socket.removeListener('error', handleConnErr);
      socket.removeListener('timeout', handleTimeout);
      ftp.dataSocket = socket;
      resolve();
    });
    const handleTimeout = () => {
      socket.destroy();
      reject(new Error(`Timeout when trying to open data connection on port ${port}`));
    };
    socket.setTimeout(ftp.timeout);
    socket.on('error', handleConnErr);
    socket.on('timeout', handleTimeout);
  });

  return res;
}

export default class FTPClient extends RemoteClient {
  private _disconnectListeners: Array<(reason: string, err?: Error) => void> = [];
  private _disconnectNotified: boolean = false;

  _initClient() {
    return new Client(this._option.connectTimeout || 10 * 1000);
  }

  _hasProvideAuth(connectOption: ConnectOption) {
    return connectOption.password != null;
  }

  async _doConnect(connectOption: ConnectOption): Promise<void> {
    const { username, password, host, port, secure, secureOptions, debug } = connectOption;
    const client: Client = this._client;

    if (debug) {
      // basic-ftp masks the PASS argument in its log output
      client.ftp.log = debug;
    }

    await client.access({
      host,
      port,
      user: username,
      password,
      secure: secure === true || secure === 'implicit' ? secure : secure === 'control' ? true : false,
      secureOptions: secureOptions as TLSConnectionOptions,
    });

    // basic-ftp always requests PROT P for FTPS. The legacy `secure: 'control'`
    // option means only the control connection is encrypted, so downgrade
    // data connections back to clear text.
    if (secure === 'control') {
      await client.send('PROT C');
      client.prepareTransfer = enterPassiveModePlainData;
    }

    // Pin the listing command for the whole connection. basic-ftp probes
    // its candidates on every list() until one succeeds, and an FTP error
    // (e.g. listing a directory that doesn't exist yet, which ensureDir
    // does routinely) makes it fall back from MLSD to LIST — silently
    // changing mtime precision and timezone semantics mid-session.
    const features = await client.features();
    client.availableListCommands = features.has('MLSD') ? ['MLSD'] : ['LIST'];

    // basic-ftp's Client is not an EventEmitter; watch the control socket
    // (attached after access() since a TLS upgrade replaces the socket)
    client.ftp.socket
      .once('end', () => this._notifyDisconnected('end'))
      .once('close', () => this._notifyDisconnected('close'))
      .once('error', err => this._notifyDisconnected('error', err));
  }

  onDisconnected(cb: (reason: string, err?: Error) => void) {
    this._disconnectListeners.push(cb);
  }

  private _notifyDisconnected(reason: string, err?: Error) {
    if (this._disconnectNotified) {
      return;
    }
    this._disconnectNotified = true;
    this._disconnectListeners.forEach(cb => cb(reason, err));
  }

  end() {
    this._client.close();
    // basic-ftp removes all socket listeners while closing, so the
    // listeners attached in _doConnect never see this close
    this._notifyDisconnected('end');
  }

  getFsClient() {
    return this._client;
  }
}
