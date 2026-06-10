import { COMMAND_DELETE_REMOTE_ACTIVEFILE } from '../constants';
import { checkFileCommand } from './abstract/createCommand';
import fileCommandDeleteRemote from './fileCommandDeleteRemote';
import { getActiveDocumentUri } from './shared';

export default checkFileCommand({
  ...fileCommandDeleteRemote,
  id: COMMAND_DELETE_REMOTE_ACTIVEFILE,
  getFileTarget: getActiveDocumentUri,
});
