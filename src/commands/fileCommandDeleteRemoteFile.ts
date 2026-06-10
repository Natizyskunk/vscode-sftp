import { COMMAND_DELETE_REMOTE_FILE } from '../constants';
import { checkFileCommand } from './abstract/createCommand';
import fileCommandDeleteRemote from './fileCommandDeleteRemote';

export default checkFileCommand({
  ...fileCommandDeleteRemote,
  id: COMMAND_DELETE_REMOTE_FILE,
});
