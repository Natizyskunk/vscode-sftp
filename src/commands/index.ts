// Command modules must be listed here explicitly so the bundler can include
// them statically (the previous require.context approach was webpack-only).
import commandAddToIgnore from './commandAddToIgnore';
import commandCancelAllTransfer from './commandCancelAllTransfer';
import commandCancelTransfer from './commandCancelTransfer';
import commandClearPassword from './commandClearPassword';
import commandConfig from './commandConfig';
import commandListActiveFolder from './commandListActiveFolder';
import commandOpenSshConnection from './commandOpenSshConnection';
import commandRetryTransfer from './commandRetryTransfer';
import commandSavePassword from './commandSavePassword';
import commandSetProfile from './commandSetProfile';
import commandTestConnection from './commandTestConnection';
import commandToggleOutputPanel from './commandToggleOutputPanel';
import commandToggleUploadOnSave from './commandToggleUploadOnSave';
import commandUploadChangedFiles from './commandUploadChangedFiles';
import fileCommandCompareFolders from './fileCommandCompareFolders';
import fileCommandCreateFile from './fileCommandCreateFile';
import fileCommandCreateFolder from './fileCommandCreateFolder';
import fileCommandDeleteRemote from './fileCommandDeleteRemote';
import fileCommandDiff from './fileCommandDiff';
import fileCommandDiffActiveFile from './fileCommandDiffActiveFile';
import fileCommandDownload from './fileCommandDownload';
import fileCommandDownloadActiveFile from './fileCommandDownloadActiveFile';
import fileCommandDownloadActiveFolder from './fileCommandDownloadActiveFolder';
import fileCommandDownloadFile from './fileCommandDownloadFile';
import fileCommandDownloadFolder from './fileCommandDownloadFolder';
import fileCommandDownloadForce from './fileCommandDownloadForce';
import fileCommandDownloadProject from './fileCommandDownloadProject';
import fileCommandEditInLocal from './fileCommandEditInLocal';
import fileCommandList from './fileCommandList';
import fileCommandListAll from './fileCommandListAll';
import fileCommandRevealInExplorer from './fileCommandRevealInExplorer';
import fileCommandRevealInRemoteExplorer from './fileCommandRevealInRemoteExplorer';
import fileCommandSyncBothDirections from './fileCommandSyncBothDirections';
import fileCommandSyncLocalToRemote from './fileCommandSyncLocalToRemote';
import fileCommandSyncRemoteToLocal from './fileCommandSyncRemoteToLocal';
import fileCommandUpload from './fileCommandUpload';
import fileCommandUploadActiveFile from './fileCommandUploadActiveFile';
import fileCommandUploadActiveFolder from './fileCommandUploadActiveFolder';
import fileCommandUploadFile from './fileCommandUploadFile';
import fileCommandUploadFolder from './fileCommandUploadFolder';
import fileCommandUploadForce from './fileCommandUploadForce';
import fileCommandUploadProject from './fileCommandUploadProject';
import fileMultiCommandUploadActiveFileToAllProfiles from './fileMultiCommandUploadActiveFileToAllProfiles';
import fileMultiCommandUploadActiveFolderToAllProfiles from './fileMultiCommandUploadActiveFolderToAllProfiles';
import fileMultiCommandUploadFileToAllProfiles from './fileMultiCommandUploadFileToAllProfiles';
import fileMultiCommandUploadFolderToAllProfiles from './fileMultiCommandUploadFolderToAllProfiles';
import fileMultiCommandUploadForceToAllProfiles from './fileMultiCommandUploadForceToAllProfiles';
import fileMultiCommandUploadProjectToAllProfiles from './fileMultiCommandUploadProjectToAllProfiles';
import fileMultiCommandUploadToAllProfiles from './fileMultiCommandUploadToAllProfiles';

export default {
  commandAddToIgnore,
  commandCancelAllTransfer,
  commandCancelTransfer,
  commandClearPassword,
  commandConfig,
  commandListActiveFolder,
  commandOpenSshConnection,
  commandRetryTransfer,
  commandSavePassword,
  commandSetProfile,
  commandTestConnection,
  commandToggleOutputPanel,
  commandToggleUploadOnSave,
  commandUploadChangedFiles,
  fileCommandCompareFolders,
  fileCommandCreateFile,
  fileCommandCreateFolder,
  fileCommandDeleteRemote,
  fileCommandDiff,
  fileCommandDiffActiveFile,
  fileCommandDownload,
  fileCommandDownloadActiveFile,
  fileCommandDownloadActiveFolder,
  fileCommandDownloadFile,
  fileCommandDownloadFolder,
  fileCommandDownloadForce,
  fileCommandDownloadProject,
  fileCommandEditInLocal,
  fileCommandList,
  fileCommandListAll,
  fileCommandRevealInExplorer,
  fileCommandRevealInRemoteExplorer,
  fileCommandSyncBothDirections,
  fileCommandSyncLocalToRemote,
  fileCommandSyncRemoteToLocal,
  fileCommandUpload,
  fileCommandUploadActiveFile,
  fileCommandUploadActiveFolder,
  fileCommandUploadFile,
  fileCommandUploadFolder,
  fileCommandUploadForce,
  fileCommandUploadProject,
  fileMultiCommandUploadActiveFileToAllProfiles,
  fileMultiCommandUploadActiveFolderToAllProfiles,
  fileMultiCommandUploadFileToAllProfiles,
  fileMultiCommandUploadFolderToAllProfiles,
  fileMultiCommandUploadForceToAllProfiles,
  fileMultiCommandUploadProjectToAllProfiles,
  fileMultiCommandUploadToAllProfiles,
};
