## Common commands

### SFTP: Config
Create a new configuration file for a project.

### SFTP: Set Profile
Set the current profile.

#### KeyBindings Args
func(profileName: string)

### SFTP: Upload Active File
Upload the current file.

### SFTP: Upload Changed Files
Upload all files changed or created since the last commit to your Git.
Can be called by default keyboard shortcut `Ctrl+Alt+U`.

### SFTP: Upload Commit Files
Pick a branch (the current one is listed first), then a commit from its last 50 commits, and upload only the files added or modified in that commit, with their content as of that commit. Your uncommitted local changes are never uploaded, and the branch does not need to be checked out (it only needs to be fetched).
Files deleted in the commit are deleted from the remote too (after a confirmation). Merge commits are compared against their first parent.

#### KeyBindings Args
func(commitHash: string)

### SFTP: Upload Active Folder
Upload the entire folder the current file is located in.

### SFTP: Download Active File
Download the remote version of the current file and overwrite the local copy.

### SFTP: Download Active Folder
Download the entire folder the current file is located in.

### SFTP: Sync Local -> Remote
1. Any files that exist on both local and remote that have a different timestamp between local and remote are copied over.
2. Any files that only exist on the local are copied over.

You can change the default behavior by [syncOption](https://github.com/Natizyskunk/vscode-sftp/wiki/Configuration#syncoption).

### SFTP: Sync Remote -> Local
Same as `Sync Local -> Remote`, but in the opposite direction.

### SFTP: Sync Both Directions
Compare file modification times, and will always perform the action that causes the newest file to be present in both locations.

*Only [skipCreate](https://github.com/Natizyskunk/vscode-sftp/wiki/Configuration#syncoptionskipcreate) and [ignoreExisting](https://github.com/Natizyskunk/vscode-sftp/wiki/Configuration#syncoptionignoreexisting) are valid for this command.*

### SFTP: List Active Folder
List the folder the current file is located in.

### SFTP: Upload To All Profiles
Upload files or folders to every profile defined in your configuration. Available variants: `Upload File To All Profiles`, `Upload Active File To All Profiles`, `Upload Folder To All Profiles`, `Upload Active Folder To All Profiles`, `Upload Project To All Profiles` and `Force Upload To All Profiles`.

*`Upload File To All Profiles` and `Upload Folder To All Profiles` ask for confirmation before uploading.*

### SFTP: Refresh Active Remote File
Reload the content of the remote file currently open in the editor. Also available as a refresh button in the editor title bar for remote files.

### sftp.upload
Upload file or folders.

#### KeyBindings Args
func(fspaths: string[])

### sftp.download
Download file or folders.

#### KeyBindings Args
func(fspaths: string[])

### SFTP: Cancel All Transfers
Stop the current transfers (upload and download).

### SFTP: Open SSH in Terminal
Open a terminal in VSCode and auto login to a specific server.


## Alt commands
An alternative command can be found when pressing `Alt` while opening a menu.

### Force Download
Download file but disregard ignore rules.

### Force Upload
Upload file but disregard ignore rules.
