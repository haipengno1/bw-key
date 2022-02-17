# bw-key

[中文](https://github.com/haipengno1/bw-key/blob/main/README_ZH.md)

A tool to add the SSH private keys stored in Bitwarden vault to `ssh-agent`, supporting self-hosted services.

## Instruction
I have been using keepassxc before, and the iPhone does not have an open source client,  so I switched to bitwarden, which the official clients are cross-platforms.
When using keepassxc, there is a very good feature, you can store the ssh private keys in it, and automatically load them into ssh-agent when unlocking the client. After switching to bitwarden, there hasn't this feature,   I found an solution at
[bitwarden-ssh-agent](https://github.com/joaojacome/bitwarden-ssh-agent), but it depends on the official bitwarden-cli, and will generate a temporary file locally, although it will be deleted afterwards, but as Patients with obsessive-compulsive disorder feel uncomfortable, and then here is the new solution.

## Usage

### 1. Storing the keys in BitWarden
1. Create a folder named `SSH` under the root directory in Bitwarden.
2. Add an new login-item to that folder.
3. Upload the private key as an attachment. If the private key has a password, please directly record it in the password of the current login project. The tool will automatically use the password when loading the key.
4. If you don't want load the  private key automatically, please create a Boolean custom field: `autoload`, and set it to false.
5. Repeat steps 2-4 to add the remaining private keys.

### 2.Load the keys.
```shell
FLAGS:
--help       Prints help information
-V, --version    Prints version information

OPTIONS:
-h, --host <host>    The URL of the Bitwarden server to use. Defaults to the official server at `https://xxx.bitwarden.com/` if unset.
-m, --method <method>   Optional, The two factor method  to use as the account name when logging into the Bitwarden server,can be one of "auth,email,duo,yubikey,u2f"
-n, --name <name>    The email address to use as the account name when logging into the Bitwarden server. Required.
```
## thanks to :
- [Bitwarden](https://bitwarden.com/).
- [rbw](https://git.tozt.net/rbw).
- [bitwarden-ssh-agent](https://github.com/joaojacome/bitwarden-ssh-agent).
- [rust-osshkeys](https://github.com/Leo1003/rust-osshkeys)