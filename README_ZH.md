# bw-key

一个把存在bitwarden中的ssh私钥添加到ssh-agent的工具，支持自建的服务。

## 说明

之前一直使用keepassxc，后来因为iPhone手机端没有开源的客户端，转为使用bitwarden，官方的客户端覆盖了全平台。
使用keepassxc的时候，有个非常不错的特性，可以把ssh的私钥存储到里面，解锁的时候自动加载到ssh-agent中，切换到bitwarden后官方没有这个功能，于是先搜索了下有没有轮子，发现了
[bitwarden-ssh-agent](https://github.com/joaojacome/bitwarden-ssh-agent)，不过这个依赖官方的bitwarden-cli,同时会在本地生成一个临时文件，虽然事后会删除，但是作为强迫症患者感觉不舒服，然后就有了这款轮子。

## 如何使用？

### 把密钥保存到bitwarden中

1. 在bitwarden的根目录下面创建一个文件夹： `SSH`。
2. 在该目录下新建一个登录项目。
3. 上传私钥作为附件，如果私钥有密码，请直接记录到当前登录项目的密码中，工具加载密钥的时候会自动使用该密码。
4. 如果不想该私钥被自动加载，请新建一个布尔型的自定义字段：`autoload`,并且设置为false。
5. 重复步骤2-4，添加其余的私钥。

### 加载私钥

```shell

FLAGS:
--help       打印帮助信息
-V, --version    打印版本信息

OPTIONS:
-h, --host <host>    Bitwarden 服务器地址. 默认使用官方服务器 `https://xxx.bitwarden.com/` .
-m, --method <method>  可选的，登录系统时使用的二次认证的方法，可以是 "auth,email,duo,yubikey,u2f"其中之一
-n, --name <name>   登录Bitwarden 服务器用的email地址.
```

## 感谢

- [Bitwarden](https://bitwarden.com/).
- [rbw](https://git.tozt.net/rbw).
- [bitwarden-ssh-agent](https://github.com/joaojacome/bitwarden-ssh-agent).
- [rust-osshkeys](https://github.com/Leo1003/rust-osshkeys)
