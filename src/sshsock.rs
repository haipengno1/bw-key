use std::io::Write;
#[cfg(not(target_os = "windows"))]
use std::os::unix::net::UnixStream;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
#[cfg(target_os = "windows")]
use named_pipe::PipeClient;

#[derive(Debug)]
pub struct SshSock {
    #[cfg(not(target_os = "windows"))]
    unix_client:UnixStream,
    #[cfg(target_os = "windows")]
    pipe_client: PipeClient,
}

impl SshSock {
    pub fn new(path: &str) -> Self {
        #[cfg(not(target_os = "windows"))]
            {
                let ssh_socket = Path::new(&path);
                let unix_client = UnixStream::connect(ssh_socket).unwrap();
                Self {
                    unix_client
                }
            }
        #[cfg(target_os = "windows")]
            {
                let mut ssh_path=path;
                if ssh_path=="" {
                    ssh_path=r"\\.\pipe\openssh-ssh-agent";
                }
                let pipe_client=PipeClient::connect(ssh_path).unwrap();
                Self {
                    pipe_client
                }
            }
    }
}

impl Write for SshSock {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        #[cfg(not(target_os = "windows"))]
            {
                self.unix_client.write(buf)
            }
        #[cfg(target_os = "windows")]
            {
                self.pipe_client.write(buf)
            }
    }

    fn flush(&mut self) -> Result<(),std::io::Error> {
        Ok(())
    }
}