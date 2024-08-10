use std::env;
use std::io::{Error, Write};
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
    pub fn new() -> Result<Self, Error> {
        #[cfg(not(target_os = "windows"))]
            {
                let ssh_path=&env::var("SSH_AUTH_SOCK").map_or(String::new(), |key|key);

                let ssh_socket = Path::new(ssh_path);
                let unix_client = UnixStream::connect(ssh_socket);
                match unix_client {
                    Ok(unix_client) => {
                        Ok(Self {
                            unix_client
                        })
                    }
                    Err(e) => {
                        print!("Error connecting to $SSH_AUTH_SOCK, did you start ssh-agent?");
                        Err(e)
                    }
                }
            }
        #[cfg(target_os = "windows")]
            {
                let mut ssh_path=r"\\.\pipe\openssh-ssh-agent";
                let pipe_client=PipeClient::connect(ssh_path);
                match pipe_client {
                    Ok(pipe_client) => {
                        Ok(Self {
                            pipe_client
                        })
                    }
                    Err(e) => {
                        print!("Error connecting to \\\\.\\pipe\\openssh-ssh-agent, did you start ssh-agent?");
                        Err(e)
                    }
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