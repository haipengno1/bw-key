use std::{env, io};
use std::convert::TryFrom;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::locked::Keys;
use crate::ossh_privkey::parse_keystr;
use crate::proto::{Identity, Message, PrivateKey, to_bytes};

mod proto;

mod prelude;
mod api;
mod error;
mod locked;
mod identity;
mod cipher;
mod sshbuf;
mod cipherstring;
mod ossh_privkey;

#[derive(structopt::StructOpt)]
/// I am a program and I work, just pass `-h`
struct Args {
    #[structopt(short, long, help = "your self-hosted server address")]
    host: Option<String>,
    #[structopt(short, long, help = "your name")]
    name: Option<String>,
}

#[paw::main]
fn main(args: Args) -> Result<(), crate::error::Error> {
    let base_url = args.host.clone().map_or(
        "https://api.bitwarden.com".to_string(),
        |url| format!("{}/api", url),
    );
    let identity_url = args.host.clone().map_or(
        "https://identity.bitwarden.com".to_string(),
        |url| format!("{}/identity", url),
    );
    let email = match args.name.clone() {
        Some(name) => name,
        None => {
            print!("Please input your email:");
            std::io::stdout().flush()?;
            let mut ret = String::with_capacity(20);
            io::stdin().read_line(&mut ret).expect("Failed to read email");
            ret.trim().to_string()
        }
    };
    print!("Please input your password: ");
    std::io::stdout().flush()?;
    let passwd_str = rpassword::read_password()?;

    let client = crate::api::Client::new(&base_url, &identity_url);
    let password = crate::locked::Password::new(
        crate::locked::Vec::from_str(passwd_str.as_bytes())
    );
    let iterations = client.prelogin(&email)?;
    let identity = crate::identity::Identity::new(email.as_str(), &password, iterations)?;
    // login
    let (access_token, _refresh_token, protected_key) = client
        .login(
            &identity.email,
            &identity.master_password_hash,
            Option::None,
            Option::None,
        )?;
    let master_keys = crate::cipherstring::CipherString::new(&protected_key)?
        .decrypt_locked_symmetric(&identity.keys)?;
    let pkey = crate::locked::Keys::new(master_keys);
    //get ssh keys
    let ssh_keys = client.get_ssh_keys(access_token.as_str(), &pkey).unwrap();
    let ssh_socket_key = env::var("SSH_AUTH_SOCK").unwrap();
    // todo windows \.\pipe\openssh-ssh-agent
    let ssh_socket = Path::new(&ssh_socket_key);
    let mut client = UnixStream::connect(ssh_socket).unwrap();
    for ssh_key in ssh_keys {
        let key = parse_keystr(ssh_key.raw_key.as_slice(),  ssh_key.passwd.as_deref()).unwrap();
        let identity = Identity {
            private_key: key,
            comment: ssh_key.name.clone(),
        };

        // // Write to the client
        let req = Message::AddIdentity(identity);
        let req_bytes = to_bytes(&to_bytes(&req).unwrap()).unwrap();
        client.write(req_bytes.as_slice());
        println!("Add ssh key:{}", ssh_key.name);
    }
    Ok(())
}
