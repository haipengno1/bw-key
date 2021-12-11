// extern crate openssl;

mod proto;

mod prelude;
mod api;
mod error;
mod locked;
mod identity;
mod cipherstring;


use std::borrow::Borrow;
use std::convert::TryFrom;
use std::{env, fmt, io};
use std::env::args;
use std::error::Error;
use std::fs::File;
use std::io::{Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use serde_json::to_string;
use snafu::ResultExt;
use crate::locked::Keys;
use crate::proto::{Identity, Message, PrivateKey, RsaPrivateKey, to_bytes};

fn decrypt_byte(src:&String, pkey: &Keys) -> Vec<u8> {
    let cipherstring = cipherstring::CipherString::new(src.as_str()).unwrap();
    let bytes = cipherstring.decrypt_symmetric(&pkey).unwrap();
    return bytes
}
fn decrypt( src:&String,pkey: &Keys) -> String {
    let cipherstring = cipherstring::CipherString::new(src.as_str()).unwrap();
    let plaintext = String::from_utf8(
        cipherstring.decrypt_symmetric(&pkey).unwrap(),
    ).unwrap();
    return plaintext
}
#[derive(structopt::StructOpt)]
/// I am a program and I work, just pass `-h`
struct Args {
    #[structopt( short, long, help = "your self-hosted server address")]
    host: Option<String>,
    #[structopt( short, long, help = "your name")]
    name: Option<String>,
}
#[paw::main]
fn main(args: Args)-> Result<(), crate::error::Error>  {
    let base_url=args.host.clone().map_or(
        "https://api.bitwarden.com".to_string(),
        |url| format!("{}/api", url),
    );
    let identity_url=args.host.clone().map_or(
        "https://identity.bitwarden.com".to_string(),
        |url| format!("{}/identity", url),
    );
   let email= match args.name.clone() {
        Some(name) =>name,
        None =>{
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

    let client =crate::api::Client::new(&base_url,&identity_url);
    let password=crate::locked::Password::new(
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
            Option::None
        )?;
    let master_keys = crate::cipherstring::CipherString::new(&protected_key)?
        .decrypt_locked_symmetric(&identity.keys)?;
    let pkey=crate::locked::Keys::new(master_keys);
    //get ssh keys
    let ssh_keys = client.get_ssh_keys(access_token.as_str(), &pkey).unwrap();
    let ssh_socket_key = env::var("SSH_AUTH_SOCK").unwrap();
    // todo windows \.\pipe\openssh-ssh-agent
    let ssh_socket=Path::new(&ssh_socket_key);
    let mut client = UnixStream::connect(ssh_socket).unwrap();
    for ssh_key in ssh_keys {

        let private_key: PKey<Private> =ssh_key.passwd.map_or_else(
            ||PKey::private_key_from_pem(ssh_key.raw_key.as_slice()).unwrap(),
            |passphrase|PKey::private_key_from_pem_passphrase(ssh_key.raw_key.as_slice(), passphrase.as_bytes()).unwrap(),
        );
        let rsa_key:Rsa<Private>= Rsa::try_from(private_key).unwrap();
        let n = rsa_key.n().to_vec_padded(257).unwrap();
        let e = rsa_key.e().to_vec();
        let d = rsa_key.d().to_vec();
        let p = rsa_key.p().unwrap().to_vec_padded(129).unwrap();
        let q = rsa_key.q().unwrap().to_vec_padded(129).unwrap();
        // let dp = &d % &(&p - &BigNum::from_u32(1)?);
        // let dq = &d % &(&q - &BigNum::from_u32(1)?);

        let key = RsaPrivateKey{
            n,
            e,
            d,
            iqmp: Vec::new(),
            p,
            q
        };
        let identity=Identity {
            private_key: PrivateKey::Rsa(key),
            comment: ssh_key.name.clone(),
        };

        // // Write to the client
        let req = Message::AddIdentity(identity);
        let req_bytes =to_bytes(&to_bytes(&req).unwrap()).unwrap();
        client.write(req_bytes.as_slice());
        println!("Add ssh key:{}",ssh_key.name);
    }
    Ok(())
}
