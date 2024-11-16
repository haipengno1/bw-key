use std::io::Write;
use std::time::Duration;
use std::{io, thread};

use log::{Level, LevelFilter, Metadata, Record};

use crate::api::{Client, TwoFactorProviderType};
use crate::core::locked::{Keys, Password, Vec as LockedVec};
use crate::crypto::cipherstring::CipherString;
use crate::identity::Identity as BwKeyIdentity;
use crate::prelude::Error as BwKeyError;
use crate::proto::{to_bytes, Identity as ProtoIdentity, Message};
use crate::ssh::ssh_key::parse_keystr;
use crate::ssh::ssh_socket::SshSocket;

mod api;
mod auth;
mod core;
mod crypto;
mod error;
mod identity;
mod key;
mod ssh;
mod prelude;

mod proto;

#[derive(structopt::StructOpt)]
/// Tool for add keys to ssh-agent from bitwarden server,support self-hosted server, just pass `--help`
struct Args {
    #[structopt(short, long, help = "The URL of the Bitwarden server to use. Defaults to the official server at `https://xxx.bitwarden.com/` if unset.")]
    host: Option<String>,
    #[structopt(short, long, help = "The email address to use as the account name when logging into the Bitwarden server. Required.")]
    name: Option<String>,
    #[structopt(short, long, help = "The two factor method to use when logging into the Bitwarden server,can be one of \"auth,email,duo,yubikey,u2f\"")]
    method: Option<String>,
}

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

#[paw::main]
fn main(args: Args) -> Result<(), BwKeyError> {
    log::set_boxed_logger(Box::new(SimpleLogger))
        .map(|()| log::set_max_level(LevelFilter::Info)).expect("log init failed");
    let mut ssh_client = SshSocket::new()?;
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
            io::stdout().flush()?;
            let mut ret = String::with_capacity(20);
            io::stdin().read_line(&mut ret).expect("Failed to read email");
            ret.trim().to_string()
        }
    };
    print!("Please input your password: ");
    io::stdout().flush()?;
    let passwd_str = rpassword::read_password().map_or_else(|_e| {
        println!("\n****WARNING****: Cannot use TTY, falling back to stdin/stdout;Password will be visible on the screen");
        rpassword::read_password_from_bufread(&mut io::BufReader::new(io::stdin())).unwrap()
    }, |v| v);

    let two_factor_provider = match args.method.clone() {
        Some(method) => if method.eq_ignore_ascii_case("auth") {
            Some(TwoFactorProviderType::Authenticator)
        } else if method.eq_ignore_ascii_case("email") {
            Some(TwoFactorProviderType::Email)
        } else if method.eq_ignore_ascii_case("duo") {
            Some(TwoFactorProviderType::Duo)
        } else if method.eq_ignore_ascii_case("yubikey") {
            Some(TwoFactorProviderType::Yubikey)
        } else if method.eq_ignore_ascii_case("u2f") {
            Some(TwoFactorProviderType::U2f)
        } else {
            None
        },
        None => {
            None
        }
    };
    let mut ret;
    let two_factor_code = match two_factor_provider.clone() {
        Some(_tw) => {
            print!("Please input  two factor code:");
            io::stdout().flush()?;
            ret = String::with_capacity(20);
            io::stdin().read_line(&mut ret).expect("Failed to get code");
            Some(ret.trim())
        }
        None => {
            None
        }
    };

    let client = Client::new(&base_url, &identity_url);
    let password = Password::new(
        LockedVec::from_str(passwd_str.as_bytes())
    );
    let iterations = client.prelogin(&email)?;
    let identity = BwKeyIdentity::new(email.as_str(), &password, iterations)?;
    // login
    let (access_token, _refresh_token, protected_key) = client
        .login(
            &identity.email,
            &identity.master_password_hash,
            two_factor_code,
            two_factor_provider,
        )?;
    let master_keys = CipherString::new(&protected_key)?
        .decrypt_locked_symmetric(&identity.keys)?;
    let pkey = Keys::new(master_keys);
    //get ssh keys
    let ssh_keys = client.get_ssh_keys(access_token.as_str(), &pkey)?;
    for ssh_key in ssh_keys {
        let key = parse_keystr(ssh_key.raw_key.as_slice(), ssh_key.passwd.as_deref())?;
        let identity = ProtoIdentity {
            private_key: key,
            comment: ssh_key.name.clone(),
        };

        // // Write to the client
        let req = Message::AddIdentity(identity);
        let req_bytes = to_bytes(&to_bytes(&req).unwrap()).unwrap();
        let result = ssh_client.write(req_bytes.as_slice());
        match result {
            Ok(_) => {
                println!("Add ssh key:{}", ssh_key.name)
            }
            _ => {
                println!("Add ssh key:{} failed", ssh_key.name)
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}