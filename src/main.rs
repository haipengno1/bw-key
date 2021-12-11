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
    url: Option<String>,
    #[structopt( short, long, help = "your name")]
    name: Option<String>,
}
#[paw::main]
fn main(args: Args)-> Result<(), crate::error::Error>  {
    let base_url=args.url.clone().map_or_else(
        || "https://api.bitwarden.com".to_string(),
        |url| format!("{}/api", url),
    );
    let identity_url=args.url.clone().map_or_else(
        || "https://identity.bitwarden.com".to_string(),
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
    let res=client.sync(access_token.as_str()).unwrap();
    let mut ssh_folder_id:String=String::new();;

    for folder in res.folders {
        let plaintext = decrypt(&folder.name, &pkey);
        if plaintext.eq_ignore_ascii_case("SSH") {
            println!(" {:x?}: {:x?}", &folder.id,plaintext);
            ssh_folder_id=folder.id;
            println!(" found SSH folder");
            break
        }
    }
    if ssh_folder_id !=""{
        for cipher in res.ciphers {
            let cipher_folder_id=cipher.folder_id.clone();
            match cipher_folder_id {
                Some(cipher_folder_idstr)=>{
                    if cipher_folder_idstr==ssh_folder_id {
                        match cipher.attachments.clone() {
                            Some(attach)=>{
                                let cli=cipher.clone();
                                let name=decrypt(&cipher.name, &pkey);
                                let password=decrypt(&cipher.login.unwrap().password.unwrap(), &pkey);
                                let att=attach[0].clone();
                                let file_name=decrypt(&att.file_name.unwrap(), &pkey);
                                let url=&att.url;
                                match cipher.fields.clone() {
                                    Some(fields) => {
                                        let field=&fields[0];
                                        let field_name =field.name.clone().unwrap();
                                        let field_value =field.value.clone().unwrap();
                                        let field_name =decrypt(&field_name, &pkey);
                                        let field_value =decrypt(&field_value, &pkey);
                                        println!("field:{:x?}:{:x?}", field_name, field_value);
                                    }
                                    _ => {}
                                }
                                println!("{:x?},{:x?}:{:x?}:{:x?}", name,password,file_name,att.key);
                                println!("{:x?}", cli);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
