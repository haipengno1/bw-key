use std::borrow::Borrow;
use std::io::Read;

use base64::{Engine as _, engine::{general_purpose::STANDARD, general_purpose::URL_SAFE_NO_PAD}};
use log::debug;

use crate::{cipherstring, Keys};
use crate::prelude::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl<'de> serde::de::Visitor<'de> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{}", ty),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(serde::Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectPasswordRes {
    access_token: String,
    #[serde(skip_deserializing)]
    _expires_in: u32,
    token_type: String,
    refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorRes {
    error: String,
    error_description: String,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    two_factor_providers: Option<Vec<TwoFactorProviderType>>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
    message: String,
}

#[derive(Debug)]
pub struct SSHKeyRecord {
    pub name: String,
    pub passwd: Option<String>,
    pub raw_key: Vec<u8>,
}

#[derive(serde::Deserialize, Debug)]
 struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
     ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
     folders: Vec<SyncResFolder>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
 struct SyncResCipher {
    #[serde(rename = "Id", alias = "id")]
     id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
     folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
     organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
     name: String,
    #[serde(rename = "Login", alias = "login")]
     login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "Notes", alias = "notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
     fields: Option<Vec<SyncResField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "Attachments", alias = "attachments")]
     attachments: Option<Vec<SyncResAttach>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
 struct SyncResAttach {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Key", alias = "key")]
    pub key: String,
    #[serde(rename = "Size", alias = "size")]
    size: String,
    #[serde(rename = "FileName", alias = "fileName")]
     file_name: String,
    #[serde(rename = "Url", alias = "url")]
     url: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
 struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
     id: String,
    #[serde(rename = "Name", alias = "name")]
     name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
 struct CipherLogin {
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
    #[serde(rename = "Password", alias = "password")]
     password: Option<String>,
    #[serde(rename = "Totp", alias = "totp")]
    totp: Option<String>,
    #[serde(rename = "Uris", alias = "uris")]
    uris: Option<Vec<CipherLoginUri>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "Uri", alias = "uri")]
    uri: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardHolderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSecureNote {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
 struct SyncResField {
    #[serde(rename = "Type", alias = "type")]
    ty: u32,
    #[serde(rename = "Name", alias = "name")]
    name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    value: Option<String>,
}


#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
}

impl Client {
    pub fn new(base_url: &str, identity_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
        }
    }

    pub fn prelogin(&self, email: &String) -> Result<u32> {
        let resp = ureq::post(&self.api_url("/accounts/prelogin"))
            .set("Accept", "application/json")
            .send_json(ureq::json!({
                "email":email.to_string(),
             }));
        match resp {
                Ok(resp) => {
                    let prelogin_res: PreloginRes = resp.into_json().context(crate::error::UreqSnafu)?;
                    debug!("{:?}",prelogin_res);
                    Ok(prelogin_res.kdf_iterations)
                }
                Err(ureq::Error::Status(code, _response)) => {
                    Err(Error::RequestFailed {status:code})
                }
                Err(_) => {
                    Err(Error::UreqErr)
                }
        }
    }

    pub fn login(
        &self,
        email: &str,
        master_password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let mut req:Vec<(&str,&str)>=Vec::new();
        req.push(("grant_type","password"));
        req.push( ("username",email));
        let pass=STANDARD.encode(master_password_hash.hash());
        req.push(  ("password",pass.borrow()));
        req.push(   ("scope","api offline_access"));
        req.push(   ("client_id","desktop"));
        req.push(    ("deviceType","8"));
        let uuid=uuid::Uuid::new_v4().hyphenated().to_string();
        req.push(    ("deviceIdentifier",uuid.borrow()));
        req.push(    ("deviceName", "bw-key"));
        req.push(    ("devicePushToken",""));
        let mut tws=String::new();
        two_factor_provider.map(|tw|{
            tws=(tw as u32).to_string();
            req.push(("twoFactorProvider",tws.as_str()));
        });
        two_factor_token.map(|tt|{
            req.push(("twoFactorToken",tt));
        });
        let resp = ureq::post(&self.identity_url("/connect/token"))
            .set("Accept", "application/json")
            .set("auth-email",
                 URL_SAFE_NO_PAD.encode(email).as_str())
            .send_form(
                req.as_slice()
            );
        match resp {
            Ok(resp) => {
                debug!("{:?}",resp);
                let connect_res: ConnectPasswordRes =
                    resp.into_json().context(crate::error::UreqSnafu)?;
                Ok((
                    connect_res.access_token,
                    connect_res.refresh_token,
                    connect_res.key,
                ))
            }
            Err(ureq::Error::Status(code, res)) => {
                debug!("{:?}:{:?}",code,res);
                Err(classify_login_error(&res.into_json().context(crate::error::UreqSnafu)?, code))
            }
            Err(_) => {
                Err(Error::UreqErr)
            }
        }
    }

    fn decrypt( &self,src:&String,pkey: &Keys) -> String {
        let cipherstring = cipherstring::CipherString::new(src.as_str()).unwrap();
        let plaintext = String::from_utf8(
            cipherstring.decrypt_symmetric(pkey).unwrap(),
        ).unwrap();
        return plaintext
    }
    fn get_raw_file(&self, url:&str, file_key:&String, pkey: &Keys) -> Vec<u8> {
        let resp = ureq::get(url)
            .call().unwrap();

        let len = resp.header("Content-Length")
            .and_then(|s| s.parse::<usize>().ok()).unwrap();

        let mut file: Vec<u8> = Vec::with_capacity(len);
        resp.into_reader()
            .take(10_000_000)
            .read_to_end(&mut file).unwrap();

        let cipherstring = cipherstring::CipherString::new(file_key.as_str()).unwrap();
        let file_master_keys = cipherstring.decrypt_symmetric(pkey).unwrap();

        let  file_master_keys_vec = crate::locked::Vec::from_str(file_master_keys.as_slice());

        let file_pkey=crate::locked::Keys::new(file_master_keys_vec);
        let cipherstring = cipherstring::CipherString::from_raw_bytes(file.as_slice()).unwrap();
        return cipherstring.decrypt_symmetric(&file_pkey).unwrap()
    }
    pub fn get_ssh_keys(
        &self,
        access_token: &str,
        pkey: &Keys,
    ) -> Result<Vec<SSHKeyRecord>> {
        let res = ureq::get(&self.api_url("/sync"))
            .set("Authorization", format!("Bearer {}", access_token).as_str())
            .call();
        match res {
            Ok(resp) => {
                let sync_res: SyncRes = resp.into_json().context(crate::error::UreqSnafu)?;
                //find ssh folder
                let mut ssh_folder_id:&String= &String::new();
                for folder in &sync_res.folders {
                    let plaintext = self.decrypt(&folder.name, pkey);
                    if plaintext.eq_ignore_ascii_case("SSH") {
                        ssh_folder_id= &folder.id;
                        break
                    }
                }
                //get ssh keys
                if ssh_folder_id !=""{
                    println!(" Found SSH folder.");
                    // SSHKeyRecord
                    let mut ssh_keys:Vec<SSHKeyRecord>=Vec::new();
                    for cipher in &sync_res.ciphers {
                        cipher.folder_id.as_ref().map(|cipher_folder_idstr|{
                            if cipher_folder_idstr.eq(ssh_folder_id) {
                                let password=cipher.login.as_ref().map_or(
                                    Option::None,
                                    |login|login.password.as_ref())
                                    .map(|pass|self.decrypt(pass, pkey));
                                cipher.attachments.as_ref().map(|attach|{
                                    let att=attach[0].clone();
                                    let file_name=self.decrypt(&att.file_name, pkey);
                                    let url=&att.url;
                                    let mut auto_load=true;
                                    cipher.fields.as_ref().map(|fields|{
                                        for field in fields{
                                            let field=field.clone();
                                            let field_name =self.decrypt(&field.name.unwrap(), pkey);
                                            let field_value =self.decrypt(&field.value.unwrap(), pkey);
                                            if field.ty==2 {
                                                if field_name.eq_ignore_ascii_case("autoload") {
                                                    if field_value.eq_ignore_ascii_case("false") {
                                                        auto_load=false;
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    });
                                    if auto_load {
                                        let raw_key=self.get_raw_file(url,&att.key,pkey);
                                        let ssh_key=SSHKeyRecord{
                                            name: file_name,
                                            passwd: password,
                                            raw_key,
                                        };
                                        ssh_keys.push(ssh_key);
                                    }
                                });
                            }
                        });
                    }
                    Ok(ssh_keys)
                }else{
                    Err(Error::SSHKeyFolderNotFound)
                }
            },
            Err(ureq::Error::Status(code, res)) => {
                if code==401 {
                    Err(Error::RequestUnauthorized)
                }else{
                    Err(Error::RequestFailed {
                        status: res.status(),
                    })
                }
            }
            Err(_) => {
                Err(Error::UreqErr)
            }
        }
    }
    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}

fn classify_login_error(error_res: &ConnectErrorRes, code: u16) -> Error {
    match error_res.error.as_str() {
        "invalid_grant" => match error_res.error_description.as_str() {
            "invalid_username_or_password" => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            "Two factor required." => {
                if let Some(providers) =
                error_res.two_factor_providers.as_ref()
                {
                    return Error::TwoFactorRequired {
                        providers: providers.to_vec(),
                    };
                }
            }
            _ => {}
        },
        "" => {
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if error_res.error_description == "" {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    match message.as_str() {
                        "Username or password is incorrect. Try again"
                        | "TOTP code is not a number" => {
                            return Error::IncorrectPassword { message };
                        }
                        s => {
                            if s.starts_with(
                                "Invalid TOTP code! Server time: ",
                            ) {
                                return Error::IncorrectPassword { message };
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    log::warn!("unexpected error received during login: {:?}", error_res);
    Error::RequestFailed { status: code }
}
