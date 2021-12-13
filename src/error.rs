#[derive(Debug, snafu::Snafu)]
#[snafu(visibility = "pub")]
pub enum Error {
    #[snafu(display("email address not set"))]
    ConfigMissingEmail,

    #[snafu(display("failed to create block mode decryptor"))]
    CreateBlockMode {
        source: block_modes::InvalidKeyIvLength,
    },

    #[snafu(display("failed to create directory at {}", file.display()))]
    CreateDirectory {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("failed to decrypt"))]
    Decrypt { source: block_modes::BlockModeError },

    #[snafu(display("failed to parse pinentry output ({:?})", out))]
    FailedToParsePinentry { out: String },

    #[snafu(display(
        "failed to run editor {}: {:?}",
        editor.to_string_lossy(),
        res
    ))]
    FailedToRunEditor {
        editor: std::path::PathBuf,
        res: std::process::ExitStatus,
    },

    #[snafu(display("failed to expand with hkdf"))]
    HkdfExpand,

    #[snafu(display("{}", message))]
    IncorrectPassword { message: String },

    #[snafu(display("invalid base64"))]
    InvalidBase64 { source: base64::DecodeError },

    #[snafu(display("invalid cipherstring: {}", reason))]
    InvalidCipherString { reason: String },

    #[snafu(display("invalid value for $EDITOR: {}", editor.to_string_lossy()))]
    InvalidEditor { editor: std::ffi::OsString },

    #[snafu(display("invalid mac"))]
    InvalidMac,

    #[snafu(display("invalid two factor provider type: {}", ty))]
    InvalidTwoFactorProvider { ty: String },

    #[snafu(display("failed to parse JSON"))]
    JSON {
        source: serde_path_to_error::Error<serde_json::Error>,
    },

    #[snafu(display("failed to load config from {}", file.display()))]
    LoadConfig {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("ureq error"))]
    Ureq { source: std::io::Error },

    #[snafu(display("pbkdf2 requires at least 1 iteration (got 0)"))]
    Pbkdf2ZeroIterations,

    #[snafu(display("api request returned error: {}", status))]
    RequestFailed { status: u16 },

    #[snafu(display("api request unauthorized"))]
    RequestUnauthorized,

    #[snafu(display("Not  found SSH folder!Please Create it"))]
    SSHKeyFolderNotFound,

    #[snafu(display("error making api request"))]
    UreqErr,

    #[snafu(display("two factor required"))]
    TwoFactorRequired {
        providers: Vec<crate::api::TwoFactorProviderType>,
    },

    #[snafu(display("unimplemented cipherstring type: {}", ty))]
    UnimplementedCipherStringType { ty: String },

    #[snafu(display("Unknown IO error"))]
    UnknownIO { source: std::io::Error },

    #[snafu(display("The key file's PEM part is invalid"))]
    InvalidPemFormat,
    #[snafu(display("The key type is not supported"))]
    UnsupportType,
    #[snafu(display("The passphrase is incorrect, can't decrypt the key"))]
    IncorrectPass,
    #[snafu(display("The key file has some invalid data in it"))]
    InvalidKeyFormat,
    #[snafu(display("The error is caused by OpenSSL, to get the underlying error, use [std::error::Error::source()](https://doc.rust-lang.org/std/error/trait.Error.html#method.source)"))]
    OpenSslError,
    #[snafu(display("The error is caused by ed25519-dalek, to get the underlying error, use [std::error::Error::source()](https://doc.rust-lang.org/std/error/trait.Error.html#method.source)"))]
    Ed25519Error,
    #[snafu(display("The error is caused by I/O error or reader error"))]
    IOError,
    #[snafu(display("Can't format some data"))]
    FmtError,
    #[snafu(display("The base64 string is invalid"))]
    Base64Error,
    #[snafu(display("The argument passed into the function is invalid"))]
    InvalidArgument,
    #[snafu(display("The key format is not supported"))]
    UnsupportFormat,
    #[snafu(display("Currently not used..."))]
    InvalidFormat,
    #[snafu(display("Some parts of the key are invalid"))]
    InvalidKey,
    #[snafu(display("The key size is invalid"))]
    InvalidKeySize,
    #[snafu(display("The slice length is invalid"))]
    InvalidLength,
    #[snafu(display("The elliptic curve is not supported"))]
    UnsupportCurve,
    #[snafu(display("The encrypt cipher is not supported"))]
    UnsupportCipher,
    #[snafu(display("The key type is not the desired one"))]
    TypeNotMatch,
    #[snafu(display("The key or IV length can't meet the cipher's requirement"))]
    InvalidKeyIvLength,
    #[snafu(display("Something shouldn't happen but it DID happen..."))]
    Unknown,
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::UnknownIO {
            source:error
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
