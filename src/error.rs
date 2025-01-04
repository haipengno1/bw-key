#[derive(Debug, snafu::Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Email address not set"))]
    ConfigMissingEmail,

    #[snafu(display("Failed to create block mode decryptor"))]
    CreateBlockMode {
        source: block_modes::InvalidKeyIvLength,
    },

    #[snafu(display("Failed to create directory at {}", file.display()))]
    CreateDirectory {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("Failed to decrypt data"))]
    Decrypt { source: block_modes::BlockModeError },

    #[snafu(display("Failed to expand with HKDF"))]
    HkdfExpand,

    #[snafu(display("{}", message))]
    IncorrectPassword { message: String },

    #[snafu(display("Invalid base64 encoding"))]
    InvalidBase64 { source: base64::DecodeError },

    #[snafu(display("Invalid cipherstring: {}", reason))]
    InvalidCipherString { reason: String },

    #[snafu(display("Invalid MAC"))]
    InvalidMac,

    #[snafu(display("Invalid key"))]
    InvalidKey,

    #[snafu(display("Invalid key format"))]
    InvalidKeyFormat,

    #[snafu(display("Invalid key or IV length"))]
    InvalidKeyIvLength,

    #[snafu(display("Invalid length"))]
    InvalidLength,

    #[snafu(display("Invalid two factor provider type: {}", ty))]
    InvalidTwoFactorProvider { ty: String },

    #[snafu(display("Failed to parse JSON response"))]
    JSON {
        source: serde_path_to_error::Error<serde_json::Error>,
    },

    #[snafu(display("Failed to load config from {}", file.display()))]
    LoadConfig {
        source: std::io::Error,
        file: std::path::PathBuf,
    },

    #[snafu(display("Network request error"))]
    NetworkError { source: std::io::Error },

    #[snafu(display("PBKDF2 requires at least 1 iteration (got 0)"))]
    Pbkdf2ZeroIterations,

    #[snafu(display("API request failed with status: {}", status))]
    RequestFailed { status: u16 },

    #[snafu(display("API request unauthorized"))]
    RequestUnauthorized,

    #[snafu(display("SSH folder not found. Please create it first."))]
    SSHKeyFolderNotFound,

    #[snafu(display("Two factor authentication required"))]
    TwoFactorRequired {
        providers: Vec<crate::api::TwoFactorProviderType>,
    },

    #[snafu(display("Unimplemented cipherstring type: {}", ty))]
    UnimplementedCipherStringType { ty: String },

    #[snafu(display("IO error: {}", source))]
    IOError { source: std::io::Error },

    #[snafu(display("Invalid PEM format in key file"))]
    InvalidPemFormat,

    #[snafu(display("Unsupported key type"))]
    UnsupportType,

    #[snafu(display("Incorrect passphrase"))]
    IncorrectPass,

    #[snafu(display("Unsupported cipher"))]
    UnsupportCipher,

    #[snafu(display("Unsupported format"))]
    UnsupportFormat,

    #[snafu(display("Unknown error occurred"))]
    Unknown,

    #[snafu(display("Error making API request: {}", source))]
    UreqErr { source: Box<dyn std::error::Error + Send + Sync> },
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IOError { source: error }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::UreqErr { source: Box::new(error) }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
