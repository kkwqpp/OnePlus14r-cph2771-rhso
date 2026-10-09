use serde::Serialize;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub message: String,
    #[serde(skip)]
    pub data: Option<serde_json::Value>,
}
impl Error {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            data: None,
        }
    }
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::new(
            "E_IO",
            "Operation failed. Check private storage permissions and available space.",
        )
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::new(
            "E_INPUT",
            "The stored JSON is invalid or ambiguous. Preserve it for review.",
        )
    }
}
pub fn exit_code(code: &str) -> i32 {
    match code {
        "OK" => 0,
        "E_INPUT" | "E_XML" | "E_VALIDATION" | "E_SELECTION" | "E_PATH" | "E_ID" | "E_REQUEST"
        | "E_API_CONFIG" | "E_API_FORMAT" | "E_API_SSRF" | "E_API_LIMIT" => 2,
        "E_BUSY" => 3,
        "E_STALE" | "E_API_STALE" => 4,
        "E_CAPABILITY" | "E_ROOT" | "E_API_UNAVAILABLE" => 5,
        "E_CONFIRM" => 6,
        "E_RECOVERY" => 7,
        _ => 1,
    }
}
