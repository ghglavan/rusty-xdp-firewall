use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum CommandResult {
    Error(String),
    Message(String),
    Ok,
}
