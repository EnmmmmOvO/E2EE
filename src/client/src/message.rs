use std::fmt;
use chrono::{DateTime, Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub sender: bool,
    pub timestamp: i64,
    pub text: String,
}

impl Message {
    pub fn new(text: String) -> Self {
        Self { sender: true, timestamp: Local::now().timestamp(), text }
    }
    
    pub fn timestamp(&self) -> String {
        let naive_datetime = DateTime::from_timestamp(self.timestamp, 0);
        let datetime: DateTime<Utc> = Utc.from_utc_datetime(&naive_datetime.expect("REASON").naive_utc());
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.text.fmt(f)
    }
}