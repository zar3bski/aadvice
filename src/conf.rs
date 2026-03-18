use std::{
    io::{Error, ErrorKind},
    str::FromStr,
};

use log::LevelFilter;

pub struct Configuration {
    pub watch_file: String,
    pub log_level: LevelFilter,
}

impl Configuration {
    pub fn set(&mut self, field: String, value: String) -> Result<bool, Error> {
        match field.as_str() {
            "watch_file" => self.watch_file = value,
            "log_level" => match LevelFilter::from_str(value.as_str()) {
                Ok(level) => self.log_level = level,
                Err(_) => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid data type: log_level",
                    ));
                }
            },
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid config attribute",
                ));
            }
        }
        Ok(true)
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            watch_file: "/var/log/audit/audit.log".to_owned(),
            log_level: LevelFilter::Info,
        }
    }
}
