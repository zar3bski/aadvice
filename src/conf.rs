use std::io::{Error, ErrorKind};

pub struct Configuration {
    pub ignore_complain: bool,
    pub watch_file: String,
}

impl Configuration {
    pub fn set(&mut self, field: String, value: String) -> Result<bool, Error> {
        match field.as_str() {
            "ignore_complain" => match value.parse::<bool>() {
                Ok(bool_val) => self.ignore_complain = bool_val,
                _ => {
                    return Err(Error::new(ErrorKind::InvalidData, "Invalid data type"));
                }
            },
            "watch_file" => self.watch_file = value,
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
            ignore_complain: false,
            watch_file: "/var/log/audit/audit.log".to_owned(),
        }
    }
}
