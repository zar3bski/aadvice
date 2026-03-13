use std::env;
use std::env::Args;
use std::sync::LazyLock;

use log::debug;

use crate::conf::Configuration;

static HELP_SYMBOL: LazyLock<String> = LazyLock::new(|| "--help".to_string());

fn print_help() {
    todo!()
}

pub fn parse_args<T>(mut args: T) -> Option<Configuration>
where
    T: Iterator<Item = String>,
{
    let mut default = Configuration::default();
    let _program_name = args.next();
    'cli: loop {
        let key = args.next();
        let value = args.next();
        match key {
            None => break 'cli,
            Some(key) => {
                if key == *HELP_SYMBOL || value.is_none() {
                    print_help();
                    return None;
                } else {
                    let value = value.unwrap();
                    if value == *HELP_SYMBOL {
                        print_help();
                        return None;
                    }
                    match default.set(key.replace("-", ""), value) {
                        Err(_) => {
                            print_help();
                            return None;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Some(default)
}

#[cfg(test)]
mod test {
    use std::default;

    use super::*;
    #[test]
    fn test_default() {
        let args = ["aadvice"].iter().map(|s| s.to_string());
        let default_config = Configuration::default();
        let config = parse_args(args);

        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.ignore_complain, default_config.ignore_complain);
        assert_eq!(config.watch_file, default_config.watch_file)
    }

    #[test]
    fn test_help() {
        let args = ["aadvice", "--help"].iter().map(|s| s.to_string());
        let config = parse_args(args);
        assert!(config.is_none())
    }

    #[test]
    fn test_setting() {
        let args = [
            "aadvice",
            "--watch_file",
            "/var/log/audit.log",
            "--ignore_complain",
            "true",
        ]
        .iter()
        .map(|s| s.to_string());

        let config = parse_args(args);
        assert!(config.is_some());
        let config = config.unwrap();

        assert_eq!(config.watch_file, "/var/log/audit.log".to_owned());
        assert_eq!(config.ignore_complain, true)
    }
}
