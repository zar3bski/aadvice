use crate::conf::Configuration;
use std::sync::LazyLock;

static HELP_SYMBOL: LazyLock<String> = LazyLock::new(|| "--help".to_string());

fn print_help() {
    println!(
        r#"usage:
    aadvice [--watch_file    </path/to/audit.log>] default: /var/log/audit.log
            [--log_level  <debug|info|warn|error>] default: info   
    "#
    );
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
        match (key, value) {
            (None, _) => break 'cli,
            (Some(_), None) => {
                print_help();
                return None;
            }
            (Some(key_str), Some(value_str)) => {
                if key_str == *HELP_SYMBOL || value_str == *HELP_SYMBOL {
                    print_help();
                    return None;
                } else {
                    if default.set(key_str.replace("-", ""), value_str).is_err() {
                        print_help();
                        return None;
                    }
                }
            }
        }
    }

    Some(default)
}

#[cfg(test)]
mod test {
    use log::Level;

    use super::*;
    #[test]
    fn test_default() {
        let args = ["aadvice"].iter().map(|s| s.to_string());
        let default_config = Configuration::default();
        let config = parse_args(args);

        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.watch_file, default_config.watch_file);
        assert_eq!(config.log_level, Level::Info);
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
            "--log_level",
            "debug",
        ]
        .iter()
        .map(|s| s.to_string());

        let config = parse_args(args);
        assert!(config.is_some());
        let config = config.unwrap();

        assert_eq!(config.watch_file, "/var/log/audit.log".to_owned());
        assert_eq!(config.log_level, Level::Debug)
    }
}
