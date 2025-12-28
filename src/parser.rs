use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::mpsc::Sender,
    thread::spawn,
};

use inotify::{Inotify, WatchMask};
use log::{debug, info, trace, warn};
use regex::Regex;

use crate::message::NotificationMessage;

const LOG_FILE: &str = "/var/log/audit/audit.log";

pub struct Parser {
    watcher: Inotify,
    out_queue: Sender<NotificationMessage>,
    reader: BufReader<File>,
}

impl Parser {
    pub fn new(out_queue: Sender<NotificationMessage>) -> Self {
        info!("Instanciating parser for {}", LOG_FILE);
        let mut watcher = Inotify::init().expect("Error while initializing inotify instance");
        watcher
            .watches()
            .add(LOG_FILE, WatchMask::MODIFY)
            .expect("Failed to add file watch");
        // TODO: handle duplicate ressource
        let reader = BufReader::new(
            File::open(LOG_FILE).expect(format!("Could not read {}", LOG_FILE).as_str()),
        );
        Self {
            watcher,
            out_queue,
            reader,
        }
    }

    fn filter(log_line: &String) -> Option<NotificationMessage> {
        let denied_regex =
            Regex::new(r#"^type=AVC.*apparmor="DENIED".*profile="(?<profile>[\w\/]+)".*$"#)
                .unwrap();
        match denied_regex.captures(&log_line) {
            Some(c) => {
                let message =
                    NotificationMessage::new(c.name("profile").unwrap().as_str().to_string());
                Some(message)
            }
            None => {
                debug!("Line did not match DENIED regex: {}", log_line);
                None
            }
        }
    }

    pub fn parse(mut self) {
        spawn(move || {
            let mut buffer = [0; 1024];
            let current_line: u64 = self.reader.lines().count() as u64;
            let reader = BufReader::new(
                File::open(LOG_FILE).expect(format!("Could not read {}", LOG_FILE).as_str()),
            );
            let mut iter = reader.lines().skip(current_line as usize);

            loop {
                // TODO: handle log rotation
                let events = self
                    .watcher
                    .read_events_blocking(&mut buffer)
                    .expect("Error while reading events");

                let event_nb: u64 = events.count() as u64;
                trace!("Found {} modify events on {}", event_nb, LOG_FILE);

                for _ in 0..event_nb {
                    let line = iter.next().unwrap();
                    match line {
                        Ok(line) => match Self::filter(&line) {
                            Some(message) => self
                                .out_queue
                                .send(message)
                                .expect("Could not send message to D-Bus proxy"),
                            None => {
                                trace!("Line filtered out: {}", line)
                            }
                        },
                        Err(e) => {
                            warn!("Could not read line from {}: {}", LOG_FILE, e)
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_filtering_denied() {
        let line = r#"type=AVC msg=audit(1766919496.539:48806): apparmor="DENIED" operation="file_mmap" class="file" profile="chromium_browser//sanitized_helper" name="/usr/lib/libKF6PurposeWidgets.so.6.21.0" pid=6044 comm="plasma-browser-" requested_mask="m" denied_mask="m" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"#;
        let result = Parser::filter(&line.to_string());
        assert!(result.is_some());
        assert!(result.unwrap().summary == "DENIED chromium_browser//sanitized_helper")
    }

    #[test]
    fn test_filtering_allowed() {
        let line = r#"type=AVC msg=audit(1766919791.036:114674): apparmor="ALLOWED" operation="recvmsg" class="net" info="failed af match" error=-13 profile="firefox" pid=2995 comm=536F636B657420546872656164 laddr=192.168.242.104 lport=36884 faddr=184.105.99.43 fport=443 family="inet" sock_type="stream" protocol=6 requested_mask="receive" denied_mask="receive""#;
        let result = Parser::filter(&line.to_string());
        assert!(result.is_none())
    }
}
