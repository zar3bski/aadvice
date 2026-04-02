use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    thread::{sleep, spawn},
    time::Duration,
};

use inotify::{EventMask, Inotify, WatchMask};
use log::{debug, info, trace, warn};
use regex::Regex;

use crate::{conf::Configuration, message::NotificationMessage};

pub struct Parser {
    watch_file: String,
    reader: BufReader<File>,
    cancel_token: Arc<AtomicBool>,
    out_queue: Sender<NotificationMessage>,
    watcher: Inotify,
}

impl Parser {
    pub fn new(
        kill_switch: &Arc<AtomicBool>,
        conf: &Configuration,
        out_queue: Sender<NotificationMessage>,
    ) -> Self {
        let watch_file = conf.watch_file.clone();
        let watcher = Inotify::init().expect("Error while initializing inotify instance");
        watcher
            .watches()
            .add(&watch_file, WatchMask::MOVE_SELF | WatchMask::MODIFY)
            .expect(format!("Failed to watch for file modifications of {}", watch_file).as_str());

        let cancel_token = kill_switch.clone();

        let reader = BufReader::new(
            File::open(&watch_file).expect(format!("Could not read {}", &watch_file).as_str()),
        );

        Self {
            watch_file,
            reader,
            cancel_token,
            out_queue,
            watcher,
        }
    }

    fn read_lines(&mut self) {
        debug!("Reading lines from {}", self.watch_file);
        let mut buffer = String::new();
        loop {
            buffer.clear();
            match self.reader.read_line(&mut buffer) {
                Err(_) => break,
                Ok(0) => break,
                Ok(_) => match Self::filter(buffer.trim_end().to_string()) {
                    Some(message) => {
                        let _ = self.out_queue.send(message);
                    }
                    None => {
                        trace!("Line filtered out: {}", &buffer);
                    }
                },
            }
        }
    }

    pub fn rotate(&mut self) {
        info!("Log rotation detected, switching to the new log file");
        let mut attempt: u8 = 0;
        'wait_for_new_log_file: loop {
            match self.watcher.watches().add(
                self.watch_file.clone(),
                WatchMask::MOVE_SELF | WatchMask::MODIFY,
            ) {
                Ok(_) => {
                    break 'wait_for_new_log_file;
                }
                Err(_) => {
                    sleep(Duration::from_millis(10));
                    attempt += 1
                }
            }
            if attempt == 10 {
                panic!("New log file not detected during rotation")
            }
        }

        self.reader = BufReader::new(
            File::open(&self.watch_file)
                .expect(format!("Could not read {}", self.watch_file).as_str()),
        );
    }

    pub fn parse(mut self) {
        let mut buffer = [0; 1024];
        debug!("Parser: started");

        spawn(move || {
            'parse_loop: loop {
                if self.cancel_token.load(Ordering::Relaxed) == true {
                    debug!("Parser: cancellation token received");
                    drop(self.reader);
                    break 'parse_loop;
                }

                match self.watcher.read_events_blocking(&mut buffer) {
                    Ok(events) => {
                        for event in events {
                            match event.mask {
                                EventMask::MOVE_SELF => {
                                    self.rotate();
                                    self.read_lines();
                                }
                                EventMask::MODIFY => self.read_lines(),
                                e => {
                                    info!("inode event: {e:?}")
                                }
                            }
                        }
                    }
                    Err(_) => {
                        warn!("Could not read inotify events of {}", &self.watch_file);
                    }
                };
            }
        });
    }

    fn filter(log_line: String) -> Option<NotificationMessage> {
        let denied_regex =
            Regex::new(r#"^type=AVC.*apparmor="DENIED".*profile="(?<profile>[\w\/]+)".*$"#)
                .unwrap();
        match denied_regex.captures(&log_line) {
            Some(c) => {
                let message = NotificationMessage::new(log_line);
                Some(message)
            }
            None => {
                debug!("Line did not match DENIED regex: {log_line}");
                None
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        fs::{self, File, create_dir, create_dir_all, remove_dir_all},
        io::Write,
        sync::atomic::Ordering,
        thread::sleep,
        time::Duration,
    };

    use ntest::timeout;

    use crate::logger::set_multithread_logger;

    use super::*;

    const THREAD_LATENCY: Duration = Duration::from_millis(50);

    #[macro_export]
    macro_rules! test_dir {
        ( $( $x:expr ),* ) => {{
            use rand::distr::{Alphanumeric, SampleString};
            let _ = create_dir_all("./test/.tmp");
            let test_id = Alphanumeric.sample_string(&mut rand::rng(), 16);
            let test_folder_path = format!("./test/.tmp/{}", test_id);
            let log_path = format!("{}/audit.log", &test_folder_path);
            let _ = create_dir(&test_folder_path);

            (test_folder_path, log_path)
        }};
    }

    #[macro_export]
    macro_rules! test_channels {
        ( $( $x:expr ),* ) => {{
            use std::sync::atomic::AtomicBool;
            use std::sync::mpsc::channel;
            let kill_switch = Arc::new(AtomicBool::new(false));
            let (to_send_in, to_send_out) = channel::<NotificationMessage>();
            (kill_switch, to_send_in, to_send_out)
        }};
    }

    #[test]
    fn test_filtering_denied() {
        let line = r#"type=AVC msg=audit(1766919496.539:48806): apparmor="DENIED" operation="file_mmap" class="file" profile="chromium_browser//sanitized_helper" name="/usr/lib/libKF6PurposeWidgets.so.6.21.0" pid=6044 comm="plasma-browser-" requested_mask="m" denied_mask="m" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"#;
        let result = Parser::filter(line.to_string());
        assert!(result.is_some());
    }

    #[test]
    #[timeout(1000)]
    fn test_filtering_allowed() {
        let line = r#"type=AVC msg=audit(1766919791.036:114674): apparmor="ALLOWED" operation="recvmsg" class="net" info="failed af match" error=-13 profile="firefox" pid=2995 comm=536F636B657420546872656164 laddr=192.168.242.104 lport=36884 faddr=184.105.99.43 fport=443 family="inet" sock_type="stream" protocol=6 requested_mask="receive" denied_mask="receive""#;
        let result = Parser::filter(line.to_string());
        assert!(result.is_none())
    }
    #[test]
    #[timeout(1000)]
    fn test_capture_denied() {
        let (test_folder_path, log_path) = test_dir!();
        let (kill_switch, to_send_in, to_send_out) = test_channels!();
        let config = Configuration {
            watch_file: log_path.to_owned(),
            log_level: log::LevelFilter::Debug,
        };
        {
            let mut file = match File::create(&log_path) {
                Ok(file) => file,
                Err(e) => {
                    println!("{} could not be created: {}", &log_path, e);
                    panic!()
                }
            };

            let parser = Parser::new(&kill_switch, &config, to_send_in.clone());
            parser.parse();
            let _ = file.write(
                br#"
type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"
type=AVC msg=audit(1773304077.386:5114): apparmor="ALLOWED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"
type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"
"#).unwrap();

            let _ = file.write(br#"type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#).unwrap();

            for _ in 0..3 {
                // should get 3 messages
                assert!(to_send_out.recv().is_ok());
            }

            kill_switch.store(true, Ordering::Relaxed);
        }
        let _ = remove_dir_all(&test_folder_path);
    }

    #[test]
    #[timeout(2000)]
    fn test_log_rotation() {
        set_multithread_logger(log::LevelFilter::Trace);
        let (test_folder_path, log_path) = test_dir!();
        let (kill_switch, to_send_in, to_send_out) = test_channels!();
        let config = Configuration {
            watch_file: log_path.to_owned(),
            log_level: log::LevelFilter::Debug,
        };

        {
            let mut file = match File::create(&log_path) {
                Ok(file) => file,
                Err(e) => {
                    println!("{} could not be created: {}", &log_path, e);
                    panic!()
                }
            };

            let parser = Parser::new(&kill_switch, &config, to_send_in.clone());
            parser.parse();

            let _ = file.write(
                br#"type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#).unwrap();
            sleep(THREAD_LATENCY);
            // file rotation
            fs::rename(&log_path, format!("{}.1", &log_path)).unwrap();
            let mut file = match File::create(&log_path) {
                Ok(file) => file,
                Err(e) => {
                    println!("{} could not be created: {}", &log_path, e);
                    panic!()
                }
            };

            let _ = file.write(
                br#"type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#).unwrap();

            sleep(THREAD_LATENCY);
            // file rotation
            fs::rename(&log_path, format!("{}.2", &log_path)).unwrap();
            let mut file = match File::create(&log_path) {
                Ok(file) => file,
                Err(e) => {
                    println!("{} could not be created: {}", &log_path, e);
                    panic!()
                }
            };
            let _ = file.write(
                br#"type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#).unwrap();

            for _ in 0..3 {
                // should get 3 messages
                assert!(to_send_out.recv().is_ok());
            }
        }
        let _ = remove_dir_all(&test_folder_path);
    }

    #[test]
    fn test_ignore_preexisting() {
        let (test_folder_path, log_path) = test_dir!();
        let (kill_switch, to_send_in, to_send_out) = test_channels!();
        let config = Configuration {
            watch_file: log_path.to_owned(),
            log_level: log::LevelFilter::Debug,
        };

        {
            let mut file = match File::create(&log_path) {
                Ok(file) => file,
                Err(e) => {
                    println!("{} could not be created: {}", &log_path, e);
                    panic!()
                }
            };

            // messages....
            let _ = file.write(
                br#"
type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"
type=AVC msg=audit(1773304077.386:5114): apparmor="ALLOWED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"
type=AVC msg=audit(1773304077.386:5114): apparmor="DENIED" operation="file_inherit" class="file" profile="id" name="/dev/dri/renderD128" pid=9108 comm="id" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root"
"#).unwrap();

            // ...that pre-exist parser instantiation
            let parser = Parser::new(&kill_switch, &config, to_send_in.clone());
            parser.parse();
            sleep(THREAD_LATENCY);

            // should not end up in the channel
            assert!(to_send_out.try_recv().is_err());
        }
        let _ = remove_dir_all(&test_folder_path);
    }
}
