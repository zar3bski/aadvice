use std::sync::mpsc::{self, Sender};

use log::{Level, Metadata, Record};

pub struct SimpleLogger {
    pub sender: Sender<String>,
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        self.sender
            .send(format!("{} - {}", record.level(), record.args()))
            .unwrap();
    }

    fn flush(&self) {}
}

pub fn set_multithread_logger() {
    let (log_sender, log_receiver) = mpsc::channel();

    log::set_boxed_logger(Box::new(SimpleLogger { sender: log_sender })).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    std::thread::spawn(move || {
        while let Ok(msg) = log_receiver.recv() {
            eprintln!("{msg}");
        }
        eprintln!("[log sender dropped]");
    });
}
