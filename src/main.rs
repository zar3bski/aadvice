use std::{
    env,
    process::exit,
    sync::{Arc, atomic::AtomicBool, mpsc},
    thread::sleep,
    time::Duration,
};

use crate::{
    cli::parse_args, conf::Configuration, logger::set_multithread_logger,
    message::NotificationMessage, parser::Parser, service::DBusService,
};

mod cli;
mod conf;
mod logger;
mod message;
mod parser;
mod service;

const DESTINATION: &str = "org.freedesktop.Notifications";
const INTERFACE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";
const TIME_GRANULARITY: Duration = Duration::from_secs(1);

fn main() {
    let config = parse_args(env::args());
    let config = match config {
        Some(config) => config,
        None => exit(1),
    };

    set_multithread_logger(config.log_level);

    let kill_switch = Arc::new(AtomicBool::new(false));
    let (to_send_in, to_send_out) = mpsc::channel::<NotificationMessage>();

    let service = DBusService::new(&kill_switch, &config, to_send_out);
    let parser = Parser::new(&kill_switch, &config, to_send_in);

    parser.parse();
    service.unpile();

    loop {
        sleep(TIME_GRANULARITY);
    }
}
