use std::{
    sync::mpsc,
    thread::{sleep, spawn},
    time::{self, Duration},
};

use dbus::blocking::{Connection, Proxy};
use log::{LevelFilter, info};

use crate::{
    logger::{SimpleLogger, set_multithread_logger},
    message::NotificationMessage,
    service::DBusService,
};

mod logger;
mod message;
mod service;

const DESTINATION: &str = "org.freedesktop.Notifications";
const INTERFACE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

fn main() {
    set_multithread_logger();

    let (to_send_in, to_send_out) = mpsc::channel::<NotificationMessage>();

    let service = DBusService::new();
    service.unpile(to_send_out);

    let message = NotificationMessage::new("some application".to_string());
    to_send_in.send(message).unwrap();

    loop {}
}
