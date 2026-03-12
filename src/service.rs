use std::{
    sync::{Arc, atomic::AtomicBool, mpsc::Receiver},
    thread::{sleep, spawn},
    time::Duration,
};

use dbus::blocking::Connection;
use log::{debug, error, info, trace};

use crate::{DESTINATION, INTERFACE, PATH, TIME_GRANULARITY, message::NotificationMessage};

pub struct DBusService {
    //connection: Connection,
    //proxy: Proxy<'a, &'a Connection>,
}

impl DBusService {
    pub fn new(_kill_swith: Arc<AtomicBool>) -> Self {
        //let proxy = connection.with_proxy(DESTINATION, PATH, Duration::from_millis(5000));

        //Self { proxy }
        Self {}
    }

    //fn proxy(&self) -> Proxy<'a, &'a Connection> {
    //    let connection = Connection::new_session().expect("D-Bus connection failed");
    //    let proxy = connection.with_proxy(DESTINATION, PATH, Duration::from_millis(5000));
    //    proxy
    //}

    pub fn unpile(&self, channel: Receiver<NotificationMessage>) {
        spawn(move || {
            // TODO: move elsewhere
            info!("Setting proxy connection");
            let connection = Connection::new_session().expect("D-Bus connection failed");
            let proxy = connection.with_proxy(DESTINATION, PATH, Duration::from_millis(5000));
            info!("Proxy connection established");
            loop {
                let received = channel.recv();
                debug!("Received message to be sent through D-Bus");
                match received {
                    Ok(message) => {
                        let resp: Result<(u32,), dbus::Error> =
                            proxy.method_call(INTERFACE, "Notify", message);
                        match resp {
                            Ok((code,)) => {
                                debug!("Message send through D-Bus successfully: code: {}", code);
                            }
                            Err(e) => {
                                error!("Could not send notification through D-Bus: {}", e)
                            }
                        }
                        //debug!("Sending message to D-Bus");
                    }
                    Err(_) => {
                        trace!("Nothing in to_send_out");
                    }
                }
                sleep(TIME_GRANULARITY);
            }
        });
    }
}

//impl<'a> DBusService<'a> {
//    fn new() -> Self {
//        let connection = Connection::new_session().expect("D-Bus connection failed");
//        let proxy = connection.with_proxy(DESTINATION, PATH, Duration::from_millis(5000));
//        Self {
//            //connection,
//            proxy,
//        }
//    }
//}

//impl<'a> Default for DBusService<'a> {
//    fn default() -> Self {
//        //let connection = Connection::new_session().expect("D-Bus connection failed");
//        let proxy = Connection::new_session()
//            .expect("D-Bus connection failed")
//            .with_proxy(DESTINATION, PATH, Duration::from_millis(5000));
//        Self {
//            //connection: &connection,
//            proxy: &proxy,
//        }
//    }
//}
