use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
    },
    thread::spawn,
    time::Duration,
};

use dbus::blocking::{Connection, Proxy};
use log::{debug, warn};

use crate::{DESTINATION, INTERFACE, PATH, conf::Configuration, message::NotificationMessage};

pub struct DBusService {
    connection: Connection,
    inbound: Receiver<NotificationMessage>,
    cancel_token: Arc<AtomicBool>,
}

impl DBusService {
    pub fn new(
        kill_swith: &Arc<AtomicBool>,
        _config: &Configuration,
        inbound: Receiver<NotificationMessage>,
    ) -> Self {
        let cancel_token = kill_swith.clone();
        let connection = Connection::new_session().expect("D-Bus connection failed");
        Self {
            connection,
            inbound,
            cancel_token,
        }
    }

    pub fn unpile(self) {
        debug!("Start unpiling messages");
        spawn(move || {
            let proxy: Proxy<'_, &Connection> =
                self.connection
                    .with_proxy(DESTINATION, PATH, Duration::from_millis(5000));

            'unpile: loop {
                match self.inbound.recv() {
                    Ok(m) => {
                        let resp: Result<(u32,), dbus::Error> =
                            proxy.method_call(INTERFACE, "Notify", m);
                        match resp {
                            Ok(code) => {
                                debug!(
                                    "Message successfully forwarded to {INTERFACE}: code {code:?}"
                                )
                            }
                            Err(e) => {
                                warn!("Failed to forward message through D-bus: {e}");
                            }
                        }
                    }
                    Err(_) => {}
                }
                if self.cancel_token.load(Ordering::Relaxed) == true {
                    debug!("DBus service: cancellation token received");
                    break 'unpile;
                }
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_channels;

    #[test]
    fn test_instanciation() {
        let (kill_switch, _to_send_in, to_send_out) = test_channels!();
        let config = Configuration::default();

        let _service = DBusService::new(&kill_switch, &config, to_send_out);
        let _message: NotificationMessage = NotificationMessage::new("toto".to_owned());
    }
}
