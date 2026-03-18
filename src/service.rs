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

use crate::{conf::Configuration, message::NotificationMessage};

const DESTINATION: &str = "org.freedesktop.Notifications";
const INTERFACE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

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
    use std::thread::sleep;

    use super::*;
    use crate::test_channels;

    const THREAD_LATENCY: Duration = Duration::from_millis(50);

    #[test]
    fn test_instanciation() {
        let (kill_switch, _to_send_in, to_send_out) = test_channels!();
        let config = Configuration::default();

        let _service = DBusService::new(&kill_switch, &config, to_send_out);

        let log_line = r#"type=AVC msg=audit(1766919496.539:48806): apparmor="DENIED" operation="file_mmap" class="file" profile="chromium_browser//sanitized_helper" name="/usr/lib/libKF6PurposeWidgets.so.6.21.0" pid=6044 comm="plasma-browser-" requested_mask="m" denied_mask="m" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#.to_owned();
        let _message: NotificationMessage = NotificationMessage::new(log_line);
        let _ = _to_send_in.send(_message);

        let log_line = r#"type=AVC msg=audit(1390876383.602:15646): apparmor="DENIED" operation="open" parent=21147 profile="/tmp/ls" name="/var/log/audit/" pid=21598 comm="ls" requested_mask="r" denied_mask="r" fsuid=0 ouid=0"#.to_owned();
        let _message: NotificationMessage = NotificationMessage::new(log_line);
        let _ = _to_send_in.send(_message);

        _service.unpile();
        sleep(THREAD_LATENCY);
    }
}
