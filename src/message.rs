use std::{collections::HashMap, sync::LazyLock};

use dbus::arg::{AppendAll, IterAppend, RefArg, Variant};
use log::trace;
use regex::Regex;

static RE_OPERATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#".*operation="(?<operation>\S+)".*"#).unwrap());
static RE_PROFILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#".*profile="(?<profile>\S+)".*"#).unwrap());
static RE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#".*name="(?<name>\S+)".*"#).unwrap());
static RE_REQ_MASK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#".*requested_mask="(?<requested_mask>\S+)".*"#).unwrap());
static RE_DEN_MASK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#".*denied_mask="(?<denied_mask>\S+)".*"#).unwrap());
static RE_FSUID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#".*fsuid=(?<fsuid>\S+).*"#).unwrap());

static MISSING_VALUE: &str = "unidentified";

pub struct NotificationMessage {
    app_name: String,     //<arg direction="in" type="s" name="app_name"/>
    replaces_id: u32,     //<arg direction="in" type="u" name="replaces_id"/>
    app_icon: String,     //<arg direction="in" type="s" name="app_icon"/>
    pub summary: String,  //<arg direction="in" type="s" name="summary"/>
    body: String,         //<arg direction="in" type="s" name="body"/>
    actions: Vec<String>, //<arg direction="in" type="as" name="actions"/>
    hints: HashMap<String, Variant<Box<dyn RefArg>>>, //<arg direction="in" type="a{sv}" name="hints"/>
    timeout: i32, //<arg direction="in" type="i" name="timeout"/>
}

impl NotificationMessage {
    pub fn new(log_line: String) -> Self {
        let (operation, profile, name, requested_mask, denied_mask, fsuid) = Self::parse(&log_line);

        let app_name = "AppArmor DENIED".to_string();
        let replaces_id: u32 = 0; // TOTO: check if optional and remove
        let app_icon: String = "🛡️".to_string(); // Fix icon
        let summary: String = format!("profile '{}'", profile);
        let body: String = format!(
            r#"<b>operation</b>: {}
            <b>name</b>: {}
            <b>requested_mask</b>: {}
            <b>denied_mask</b>: {}
            <b>fsuid</b>: {}"#,
            operation, name, requested_mask, denied_mask, fsuid
        );

        let actions: Vec<String> = vec![];
        let hints: HashMap<String, Variant<Box<dyn RefArg>>> = HashMap::new();
        let timeout: i32 = 3000;

        Self {
            app_name,
            replaces_id,
            app_icon,
            summary,
            body,
            actions,
            hints,
            timeout,
        }
    }

    fn parse(log_line: &String) -> (&str, &str, &str, &str, &str, &str) {
        let operation = match RE_OPERATION.captures(log_line) {
            Some(c) => match c.get(1) {
                Some(f) => f.as_str(),
                None => MISSING_VALUE,
            },
            None => MISSING_VALUE,
        };
        let profile = match RE_PROFILE.captures(log_line) {
            Some(c) => match c.get(1) {
                Some(f) => f.as_str(),
                None => MISSING_VALUE,
            },
            None => MISSING_VALUE,
        };
        let name = match RE_NAME.captures(log_line) {
            Some(c) => match c.get(1) {
                Some(f) => f.as_str(),
                None => MISSING_VALUE,
            },
            None => MISSING_VALUE,
        };
        let requested_mask = match RE_REQ_MASK.captures(log_line) {
            Some(c) => match c.get(1) {
                Some(f) => f.as_str(),
                None => MISSING_VALUE,
            },
            None => MISSING_VALUE,
        };
        let denied_mask = match RE_DEN_MASK.captures(log_line) {
            Some(c) => match c.get(1) {
                Some(f) => f.as_str(),
                None => MISSING_VALUE,
            },
            None => MISSING_VALUE,
        };
        let fsuid = match RE_FSUID.captures(log_line) {
            Some(c) => match c.get(1) {
                Some(f) => f.as_str(),
                None => MISSING_VALUE,
            },
            None => MISSING_VALUE,
        };
        (operation, profile, name, requested_mask, denied_mask, fsuid)
    }
}

impl AppendAll for NotificationMessage {
    fn append(&self, i: &mut IterAppend) {
        RefArg::append(&self.app_name, i);
        RefArg::append(&self.replaces_id, i);
        RefArg::append(&self.app_icon, i);
        RefArg::append(&self.summary, i);
        RefArg::append(&self.body, i);
        RefArg::append(&self.actions, i);
        RefArg::append(&self.hints, i);
        RefArg::append(&self.timeout, i);
        trace!("Serialized data for D-Bus");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dbus::Message;

    #[test]
    fn test_field_extraction() {
        let log_line = r#"type=AVC msg=audit(1766919496.539:48806): apparmor="DENIED" operation="file_mmap" class="file" profile="chromium_browser//sanitized_helper" name="/usr/lib/libKF6PurposeWidgets.so.6.21.0" pid=6044 comm="plasma-browser-" requested_mask="m" denied_mask="m" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#.to_owned();
        let message = NotificationMessage::new(log_line);
        assert!(message.summary == "profile 'chromium_browser//sanitized_helper'");
        assert!(message.body.contains("file_mmap"));
        assert!(
            message
                .body
                .contains("/usr/lib/libKF6PurposeWidgets.so.6.21.0")
        );
        assert!(message.body.contains("m"));
    }

    #[test]
    fn test_field_extraction_non_canonical_order() {
        let log_line = r#"type=AVC msg=audit(1766919496.539:48806): apparmor="DENIED" class="file" profile="chromium_browser//sanitized_helper" operation="file_mmap" pid=6044 comm="plasma-browser-" requested_mask="m" denied_mask="m" name="/usr/lib/libKF6PurposeWidgets.so.6.21.0" fsuid=1000 ouid=0FSUID="zar3bski" OUID="root""#.to_owned();
        let message = NotificationMessage::new(log_line);
        assert!(message.summary == "profile 'chromium_browser//sanitized_helper'");
        assert!(message.body.contains("file_mmap"));
        assert!(
            message
                .body
                .contains("/usr/lib/libKF6PurposeWidgets.so.6.21.0")
        );
        assert!(message.body.contains("m"));
    }

    #[test]
    fn test_field_extraction_missing_fields() {
        let log_line = r#"type=AVC msg=audit(1766919496.539:48806): apparmor="DENIED" class="file" operation="file_mmap" pid=6044 comm="plasma-browser-" requested_mask="m" denied_mask="m" name="/usr/lib/libKF6PurposeWidgets.so.6.21.0" ouid=0FSUID="zar3bski" OUID="root""#.to_owned();
        let message = NotificationMessage::new(log_line);
        assert!(message.summary == "profile 'unidentified'");
        assert!(message.body.contains("file_mmap"));
        assert!(
            message
                .body
                .contains("/usr/lib/libKF6PurposeWidgets.so.6.21.0")
        );
        assert!(message.body.contains("m"));
    }
}
