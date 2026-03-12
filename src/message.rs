use std::collections::HashMap;

use dbus::arg::{AppendAll, IterAppend, RefArg, Variant};
use log::trace;

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
    pub fn new(profile_name: String) -> Self {
        let app_name = "AppArmor".to_string();
        let replaces_id: u32 = 0;
        let app_icon: String = "".to_string();
        let summary: String = format!("DENIED {}", profile_name);
        let body: String = "".to_string();
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
