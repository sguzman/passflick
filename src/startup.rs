use std::time::Instant;

#[derive(Clone)]
pub struct StartupTrace {
    start: Option<Instant>,
}

impl StartupTrace {
    pub fn from_env() -> Self {
        let enabled = std::env::var_os("PASSFLICK_TRACE_STARTUP").is_some();
        Self {
            start: enabled.then(Instant::now),
        }
    }

    pub fn mark(&self, label: &str) {
        if let Some(start) = self.start {
            eprintln!("passflick-startup {label} {}us", start.elapsed().as_micros());
        }
    }
}
