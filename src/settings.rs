//! Runtime settings.
//!
//! Everything here lives in the SQLite `settings` table and is editable from
//! the admin UI at `/admin/settings`. Only the data directory and the initial
//! web bind address come from the environment (see [`crate::config::BootConfig`]),
//! because the database lives in the former and the admin needs the latter to
//! reach the UI at all.

use std::collections::HashMap;

/// How long a certificate may have left before ACME tries to renew it.
pub const DEFAULT_RENEW_BEFORE_DAYS: i64 = 30;

pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    // ---- identity ----
    /// Hostname in the SMTP banner and in the self-signed certificate.
    pub hostname: String,

    // ---- listeners ----
    /// Plaintext SMTP listener, which also offers STARTTLS.
    pub smtp_addr: String,
    /// Implicit-TLS SMTP listener (SMTPS).
    pub smtps_addr: String,
    /// HTTPS listener for the web UI. Empty disables it.
    pub https_addr: String,

    // ---- mail behaviour ----
    /// How long captured messages are kept before they vanish.
    pub retention_secs: u64,
    /// Maximum messages per mailbox; the oldest is evicted past this.
    pub mailbox_cap: usize,
    /// Maximum accepted message size in bytes (advertised via SIZE).
    pub max_message_size: usize,
    /// Maximum SMTP credentials per user account.
    pub max_credentials_per_user: i64,

    // ---- web / security ----
    /// Set the Secure flag on session cookies.
    pub cookie_secure: bool,
    /// Whether anyone may create an account.
    pub registration_open: bool,
    /// Registrations allowed per client IP per hour.
    pub registrations_per_hour: u32,

    // ---- Let's Encrypt / ACME ----
    pub acme_enabled: bool,
    /// ACME directory URL (production or staging).
    pub acme_directory: String,
    /// Contact address registered with the CA. Empty means no contact.
    pub acme_contact_email: String,
    /// Domains to request the certificate for.
    pub acme_domains: Vec<String>,
    /// Bind address of the dedicated HTTP-01 challenge listener.
    pub acme_http_addr: String,
    /// The operator has accepted the CA's terms of service.
    pub acme_tos_agreed: bool,
    /// Renew once the certificate has fewer than this many days left.
    pub acme_renew_before_days: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            hostname: "smtpvoid.local".to_string(),
            // The standard submission ports (RFC 6409 / RFC 8314). Both are
            // privileged, so an unprivileged process needs CAP_NET_BIND_SERVICE
            // or a port redirect; the listener supervisor reports a failed bind
            // and leaves the web UI up so the ports can be changed there.
            smtp_addr: "0.0.0.0:587".to_string(),
            smtps_addr: "0.0.0.0:465".to_string(),
            https_addr: String::new(),
            retention_secs: 3600,
            mailbox_cap: 100,
            max_message_size: 1_048_576,
            max_credentials_per_user: 20,
            cookie_secure: false,
            registration_open: true,
            registrations_per_hour: 10,
            acme_enabled: false,
            acme_directory: LETSENCRYPT_PRODUCTION.to_string(),
            acme_contact_email: String::new(),
            acme_domains: Vec::new(),
            acme_http_addr: "0.0.0.0:80".to_string(),
            acme_tos_agreed: false,
            acme_renew_before_days: DEFAULT_RENEW_BEFORE_DAYS,
        }
    }
}

/// Split a comma/whitespace separated domain list into a clean vector.
pub fn parse_domains(s: &str) -> Vec<String> {
    s.split([',', ' ', '\t', '\n', '\r', ';'])
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .collect()
}

fn get<'a>(map: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    map.get(key).map(String::as_str).filter(|v| !v.is_empty())
}

fn get_bool(map: &HashMap<String, String>, key: &str, default: bool) -> bool {
    match map.get(key).map(String::as_str) {
        Some("1") | Some("true") => true,
        Some("0") | Some("false") => false,
        _ => default,
    }
}

impl Settings {
    /// Build settings from stored key/value pairs, falling back to defaults for
    /// anything missing or unparseable. A corrupt row must never stop startup.
    pub fn from_pairs(map: &HashMap<String, String>) -> Self {
        let d = Settings::default();
        Settings {
            hostname: get(map, "hostname").unwrap_or(&d.hostname).to_string(),
            smtp_addr: get(map, "smtp_addr").unwrap_or(&d.smtp_addr).to_string(),
            smtps_addr: get(map, "smtps_addr").unwrap_or(&d.smtps_addr).to_string(),
            // Empty is meaningful here (disabled), so read it directly.
            https_addr: map.get("https_addr").cloned().unwrap_or(d.https_addr),
            retention_secs: get(map, "retention_secs")
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.retention_secs),
            mailbox_cap: get(map, "mailbox_cap")
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.mailbox_cap),
            max_message_size: get(map, "max_message_size")
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.max_message_size),
            max_credentials_per_user: get(map, "max_credentials_per_user")
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.max_credentials_per_user),
            cookie_secure: get_bool(map, "cookie_secure", d.cookie_secure),
            registration_open: get_bool(map, "registration_open", d.registration_open),
            registrations_per_hour: get(map, "registrations_per_hour")
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.registrations_per_hour),
            acme_enabled: get_bool(map, "acme_enabled", d.acme_enabled),
            acme_directory: get(map, "acme_directory").unwrap_or(&d.acme_directory).to_string(),
            acme_contact_email: map
                .get("acme_contact_email")
                .cloned()
                .unwrap_or(d.acme_contact_email),
            acme_domains: map
                .get("acme_domains")
                .map(|v| parse_domains(v))
                .unwrap_or(d.acme_domains),
            acme_http_addr: get(map, "acme_http_addr").unwrap_or(&d.acme_http_addr).to_string(),
            acme_tos_agreed: get_bool(map, "acme_tos_agreed", d.acme_tos_agreed),
            acme_renew_before_days: get(map, "acme_renew_before_days")
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.acme_renew_before_days),
        }
    }

    /// Flatten into the key/value rows stored in the database.
    pub fn to_pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("hostname", self.hostname.clone()),
            ("smtp_addr", self.smtp_addr.clone()),
            ("smtps_addr", self.smtps_addr.clone()),
            ("https_addr", self.https_addr.clone()),
            ("retention_secs", self.retention_secs.to_string()),
            ("mailbox_cap", self.mailbox_cap.to_string()),
            ("max_message_size", self.max_message_size.to_string()),
            ("max_credentials_per_user", self.max_credentials_per_user.to_string()),
            ("cookie_secure", bool_str(self.cookie_secure)),
            ("registration_open", bool_str(self.registration_open)),
            ("registrations_per_hour", self.registrations_per_hour.to_string()),
            ("acme_enabled", bool_str(self.acme_enabled)),
            ("acme_directory", self.acme_directory.clone()),
            ("acme_contact_email", self.acme_contact_email.clone()),
            ("acme_domains", self.acme_domains.join(",")),
            ("acme_http_addr", self.acme_http_addr.clone()),
            ("acme_tos_agreed", bool_str(self.acme_tos_agreed)),
            ("acme_renew_before_days", self.acme_renew_before_days.to_string()),
        ]
    }

    /// Names the TLS certificate should cover: the ACME domains when ACME is
    /// configured, otherwise the SMTP hostname.
    pub fn cert_names(&self) -> Vec<String> {
        if self.acme_enabled && !self.acme_domains.is_empty() {
            self.acme_domains.clone()
        } else {
            vec![self.hostname.clone()]
        }
    }

    /// What a mail client should be told to connect to for a listener: the
    /// announced hostname with that listener's port. The bind address itself
    /// names a local interface (`0.0.0.0:587` and friends) and is meaningless
    /// to anyone on the other end of the connection.
    pub fn endpoint(&self, bind_addr: &str) -> String {
        match port_of(bind_addr) {
            Some(port) => format!("{}:{port}", self.hostname),
            None => self.hostname.clone(),
        }
    }

    /// Reject anything that would break the server or lock the admin out.
    /// Returns a human-readable message describing the first problem found.
    pub fn validate(&self) -> Result<(), String> {
        if !valid_hostname(&self.hostname) {
            return Err("Hostname must be a plain DNS name (letters, digits, - and .)".into());
        }
        check_addr("SMTP bind address", &self.smtp_addr, false)?;
        check_addr("SMTPS bind address", &self.smtps_addr, false)?;
        check_addr("HTTPS bind address", &self.https_addr, true)?;

        if self.smtp_addr == self.smtps_addr {
            return Err("SMTP and SMTPS cannot share the same bind address".into());
        }
        if !self.https_addr.is_empty()
            && (self.https_addr == self.smtp_addr || self.https_addr == self.smtps_addr)
        {
            return Err("HTTPS cannot share a bind address with an SMTP listener".into());
        }

        if !(60..=30 * 86_400).contains(&self.retention_secs) {
            return Err("Retention must be between 60 seconds and 30 days".into());
        }
        if !(1..=100_000).contains(&self.mailbox_cap) {
            return Err("Mailbox capacity must be between 1 and 100000".into());
        }
        if !(1024..=256 * 1024 * 1024).contains(&self.max_message_size) {
            return Err("Max message size must be between 1 KiB and 256 MiB".into());
        }
        if !(1..=1000).contains(&self.max_credentials_per_user) {
            return Err("Credentials per user must be between 1 and 1000".into());
        }
        if !(1..=10_000).contains(&self.registrations_per_hour) {
            return Err("Registrations per hour must be between 1 and 10000".into());
        }

        if self.acme_enabled {
            if self.acme_domains.is_empty() {
                return Err("Let's Encrypt needs at least one domain".into());
            }
            if let Some(bad) = self.acme_domains.iter().find(|d| !valid_hostname(d)) {
                return Err(format!("'{bad}' is not a valid domain name"));
            }
            if self.acme_domains.len() > 100 {
                return Err("At most 100 domains per certificate".into());
            }
            if !self.acme_tos_agreed {
                return Err("You must accept the CA's terms of service to enable Let's Encrypt".into());
            }
            if !self.acme_directory.starts_with("https://") {
                return Err("The ACME directory must be an https:// URL".into());
            }
            if !self.acme_contact_email.is_empty() && !self.acme_contact_email.contains('@') {
                return Err("The ACME contact must be an email address".into());
            }
            check_addr("ACME challenge bind address", &self.acme_http_addr, true)?;
            if self.acme_http_addr.is_empty() {
                return Err("Let's Encrypt needs an HTTP-01 challenge bind address (usually 0.0.0.0:80)".into());
            }
            if !(1..=80).contains(&self.acme_renew_before_days) {
                return Err("Renewal window must be between 1 and 80 days".into());
            }
        }
        Ok(())
    }
}

/// The message-size limit is stored (and advertised over SMTP) in bytes, but
/// the settings form edits it in mebibytes, which is how operators think of it.
pub const MIB: usize = 1024 * 1024;

/// A byte count as the MiB number to put in a form field. Six decimals resolve
/// to about a byte, so a value that was never edited comes back unchanged.
pub fn bytes_as_mib(bytes: usize) -> String {
    let text = format!("{:.6}", bytes as f64 / MIB as f64);
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() { "0" } else { trimmed }.to_string()
}

/// The inverse of [`bytes_as_mib`]. `None` for anything that is not a
/// non-negative number; the range itself is left to [`Settings::validate`].
pub fn mib_as_bytes(raw: &str) -> Option<usize> {
    let mib = raw.trim().parse::<f64>().ok()?;
    if !mib.is_finite() || mib < 0.0 {
        return None;
    }
    let bytes = (mib * MIB as f64).round();
    if bytes > usize::MAX as f64 {
        return None;
    }
    Some(bytes as usize)
}

/// The port half of a `host:port` bind address, if it has a usable one.
fn port_of(addr: &str) -> Option<u16> {
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    port.parse::<u16>().ok().filter(|p| *p > 0)
}

fn bool_str(b: bool) -> String {
    if b { "1" } else { "0" }.to_string()
}

/// Accept `host:port` where the port is a valid, non-zero u16. The host part is
/// left to the resolver, which is what `TcpListener::bind` uses anyway.
fn check_addr(label: &str, addr: &str, allow_empty: bool) -> Result<(), String> {
    if addr.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(format!("{label} cannot be empty"))
        };
    }
    let port = match addr.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => port,
        _ => return Err(format!("{label} must be in host:port form, e.g. 0.0.0.0:587")),
    };
    match port.parse::<u16>() {
        Ok(p) if p > 0 => Ok(()),
        _ => Err(format!("{label} has an invalid port")),
    }
}

fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('.')
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '*')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_pairs() {
        let d = Settings::default();
        let map: HashMap<String, String> = d
            .to_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        assert_eq!(Settings::from_pairs(&map), d);
    }

    #[test]
    fn missing_keys_fall_back_to_defaults() {
        let map = HashMap::from([("hostname".to_string(), "mail.example.test".to_string())]);
        let s = Settings::from_pairs(&map);
        assert_eq!(s.hostname, "mail.example.test");
        assert_eq!(s.retention_secs, Settings::default().retention_secs);
    }

    #[test]
    fn garbage_numbers_fall_back_instead_of_panicking() {
        let map = HashMap::from([("retention_secs".to_string(), "not-a-number".to_string())]);
        assert_eq!(
            Settings::from_pairs(&map).retention_secs,
            Settings::default().retention_secs
        );
    }

    #[test]
    fn domain_lists_are_normalised() {
        assert_eq!(
            parse_domains(" Mail.Example.test., ,smtp.example.test\nother.test "),
            vec!["mail.example.test", "smtp.example.test", "other.test"]
        );
    }

    #[test]
    fn defaults_validate() {
        assert!(Settings::default().validate().is_ok());
    }

    #[test]
    fn listeners_may_not_collide() {
        let mut s = Settings::default();
        s.smtps_addr = s.smtp_addr.clone();
        assert!(s.validate().is_err());
    }

    #[test]
    fn acme_requires_domains_and_tos() {
        let mut s = Settings { acme_enabled: true, ..Default::default() };
        assert!(s.validate().is_err(), "no domains");
        s.acme_domains = vec!["mail.example.test".into()];
        assert!(s.validate().is_err(), "terms not agreed");
        s.acme_tos_agreed = true;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn message_size_round_trips_through_the_mib_field() {
        for bytes in [1024_usize, 1_048_576, 1_572_864, 1_000_000, 256 * 1024 * 1024] {
            let shown = bytes_as_mib(bytes);
            assert_eq!(mib_as_bytes(&shown), Some(bytes), "{bytes} shown as {shown}");
        }
        assert_eq!(bytes_as_mib(1_048_576), "1");
        assert_eq!(bytes_as_mib(1_572_864), "1.5");
        assert_eq!(mib_as_bytes(" 2 "), Some(2 * 1024 * 1024));
        assert_eq!(mib_as_bytes("half a meg"), None);
        assert_eq!(mib_as_bytes("-1"), None);
    }

    #[test]
    fn endpoint_pairs_the_hostname_with_the_listener_port() {
        let s = Settings {
            hostname: "mail.example.com".into(),
            smtp_addr: "0.0.0.0:587".into(),
            smtps_addr: "[::]:465".into(),
            ..Default::default()
        };
        assert_eq!(s.endpoint(&s.smtp_addr), "mail.example.com:587");
        assert_eq!(s.endpoint(&s.smtps_addr), "mail.example.com:465");
        // Nothing usable to append: better a bare hostname than "host:".
        assert_eq!(s.endpoint(""), "mail.example.com");
        assert_eq!(s.endpoint("0.0.0.0:0"), "mail.example.com");
    }

    #[test]
    fn empty_https_addr_is_allowed_but_empty_smtp_is_not() {
        let mut s = Settings { https_addr: String::new(), ..Default::default() };
        assert!(s.validate().is_ok());
        s.smtp_addr = String::new();
        assert!(s.validate().is_err());
    }
}
