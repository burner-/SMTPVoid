//! A small one-shot command line for provisioning.
//!
//! The admin UI is still the place to configure a running server, but the
//! domain has to be typed into two fields there (the SMTP hostname and, when
//! Let's Encrypt is on, the certificate domains). An installer only wants to
//! ask for it once, so `smtpvoid set-domain` writes exactly the same settings
//! rows the settings form writes, before the service is ever started.
//!
//! The other command, `smtpvoid set-password`, is the way back in when nobody
//! can sign in any more: the setup token only works until the first admin
//! exists, and an admin cannot reset someone else's password from the UI.
//!
//! Nothing here talks to a running instance: settings are cached in memory, so
//! an already-running server picks the change up on its next restart.

use anyhow::{anyhow, bail, Context, Result};

use crate::config::BootConfig;
use crate::db::Db;
use crate::settings::{parse_domains, Settings, LETSENCRYPT_PRODUCTION, LETSENCRYPT_STAGING};
use crate::tls::{CertSource, CertStore};

pub const USAGE: &str = "\
SMTPVoid - an SMTP black hole for testing mail submission.

Usage:
  smtpvoid                          run the server
  smtpvoid set-domain <domain>...   set the domain, then exit
  smtpvoid set-password <user>      set an account's web password, then exit
  smtpvoid --help                   show this help

set-domain options:
  --letsencrypt        request a certificate for these domains from the CA
  --agree-tos          accept the CA's terms of service (required with --letsencrypt)
  --email ADDR         contact address to register with the CA
  --staging            use the Let's Encrypt staging directory
  --https-addr ADDR    serve the web UI over TLS here too, e.g. 0.0.0.0:443
                       (an empty value turns HTTPS off)

set-password options:
  --admin              also grant this account admin rights

The password is read from standard input, never from an argument, so it stays
out of the shell history and the process list.

The first domain becomes the SMTP hostname; all of them go on the certificate.
Everything else is configured at /admin/settings.

Environment:
  SMTPVOID_DATA_DIR    database, TLS material, ACME state (default ./data)
  SMTPVOID_HTTP_ADDR   plaintext web UI address (default 0.0.0.0:8080)
  RUST_LOG             log filter (default info)";

/// Point the SMTP banner, the certificate and any ACME order at one domain.
pub fn set_domain(args: &[String]) -> Result<()> {
    let request = SetDomain::parse(args)?;

    let boot = BootConfig::from_env();
    std::fs::create_dir_all(&boot.data_dir)
        .with_context(|| format!("cannot create data dir {}", boot.data_dir.display()))?;
    let db = Db::open(&boot.data_dir.join("smtpvoid.db")).context("opening database")?;

    let old = Settings::from_pairs(&db.load_settings().context("reading settings")?);
    let new = request.apply(&old);
    new.validate().map_err(|e| anyhow!("{e}"))?;

    if new == old {
        println!("Already set to {} - nothing to change.", new.hostname);
        return Ok(());
    }
    db.save_settings(&new.to_pairs()).context("saving settings")?;
    report(&new);

    reissue_self_signed_if_needed(&boot, &new)?;
    println!("Saved. A running server applies this on its next restart.");
    Ok(())
}

/// A parsed `set-domain` invocation, kept apart from the database work so the
/// argument handling and the settings it implies can be tested on their own.
#[derive(Debug, Default, PartialEq, Eq)]
struct SetDomain {
    domains: Vec<String>,
    letsencrypt: bool,
    staging: bool,
    email: Option<String>,
    https_addr: Option<String>,
}

impl SetDomain {
    fn parse(args: &[String]) -> Result<SetDomain> {
        let mut out = SetDomain::default();
        let mut agree_tos = false;

        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            let mut value = || -> Result<String> {
                i += 1;
                args.get(i).cloned().ok_or_else(|| anyhow!("{arg} needs a value"))
            };
            match arg {
                "--letsencrypt" => out.letsencrypt = true,
                "--agree-tos" => agree_tos = true,
                "--staging" => out.staging = true,
                "--email" => out.email = Some(value()?),
                "--https-addr" => out.https_addr = Some(value()?),
                other if other.starts_with('-') => bail!("unknown option {other}\n\n{USAGE}"),
                // parse_domains lowercases, drops trailing dots and splits
                // lists, so "a.test, b.test" and two arguments behave alike.
                other => out.domains.extend(parse_domains(other)),
            }
            i += 1;
        }

        if out.domains.is_empty() {
            bail!("set-domain needs at least one domain\n\n{USAGE}");
        }
        if out.letsencrypt && !agree_tos {
            bail!(
                "--letsencrypt also needs --agree-tos: ordering a certificate accepts the CA's \
                 terms of service on your behalf"
            );
        }
        Ok(out)
    }

    /// The settings this request implies. Anything it does not mention is
    /// carried over untouched, so re-running it never resets the rest.
    fn apply(&self, old: &Settings) -> Settings {
        let mut new = old.clone();
        new.hostname = self.domains[0].clone();

        // Retarget an existing ACME configuration even without --letsencrypt:
        // a certificate for the previous domain no longer matches the banner.
        if self.letsencrypt || new.acme_enabled || !new.acme_domains.is_empty() {
            new.acme_domains = self.domains.clone();
        }
        if self.letsencrypt {
            new.acme_enabled = true;
            new.acme_tos_agreed = true;
            new.acme_directory =
                if self.staging { LETSENCRYPT_STAGING } else { LETSENCRYPT_PRODUCTION }.to_string();
        }
        if let Some(email) = &self.email {
            new.acme_contact_email = email.trim().to_string();
        }
        if let Some(addr) = &self.https_addr {
            new.https_addr = addr.trim().to_string();
        }
        new
    }
}

fn report(new: &Settings) {
    println!("SMTP hostname:  {}", new.hostname);
    if new.acme_enabled {
        let dir = if new.acme_directory == LETSENCRYPT_STAGING { "staging" } else { "production" };
        println!("Let's Encrypt:  on ({dir}), domains {}", new.acme_domains.join(", "));
        if !new.acme_contact_email.is_empty() {
            println!("CA contact:     {}", new.acme_contact_email);
        }
        println!(
            "                each domain must resolve to this host and reach the challenge \
             listener ({}) on port 80",
            new.acme_http_addr
        );
    }
    if !new.https_addr.is_empty() {
        println!("HTTPS web UI:   {}", new.https_addr);
    }
}

/// Set an existing account's web password, and optionally make it an admin.
/// The server keeps no per-user state outside the database, so this needs no
/// running instance - only the data directory.
pub fn set_password(args: &[String]) -> Result<()> {
    let request = SetPassword::parse(args)?;

    let boot = BootConfig::from_env();
    let db_path = boot.data_dir.join("smtpvoid.db");
    if !db_path.exists() {
        bail!(
            "no database at {} - start the server once, or point SMTPVOID_DATA_DIR at the              right directory",
            db_path.display()
        );
    }
    let db = Db::open(&db_path).context("opening database")?;

    // Look the account up before asking for a password: a typo in the username
    // should not cost the operator a round of typing.
    let user = db
        .get_user_by_username(&request.username)
        .context("reading the account")?
        .ok_or_else(|| anyhow!("no account named {}", request.username))?;

    let password = read_password()?;
    // The same bounds the web form enforces, so a password set here can also
    // be re-entered there.
    if !(8..=128).contains(&password.len()) {
        bail!("password must be 8-128 characters");
    }
    let hash = crate::web::hash_password(&password).context("hashing the password")?;

    if !db.set_password(user.id, &hash).context("saving the password")? {
        bail!("account {} disappeared while it was being updated", user.username);
    }
    println!("Password set for {}.", user.username);

    if request.admin && !user.is_admin {
        db.set_admin(user.id, true).context("granting admin rights")?;
        println!("{} is now an admin.", user.username);
    }
    println!("A running server keeps its existing sessions until it restarts.");
    Ok(())
}

/// A parsed `set-password` invocation. The password itself is not part of it:
/// it arrives on stdin, and only once the account is known to exist.
#[derive(Debug, Default, PartialEq, Eq)]
struct SetPassword {
    username: String,
    admin: bool,
}

impl SetPassword {
    fn parse(args: &[String]) -> Result<SetPassword> {
        let mut out = SetPassword::default();
        let mut named = false;

        for arg in args {
            match arg.as_str() {
                "--admin" => out.admin = true,
                other if other.starts_with('-') => bail!("unknown option {other}\n\n{USAGE}"),
                other if named => bail!("set-password takes one username, also got {other}"),
                other => {
                    out.username = other.trim().to_string();
                    named = true;
                }
            }
        }

        if !named || out.username.is_empty() {
            bail!("set-password needs a username\n\n{USAGE}");
        }
        Ok(out)
    }
}

/// Read one line from stdin. Passwords never come in as arguments, where the
/// shell history and `ps` would both see them. A terminal echoes what is typed
/// - hiding it would mean another dependency - so warn before waiting.
fn read_password() -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        print!("New password (visible as you type): ");
        std::io::stdout().flush().ok();
    }
    let mut line = String::new();
    stdin.lock().read_line(&mut line).context("reading the password from stdin")?;
    // Only the line ending goes: a password may legitimately end in a space.
    let password = line.trim_end_matches(['\n', '\r']).to_string();
    if password.is_empty() {
        bail!("no password on stdin");
    }
    Ok(password)
}

/// The placeholder certificate names the hostname, so it goes stale when the
/// hostname changes. A real certificate - one ACME or an operator installed -
/// is never touched.
fn reissue_self_signed_if_needed(boot: &BootConfig, settings: &Settings) -> Result<()> {
    let names = settings.cert_names();
    let certs = CertStore::new(&boot.data_dir).context("preparing the TLS directory")?;
    certs.load_or_generate(&names).context("preparing TLS")?;

    let stale = certs
        .info()
        .is_some_and(|i| i.source == CertSource::SelfSigned && !i.covers(&names));
    if stale {
        certs.generate_self_signed(&names).context("reissuing the self-signed certificate")?;
        println!("Reissued the self-signed certificate for {}.", names.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn parse(list: &[&str]) -> Result<SetDomain> {
        SetDomain::parse(&args(list))
    }

    #[test]
    fn domains_are_normalised_and_may_repeat() {
        let r = parse(&["Mail.Example.Test.", "smtp.example.test"]).unwrap();
        assert_eq!(r.domains, vec!["mail.example.test", "smtp.example.test"]);
    }

    #[test]
    fn a_domain_is_required() {
        assert!(SetDomain::parse(&[]).is_err());
        assert!(parse(&["--letsencrypt", "--agree-tos"]).is_err());
    }

    #[test]
    fn letsencrypt_needs_the_terms_accepted() {
        assert!(parse(&["a.test", "--letsencrypt"]).is_err());
        assert!(parse(&["a.test", "--letsencrypt", "--agree-tos"]).is_ok());
    }

    #[test]
    fn options_need_their_values() {
        assert!(parse(&["a.test", "--email"]).is_err());
        assert!(parse(&["a.test", "--https-addr"]).is_err());
        assert!(parse(&["a.test", "--nope"]).is_err());
    }

    #[test]
    fn the_first_domain_becomes_the_hostname() {
        let s = parse(&["a.test", "b.test"]).unwrap().apply(&Settings::default());
        assert_eq!(s.hostname, "a.test");
        // ACME is untouched while it is off and unconfigured.
        assert!(!s.acme_enabled);
        assert!(s.acme_domains.is_empty());
        assert_eq!(s.retention_secs, Settings::default().retention_secs);
    }

    #[test]
    fn letsencrypt_configures_every_domain_field_at_once() {
        let s = parse(&[
            "a.test",
            "b.test",
            "--letsencrypt",
            "--agree-tos",
            "--staging",
            "--email",
            " ops@example.test ",
        ])
        .unwrap()
        .apply(&Settings::default());

        assert_eq!(s.hostname, "a.test");
        assert_eq!(s.acme_domains, vec!["a.test", "b.test"]);
        assert!(s.acme_enabled && s.acme_tos_agreed);
        assert_eq!(s.acme_directory, LETSENCRYPT_STAGING);
        assert_eq!(s.acme_contact_email, "ops@example.test");
        assert!(s.validate().is_ok());
    }

    #[test]
    fn an_existing_acme_setup_follows_the_new_domain() {
        let old = Settings {
            acme_enabled: true,
            acme_tos_agreed: true,
            acme_domains: vec!["old.test".into()],
            ..Default::default()
        };
        let s = parse(&["new.test"]).unwrap().apply(&old);
        assert_eq!(s.acme_domains, vec!["new.test"]);
        assert_eq!(s.acme_directory, old.acme_directory);
    }

    #[test]
    fn https_can_be_turned_on_and_off() {
        let on = parse(&["a.test", "--https-addr", "0.0.0.0:443"])
            .unwrap()
            .apply(&Settings::default());
        assert_eq!(on.https_addr, "0.0.0.0:443");
        let off = parse(&["a.test", "--https-addr", ""]).unwrap().apply(&on);
        assert_eq!(off.https_addr, "");
    }

    fn parse_pw(list: &[&str]) -> Result<SetPassword> {
        SetPassword::parse(&args(list))
    }

    #[test]
    fn set_password_takes_a_username_and_an_admin_flag() {
        let r = parse_pw(&["--admin", "operator"]).unwrap();
        assert_eq!(r, SetPassword { username: "operator".into(), admin: true });
        let r = parse_pw(&["operator"]).unwrap();
        assert_eq!(r, SetPassword { username: "operator".into(), admin: false });
    }

    #[test]
    fn set_password_rejects_no_username_and_two_usernames() {
        assert!(parse_pw(&[]).is_err());
        assert!(parse_pw(&["--admin"]).is_err());
        assert!(parse_pw(&["one", "two"]).is_err());
        assert!(parse_pw(&["--nope", "one"]).is_err());
    }
}
