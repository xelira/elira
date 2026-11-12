use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};

use crate::{AcmeConfig, ConfigError};

fn secure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

fn write_secret(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(data)
}

pub async fn obtain(config: &AcmeConfig) -> anyhow::Result<(String, String)> {
    let directory = if config.production {
        LetsEncrypt::Production.url()
    } else {
        LetsEncrypt::Staging.url()
    };
    let credentials_path = config.cache_dir.join("instant-acme-account.json");
    secure_dir(&config.cache_dir)?;
    let account = if let Ok(bytes) = std::fs::read(&credentials_path) {
        let credentials: AccountCredentials = serde_json::from_slice(&bytes)?;
        Account::builder()?.from_credentials(credentials).await?
    } else {
        let contacts: Vec<&str> = config.contacts.iter().map(String::as_str).collect();
        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.to_owned(),
                None,
            )
            .await?;
        write_secret(&credentials_path, &serde_json::to_vec_pretty(&credentials)?)?;
        account
    };

    let identifiers: Vec<Identifier> = config
        .domains
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await?;

    let mut records: Vec<(String, String, String, String)> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result?;
        if matches!(
            authorization.status,
            instant_acme::AuthorizationStatus::Valid
        ) {
            continue;
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge offered"))?;
        let identifier = challenge.identifier().to_string();
        let base = identifier.trim_start_matches("*.");
        let txt_name = format!("_acme-challenge.{base}");
        let value = challenge.key_authorization().dns_value();
        run_hook(
            config,
            config.dns_hook.as_deref(),
            &identifier,
            &txt_name,
            &challenge.token,
            &value,
            None,
        )?;
        records.push((identifier, txt_name, challenge.token.clone(), value));
        if config.dns_propagation_secs > 0 {
            tokio::time::sleep(Duration::from_secs(config.dns_propagation_secs)).await;
        }
        challenge.set_ready().await?;
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        anyhow::bail!("ACME order is {status:?}, expected Ready");
    }
    let key_pem = order.finalize().await?;
    let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    if let Some(cleanup) = &config.dns_cleanup_hook {
        for (domain, txt_name, token, value) in &records {
            let _ = run_hook(
                config,
                Some(cleanup),
                domain,
                txt_name,
                token,
                value,
                Some("cleanup"),
            );
        }
    }

    Ok((cert_pem, key_pem))
}

fn check_hook(hook: &Path) -> Result<(), ConfigError> {
    let meta = std::fs::symlink_metadata(hook).map_err(|source| ConfigError::DnsHook {
        path: hook.to_path_buf(),
        source,
    })?;
    if !hook.is_absolute()
        || meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.permissions().mode() & 0o022 != 0
    {
        return Err(ConfigError::DnsHook {
            path: hook.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "dns_hook must be an absolute, non-symlink file not writable by group or others",
            ),
        });
    }
    Ok(())
}

fn run_hook(
    config: &AcmeConfig,
    hook: Option<&Path>,
    domain: &str,
    txt_name: &str,
    token: &str,
    value: &str,
    action: Option<&str>,
) -> Result<(), ConfigError> {
    let _ = config;
    let hook = hook.ok_or(ConfigError::DnsHookMissing)?;
    check_hook(hook)?;
    let mut command = Command::new(hook);
    command
        .env("DOMAIN", domain)
        .env("TXT_NAME", txt_name)
        .env("TOKEN", token)
        .env("VALUE", value);
    if let Some(action) = action {
        command.env("ACTION", action);
    }
    let status = command.status().map_err(|source| ConfigError::DnsHook {
        path: hook.to_path_buf(),
        source,
    })?;
    if !status.success() {
        return Err(ConfigError::DnsHookStatus {
            path: hook.to_path_buf(),
            status: status.code(),
        });
    }
    Ok(())
}

pub async fn build_config(
    config: &AcmeConfig,
) -> anyhow::Result<(std::sync::Arc<rustls::ServerConfig>, String, String)> {
    let (cert_pem, key_pem) = obtain(config).await?;
    let cert_path = config.cache_dir.join("dns-cert.pem");
    let key_path = config.cache_dir.join("dns-key.pem");
    secure_dir(&config.cache_dir)?;
    write_secret(&cert_path, cert_pem.as_bytes())?;
    write_secret(&key_path, key_pem.as_bytes())?;
    let server = elira_tls::server_config(Path::new(&cert_path), Path::new(&key_path))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok((std::sync::Arc::new(server), cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Challenge;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_hook_receives_the_record_data() {
        let dir = std::env::temp_dir().join(format!("elira-dns-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let output = dir.join("out");
        let hook = dir.join("hook");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\nprintf '%s|%s|%s|%s' \"$DOMAIN\" \"$TXT_NAME\" \"$TOKEN\" \"$VALUE\" > {}\n",
                output.display()
            ),
        )
        .expect("hook");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("mode");

        let config = AcmeConfig {
            domains: vec!["*.example.com".into()],
            contacts: vec!["mailto:admin@example.com".into()],
            cache_dir: dir.clone(),
            production: false,
            challenge: Challenge::Dns01,
            dns_hook: Some(hook.clone()),
            dns_cleanup_hook: None,
            dns_propagation_secs: 0,
        };
        run_hook(
            &config,
            config.dns_hook.as_deref(),
            "*.example.com",
            "_acme-challenge.example.com",
            "token",
            "value",
            None,
        )
        .expect("hook");
        assert_eq!(
            std::fs::read_to_string(&output).expect("output"),
            "*.example.com|_acme-challenge.example.com|token|value"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
