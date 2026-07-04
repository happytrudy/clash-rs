use std::{
    io,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use hickory_proto::rr::RData;
use hickory_resolver::TokioResolver;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest::Method;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::acme::{
    Account, AuthStatus, ChallengeType, Directory,
    LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY, OrderStatus,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::{sync::watch, time::sleep};
use tracing::{debug, info, warn};
use x509_parser::parse_x509_certificate;

use super::{CloudflareAuth, CloudflareDnsOptions, acme_store};

const DNS01_RETRY_BASE: Duration = Duration::from_secs(60);
const DNS01_RETRY_MAX: Duration = Duration::from_secs(3600);
const AUTH_CHECK_ATTEMPTS: u64 = 6;
const ORDER_PROCESSING_ATTEMPTS: u64 = 10;
const DNS01_PROPAGATION_CHECK_ATTEMPTS: u64 = 8;
const CLOUDFLARE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CLOUDFLARE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Dns01AcmeOptions {
    pub domain: String,
    pub email: Option<String>,
    pub cache_dir: PathBuf,
    pub production: bool,
    pub cloudflare: CloudflareDnsOptions,
}

#[derive(Debug)]
pub struct Dns01CertResolver {
    cert: RwLock<Option<Arc<CertifiedKey>>>,
    state: watch::Sender<Dns01CertState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dns01CertState {
    Pending,
    Ready,
    Failed(String),
}

impl Dns01CertResolver {
    pub fn new() -> Self {
        let (state, _rx) = watch::channel(Dns01CertState::Pending);
        Self {
            cert: RwLock::new(None),
            state,
        }
    }

    fn set_pem(&self, pem: &[u8]) -> anyhow::Result<()> {
        let cert = certified_key_from_pem(pem)?;
        *self
            .cert
            .write()
            .map_err(|_| anyhow!("dns-01 certificate resolver lock poisoned"))? =
            Some(Arc::new(cert));
        self.state.send_replace(Dns01CertState::Ready);
        Ok(())
    }

    fn set_error_if_empty(&self, error: String) {
        let has_cert = self.cert.read().map(|cert| cert.is_some()).unwrap_or(false);
        if !has_cert {
            self.state.send_replace(Dns01CertState::Failed(error));
        }
    }

    pub fn subscribe_state(&self) -> watch::Receiver<Dns01CertState> {
        self.state.subscribe()
    }
}

impl ResolvesServerCert for Dns01CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.cert.read().ok()?.clone()
    }
}

pub fn load_cached_certificate(
    opts: &Dns01AcmeOptions,
    resolver: Arc<Dns01CertResolver>,
) -> anyhow::Result<()> {
    let path = cert_cache_path(opts);
    let pem = match std::fs::read(&path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    acme_store::harden_private_file_sync(&path)?;
    resolver.set_pem(&pem)?;
    info!(
        "hysteria2 acme dns-01: deployed cached certificate for {}",
        opts.domain
    );
    Ok(())
}

pub async fn run_dns01_acme(
    opts: Dns01AcmeOptions,
    resolver: Arc<Dns01CertResolver>,
) {
    let mut retry = DNS01_RETRY_BASE;

    loop {
        match renewal_delay_from_cache(&opts) {
            Ok(Some(delay)) if !delay.is_zero() => {
                debug!(
                    "hysteria2 acme dns-01: next renewal for {} in {:?}",
                    opts.domain, delay
                );
                sleep(delay).await;
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                debug!(
                    "hysteria2 acme dns-01: cached certificate for {} is not usable: {e}",
                    opts.domain
                );
            }
        }

        match order_and_deploy_certificate(&opts, Arc::clone(&resolver)).await {
            Ok(()) => {
                retry = DNS01_RETRY_BASE;
            }
            Err(e) => {
                warn!(
                    "hysteria2 acme dns-01: certificate order for {} failed: {e:#}",
                    opts.domain
                );
                resolver.set_error_if_empty(format!("{e:#}"));
                sleep(retry).await;
                retry = (retry * 2).min(DNS01_RETRY_MAX);
            }
        }
    }
}

async fn order_and_deploy_certificate(
    opts: &Dns01AcmeOptions,
    resolver: Arc<Dns01CertResolver>,
) -> anyhow::Result<()> {
    acme_store::ensure_private_dir(&opts.cache_dir)
        .await
        .with_context(|| {
            format!(
                "failed to create acme cache dir {}",
                opts.cache_dir.display()
            )
        })?;

    let pem = order_certificate(opts).await?;
    acme_store::write_private_file(&cert_cache_path(opts), &pem)
        .await
        .context("failed to store dns-01 certificate cache")?;
    resolver.set_pem(&pem)?;
    info!(
        "hysteria2 acme dns-01: deployed new certificate for {}",
        opts.domain
    );
    Ok(())
}

async fn order_certificate(opts: &Dns01AcmeOptions) -> anyhow::Result<Vec<u8>> {
    let client_config = acme_client_config();
    let directory =
        Directory::discover(&client_config, acme_directory(opts.production))
            .await
            .context("discover acme directory")?;
    let account_key = load_or_create_account_key(opts).await?;
    let contact = acme_contact(opts.email.as_deref());
    let account = Account::create_with_keypair(
        &client_config,
        directory,
        &contact,
        &account_key,
    )
    .await
    .context("create acme account")?;

    let mut params = CertificateParams::new(vec![opts.domain.clone()])?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let csr = params.serialize_request(&key_pair)?;

    let (order_url, mut order) = account
        .new_order(&client_config, vec![opts.domain.clone()])
        .await
        .context("create acme order")?;

    loop {
        match order.status {
            OrderStatus::Pending => {
                for auth_url in &order.authorizations {
                    authorize_dns01(opts, &account, &client_config, auth_url)
                        .await?;
                }
                order = account.order(&client_config, &order_url).await?;
            }
            OrderStatus::Ready => {
                order = account
                    .finalize(&client_config, order.finalize, csr.der())
                    .await
                    .context("finalize acme order")?;
            }
            OrderStatus::Processing => {
                for i in 0..ORDER_PROCESSING_ATTEMPTS {
                    sleep(Duration::from_secs(1u64 << i)).await;
                    order = account.order(&client_config, &order_url).await?;
                    if !matches!(order.status, OrderStatus::Processing) {
                        break;
                    }
                }
                if matches!(order.status, OrderStatus::Processing) {
                    bail!("acme order stayed processing too long");
                }
            }
            OrderStatus::Valid { certificate } => {
                let cert = account
                    .certificate(&client_config, certificate)
                    .await
                    .context("download acme certificate")?;
                return Ok([key_pair.serialize_pem(), "\n".to_owned(), cert]
                    .concat()
                    .into_bytes());
            }
            OrderStatus::Invalid => {
                bail!("acme order became invalid: {:?}", order.error);
            }
        }
    }
}

async fn authorize_dns01(
    opts: &Dns01AcmeOptions,
    account: &Account,
    client_config: &Arc<rustls_acme::rustls::ClientConfig>,
    auth_url: &str,
) -> anyhow::Result<()> {
    let auth = account.auth(client_config, auth_url).await?;
    match auth.status {
        AuthStatus::Valid => return Ok(()),
        AuthStatus::Pending => {}
        _ => bail!(
            "acme authorization is not pending or valid: {:?}",
            auth.status
        ),
    }

    let challenge = auth
        .challenges
        .iter()
        .find(|challenge| challenge.typ == ChallengeType::Dns01)
        .ok_or_else(|| anyhow!("no dns-01 challenge found"))?;
    let challenge_url = challenge.url.clone();
    let txt_value = dns01_txt_value(account, challenge.token.as_str())?;
    let record_name = dns01_record_name(&auth.identifier.into_inner());

    let cloudflare = CloudflareDnsClient::new(opts.cloudflare.clone());
    let record = cloudflare
        .create_txt_record(record_name.as_str(), txt_value.as_str(), &opts.domain)
        .await
        .context("create cloudflare dns-01 TXT record")?;

    let result = async {
        wait_for_dns01_propagation(
            record_name.as_str(),
            txt_value.as_str(),
            opts.cloudflare.propagation_delay,
        )
        .await?;
        account
            .challenge(client_config, &challenge_url)
            .await
            .context("trigger acme dns-01 challenge")?;

        for i in 0..AUTH_CHECK_ATTEMPTS {
            sleep(Duration::from_secs(1u64 << i)).await;
            let auth = account.auth(client_config, auth_url).await?;
            match auth.status {
                AuthStatus::Valid => return Ok(()),
                AuthStatus::Pending => {
                    debug!(
                        "hysteria2 acme dns-01: authorization for {} still pending",
                        opts.domain
                    );
                }
                _ => bail!("acme dns-01 authorization failed: {:?}", auth.status),
            }
        }

        bail!("acme dns-01 authorization timed out")
    }
    .await;

    if let Err(e) = cloudflare.delete_txt_record(&record).await {
        warn!(
            "hysteria2 acme dns-01: failed to delete Cloudflare TXT record {}: {e:#}",
            record.id
        );
    }

    result
}

async fn wait_for_dns01_propagation(
    record_name: &str,
    txt_value: &str,
    initial_delay: Duration,
) -> anyhow::Result<()> {
    sleep(initial_delay).await;

    let resolver = TokioResolver::builder_tokio()
        .context("create DNS resolver for dns-01 propagation check")?
        .build()
        .context("build DNS resolver for dns-01 propagation check")?;

    for i in 0..DNS01_PROPAGATION_CHECK_ATTEMPTS {
        match resolver.txt_lookup(record_name).await {
            Ok(lookup) if txt_lookup_contains(&lookup, txt_value) => {
                return Ok(());
            }
            Ok(_) => {
                debug!(
                    "hysteria2 acme dns-01: TXT record {record_name} \
                     is not propagated yet"
                );
            }
            Err(e) => {
                debug!(
                    "hysteria2 acme dns-01: TXT lookup for {record_name} \
                     failed while checking propagation: {e}"
                );
            }
        }

        sleep(Duration::from_secs(1u64 << i.min(5))).await;
    }

    bail!("dns-01 TXT record {record_name} did not propagate")
}

fn txt_lookup_contains(
    lookup: &hickory_resolver::lookup::Lookup,
    expected: &str,
) -> bool {
    let expected = expected.as_bytes();
    lookup.answers().iter().any(|record| {
        let RData::TXT(txt) = &record.data else {
            return false;
        };
        txt.txt_data.iter().any(|chunk| chunk.as_ref() == expected)
            || txt.txt_data.concat().as_slice() == expected
    })
}

fn dns01_txt_value(account: &Account, token: &str) -> anyhow::Result<String> {
    let key_auth = format!("{token}.{}", jwk_thumb_sha256_base64(account)?);
    Ok(BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(key_auth.as_bytes())))
}

fn jwk_thumb_sha256_base64(account: &Account) -> anyhow::Result<String> {
    let public_key = account_public_key(account);
    if public_key.len() != 65 || public_key[0] != 0x04 {
        bail!("unexpected ACME account public key format");
    }
    let (x, y) = public_key[1..].split_at(32);
    let jwk = JwkThumb {
        crv: "P-256",
        kty: "EC",
        x: BASE64_URL_SAFE_NO_PAD.encode(x),
        y: BASE64_URL_SAFE_NO_PAD.encode(y),
    };
    let json = serde_json::to_vec(&jwk)?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(json)))
}

#[cfg(feature = "aws-lc-rs")]
fn account_public_key(account: &Account) -> Vec<u8> {
    use aws_lc_rs::signature::KeyPair as _;
    account.key_pair.public_key().as_ref().to_vec()
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn account_public_key(account: &Account) -> Vec<u8> {
    use ring::signature::KeyPair as _;
    account.key_pair.public_key().as_ref().to_vec()
}

#[derive(Serialize)]
struct JwkThumb {
    crv: &'static str,
    kty: &'static str,
    x: String,
    y: String,
}

#[derive(Clone)]
struct CloudflareDnsClient {
    client: reqwest::Client,
    auth: CloudflareAuth,
    zone_id: Option<String>,
    ttl: u32,
}

impl CloudflareDnsClient {
    fn new(opts: CloudflareDnsOptions) -> Self {
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(CLOUDFLARE_CONNECT_TIMEOUT)
                .timeout(CLOUDFLARE_REQUEST_TIMEOUT)
                .build()
                .expect("valid Cloudflare DNS HTTP client"),
            auth: opts.auth,
            zone_id: opts.zone_id,
            ttl: opts.ttl.unwrap_or(1),
        }
    }

    async fn create_txt_record(
        &self,
        name: &str,
        content: &str,
        domain: &str,
    ) -> anyhow::Result<CreatedCloudflareDnsRecord> {
        let zone_id = self
            .zone_id(domain)
            .await
            .with_context(|| format!("discover Cloudflare zone for {domain}"))?;
        let record: CloudflareDnsRecord = self
            .cloudflare_request(
                Method::POST,
                format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                ),
                Some(&serde_json::json!({
                    "type": "TXT",
                    "name": name,
                    "content": content,
                    "ttl": self.ttl,
                })),
                None,
            )
            .await?;
        Ok(CreatedCloudflareDnsRecord {
            id: record.id,
            zone_id,
        })
    }

    async fn delete_txt_record(
        &self,
        record: &CreatedCloudflareDnsRecord,
    ) -> anyhow::Result<()> {
        let _: serde_json::Value = self
            .cloudflare_request(
                Method::DELETE,
                format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    record.zone_id, record.id
                ),
                None,
                None,
            )
            .await?;
        Ok(())
    }

    async fn zone_id(&self, domain: &str) -> anyhow::Result<String> {
        if let Some(zone_id) = self.zone_id.as_deref() {
            return Ok(zone_id.to_owned());
        }

        for zone_name in zone_candidates(domain) {
            let zones: Vec<CloudflareZone> = self
                .cloudflare_request(
                    Method::GET,
                    format!(
                        "https://api.cloudflare.com/client/v4/zones?name={}",
                        url_escape(zone_name.as_str())
                    ),
                    None,
                    None,
                )
                .await?;
            if let Some(zone) = zones.into_iter().next() {
                return Ok(zone.id);
            }
        }

        bail!("failed to discover Cloudflare zone for {domain}")
    }

    async fn cloudflare_request<T>(
        &self,
        method: Method,
        url: impl AsRef<str>,
        json: Option<&serde_json::Value>,
        _query: Option<&[(&str, &str)]>,
    ) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let mut req = self.apply_auth(self.client.request(method, url.as_ref()));
        if let Some(json) = json {
            req = req.json(json);
        }
        let response = req.send().await?;
        let status = response.status();
        let body = response.text().await?;
        let response: CloudflareResponse<T> = serde_json::from_str(&body)
            .with_context(|| format!("parse Cloudflare response: {body}"))?;
        if !status.is_success() || !response.success {
            bail!("Cloudflare API error: {}", response.error_message());
        }
        response
            .result
            .ok_or_else(|| anyhow!("Cloudflare API success response missing result"))
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            CloudflareAuth::ApiToken(token) => req.bearer_auth(token),
            CloudflareAuth::GlobalKey { email, key } => req
                .header("X-Auth-Email", email.as_str())
                .header("X-Auth-Key", key.as_str()),
        }
    }
}

#[derive(Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

impl<T> CloudflareResponse<T> {
    fn error_message(&self) -> String {
        if self.errors.is_empty() {
            return "unknown error".to_owned();
        }
        self.errors
            .iter()
            .map(format_cloudflare_error)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn format_cloudflare_error(err: &CloudflareError) -> String {
    let mut message = match err.code {
        Some(code) => format!("{code}: {}", err.message),
        None => err.message.clone(),
    };
    if !err.error_chain.is_empty() {
        let chain = err
            .error_chain
            .iter()
            .map(format_cloudflare_error)
            .collect::<Vec<_>>()
            .join("; ");
        message.push_str(" (");
        message.push_str(&chain);
        message.push(')');
    }
    message
}

#[derive(Deserialize)]
struct CloudflareError {
    code: Option<u64>,
    message: String,
    #[serde(default)]
    error_chain: Vec<CloudflareError>,
}

#[derive(Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Deserialize)]
struct CloudflareDnsRecord {
    id: String,
}

struct CreatedCloudflareDnsRecord {
    id: String,
    zone_id: String,
}

fn certified_key_from_pem(pem: &[u8]) -> anyhow::Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut io::Cursor::new(pem))
            .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        bail!("no certificate found in cached PEM");
    }

    let key = rustls_pemfile::private_key(&mut io::Cursor::new(pem))?
        .ok_or_else(|| anyhow!("no private key found in cached PEM"))?;
    let signing_key = any_supported_signing_key(&key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

#[cfg(feature = "aws-lc-rs")]
fn any_supported_signing_key(
    key: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    rustls::crypto::aws_lc_rs::sign::any_supported_type(key)
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn any_supported_signing_key(
    key: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    rustls::crypto::ring::sign::any_supported_type(key)
}

fn renewal_delay_from_cache(
    opts: &Dns01AcmeOptions,
) -> anyhow::Result<Option<Duration>> {
    let path = cert_cache_path(opts);
    if !path.exists() {
        return Ok(None);
    }
    let pem = std::fs::read(&path)?;
    acme_store::harden_private_file_sync(&path)?;
    certificate_renewal_delay(&pem).map(Some)
}

fn certificate_renewal_delay(pem: &[u8]) -> anyhow::Result<Duration> {
    let certs = rustls_pemfile::certs(&mut io::Cursor::new(pem))
        .collect::<Result<Vec<_>, _>>()?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow!("cached PEM has no certificate"))?;
    let (_, cert) = parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow!("parse cached certificate: {e}"))?;
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let lifetime = not_after.saturating_sub(not_before);
    let renew_at = not_after.saturating_sub(lifetime / 3);
    let now = chrono::Utc::now().timestamp();
    if now >= renew_at {
        return Ok(Duration::ZERO);
    }
    Ok(Duration::from_secs((renew_at - now) as u64))
}

async fn load_or_create_account_key(
    opts: &Dns01AcmeOptions,
) -> anyhow::Result<Vec<u8>> {
    let path = account_key_path(opts);
    if let Some(key) = acme_store::read_private_file_if_exists(&path).await? {
        return Ok(key);
    }

    let key = Account::generate_key_pair();
    acme_store::write_private_file(&path, &key)
        .await
        .with_context(|| format!("store acme account key {}", path.display()))?;
    Ok(key)
}

fn acme_client_config() -> Arc<rustls_acme::rustls::ClientConfig> {
    let root_store: RootCertStore =
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(
        rustls_acme::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

fn acme_directory(production: bool) -> &'static str {
    if production {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
    } else {
        LETS_ENCRYPT_STAGING_DIRECTORY
    }
}

fn acme_contact(email: Option<&str>) -> Vec<String> {
    email
        .filter(|email| !email.trim().is_empty())
        .map(|email| {
            if email.starts_with("mailto:") {
                email.to_owned()
            } else {
                format!("mailto:{email}")
            }
        })
        .into_iter()
        .collect()
}

fn cert_cache_path(opts: &Dns01AcmeOptions) -> PathBuf {
    opts.cache_dir.join(format!(
        "dns01-{}-{}.pem",
        safe_name(&opts.domain),
        directory_tag(opts.production)
    ))
}

fn account_key_path(opts: &Dns01AcmeOptions) -> PathBuf {
    opts.cache_dir.join(format!(
        "dns01-account-{}.key",
        directory_tag(opts.production)
    ))
}

fn directory_tag(production: bool) -> &'static str {
    if production { "production" } else { "staging" }
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn dns01_record_name(domain: &str) -> String {
    format!("_acme-challenge.{}", dns_base_domain(domain))
}

fn dns_base_domain(domain: &str) -> String {
    domain
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_owned()
}

fn zone_candidates(domain: &str) -> Vec<String> {
    let base = dns_base_domain(domain);
    let labels: Vec<&str> = base.split('.').collect();
    if labels.len() < 2 {
        return vec![base];
    }
    (0..labels.len() - 1)
        .map(|idx| labels[idx..].join("."))
        .collect()
}

fn url_escape(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{Name, RData, RecordType, rdata::TXT},
    };

    #[test]
    fn dns01_record_name_strips_wildcard() {
        assert_eq!(
            dns01_record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn zone_candidates_prefers_longest_suffix() {
        assert_eq!(
            zone_candidates("hy2.example.com"),
            vec!["hy2.example.com", "example.com"]
        );
    }

    #[test]
    fn txt_lookup_contains_split_value() {
        let query = Query::query(
            Name::from_ascii("_acme-challenge.example.com.").unwrap(),
            RecordType::TXT,
        );
        let lookup = hickory_resolver::lookup::Lookup::from_rdata(
            query,
            RData::TXT(TXT::from_bytes(vec![b"abc", b"def"])),
        );

        assert!(txt_lookup_contains(&lookup, "abcdef"));
        assert!(!txt_lookup_contains(&lookup, "abcxyz"));
    }

    #[test]
    fn cloudflare_error_response_accepts_null_result() {
        let response: CloudflareResponse<Vec<CloudflareZone>> =
            serde_json::from_str(
                r#"{"success":false,"errors":[{"code":6003,"message":"Invalid request headers","error_chain":[{"code":6103,"message":"Invalid format for X-Auth-Key header"}]}],"messages":[],"result":null}"#,
            )
            .unwrap();

        assert!(!response.success);
        assert!(response.result.is_none());
        assert_eq!(
            response.error_message(),
            "6003: Invalid request headers (6103: Invalid format for X-Auth-Key header)"
        );
    }

    #[test]
    fn cloudflare_api_token_auth_uses_bearer_header() {
        let client = CloudflareDnsClient::new(CloudflareDnsOptions {
            auth: CloudflareAuth::ApiToken("cf-token".to_owned()),
            zone_id: None,
            ttl: None,
            propagation_delay: Duration::ZERO,
        });
        let request = client
            .apply_auth(
                client
                    .client
                    .get("https://api.cloudflare.com/client/v4/zones"),
            )
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer cf-token")
        );
    }

    #[test]
    fn cloudflare_global_key_auth_uses_email_and_key_headers() {
        let client = CloudflareDnsClient::new(CloudflareDnsOptions {
            auth: CloudflareAuth::GlobalKey {
                email: "account@example.com".to_owned(),
                key: "cf-global-key".to_owned(),
            },
            zone_id: None,
            ttl: None,
            propagation_delay: Duration::ZERO,
        });
        let request = client
            .apply_auth(
                client
                    .client
                    .get("https://api.cloudflare.com/client/v4/zones"),
            )
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get("x-auth-email")
                .and_then(|value| value.to_str().ok()),
            Some("account@example.com")
        );
        assert_eq!(
            request
                .headers()
                .get("x-auth-key")
                .and_then(|value| value.to_str().ok()),
            Some("cf-global-key")
        );
        assert!(!request.headers().contains_key("authorization"));
    }
}
