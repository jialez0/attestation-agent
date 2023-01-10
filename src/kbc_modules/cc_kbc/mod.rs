// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface, ResourceDescription};

mod attester;
mod crypto;
mod kbs_protocol;

use anyhow::*;
use async_trait::async_trait;
use attester::{detect_tee_type, Attester};
use core::time::Duration;
use crypto::{hash_chunks, TeeKey};
use kbs_protocol::message::*;
use reqwest::{cookie, Url};
use std::sync::Arc;

const KBS_REQ_TIMEOUT_SEC: u64 = 60;

pub struct Kbc {
    tee: String,
    kbs_uri: String,
    token: Option<String>,
    nonce: String,
    tee_key: Option<TeeKey>,
    attester: Option<Box<dyn Attester + Send + Sync>>,
    http_client: reqwest::Client,
    cookie_store: Arc<dyn cookie::CookieStore>,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, _annotation: &str) -> Result<Vec<u8>> {
        Err(anyhow!("Decrypt Payload API of this KBC is unimplemented."))
    }

    #[allow(unused_assignments)]
    async fn get_resource(&mut self, description: &str) -> Result<Vec<u8>> {
        let desc: ResourceDescription = serde_json::from_str::<ResourceDescription>(description)?;
        let mut resource_url = String::default();
        let resource_type = desc
            .optional
            .get("type")
            .ok_or_else(|| anyhow!("Invalid Resource description: Missing `type` field"))?;
        let resource_tag = desc
            .optional
            .get("tag")
            .ok_or_else(|| anyhow!("Invalid Resource description: Missing `tag` field"))?;
        if let Some(resource_repo) = desc.optional.get("repository") {
            resource_url = format!(
                "{}/{resource_repo}/{resource_type}/{resource_tag}",
                self.kbs_uri
            );
        } else {
            resource_url = format!("{}/{resource_type}/{resource_tag}", self.kbs_uri);
        }

        let response = self.request_kbs_resource(resource_url).await?;

        self.decrypt_response_output(response)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Kbc {
        // Detect TEE type of the current platform.
        let tee_type = detect_tee_type();

        // Create attester instance.
        let attester = tee_type.to_attester().ok();

        Kbc {
            tee: tee_type.to_string(),
            kbs_uri,
            token: None,
            nonce: String::default(),
            tee_key: TeeKey::new().ok(),
            attester,
            http_client: build_http_client().unwrap(),
            cookie_store: Arc::new(cookie::Jar::default()),
        }
    }

    fn generate_evidence(&self) -> Result<Attestation> {
        let key = self
            .tee_key
            .as_ref()
            .ok_or_else(|| anyhow!("Generate TEE key failed"))?;
        let attester = self
            .attester
            .as_ref()
            .ok_or_else(|| anyhow!("TEE attester missed"))?;

        let tee_pubkey = key
            .export_pubkey()
            .map_err(|e| anyhow!("Export TEE pubkey failed: {:?}", e))?;
        let tee_pubkey_string = serde_json::to_string(&tee_pubkey)?;

        let ehd_chunks = vec![
            self.nonce.clone().into_bytes(),
            tee_pubkey_string.clone().into_bytes(),
        ];

        let ehd = hash_chunks(ehd_chunks);

        let tee_evidence = attester
            .get_evidence(ehd)
            .map_err(|e| anyhow!("Get TEE evidence failed: {:?}", e))?;

        Ok(Attestation {
            tee_pubkey: tee_pubkey_string,
            tee_evidence,
        })
    }

    fn decrypt_response_output(&self, response: Response) -> Result<Vec<u8>> {
        let key = self
            .tee_key
            .clone()
            .ok_or_else(|| anyhow!("TEE rsa key missing"))?;
        response.decrypt_output(key)
    }

    fn tee(&self) -> &str {
        &self.tee
    }

    fn kbs_uri(&self) -> &str {
        &self.kbs_uri
    }

    fn http_client(&mut self) -> &mut reqwest::Client {
        &mut self.http_client
    }

    async fn establish_kbs_session(&mut self) -> Result<()> {
        let kbs_uri = self.kbs_uri().to_string();
        let parsed_kbs_uri =
            Url::parse(&kbs_uri).map_err(|e| anyhow!("Parse KBS URL Failed: {:?}", e))?;
        let auth_request = Request::new(self.tee().to_string());
        let auth_response = self
            .http_client()
            .post(format!("{}/auth", kbs_uri))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&auth_request)?)
            .send()
            .await?;

        let mut cookies = auth_response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .peekable();
        if cookies.peek().is_some() {
            self.cookie_store.set_cookies(&mut cookies, &parsed_kbs_uri);
        }

        let challenge = auth_response.json::<Challenge>().await?;
        self.nonce = challenge.nonce.clone();

        let attestation_evidence = self.generate_evidence()?;
        let attest_response = self
            .http_client()
            .post(format!("{}/attest", kbs_uri))
            .header("Content-Type", "application/json")
            .header(
                reqwest::header::COOKIE,
                self.cookie_store
                    .cookies(&parsed_kbs_uri)
                    .ok_or_else(|| anyhow!("Authenticated but cookie_store is still empty."))?,
            )
            .body(serde_json::to_string(&attestation_evidence)?)
            .send()
            .await?;
        if attest_response.status() != reqwest::StatusCode::OK {
            // TODO: Parse Error description payload
            bail!("KBS attest failed")
        }

        Ok(())
    }

    async fn request_kbs_resource(&mut self, resource_url: String) -> Result<Response> {
        let parsed_kbs_uri =
            Url::parse(self.kbs_uri()).map_err(|e| anyhow!("Parse KBS URL Failed: {:?}", e))?;

        if self.cookie_store.cookies(&parsed_kbs_uri).is_none() {
            self.establish_kbs_session().await?;
        }

        let mut res = self
            .http_client()
            .get(&resource_url)
            .header(
                reqwest::header::COOKIE,
                self.cookie_store.cookies(&parsed_kbs_uri).ok_or_else(|| {
                    anyhow!("Established session but cookie_store is still empty.")
                })?,
            )
            .send()
            .await?;

        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.establish_kbs_session().await?;
        }
        res = self
            .http_client()
            .get(&resource_url)
            .header(
                reqwest::header::COOKIE,
                self.cookie_store.cookies(&parsed_kbs_uri).ok_or_else(|| {
                    anyhow!("Established session again but cookie_store is still empty.")
                })?,
            )
            .send()
            .await?;

        if res.status() == reqwest::StatusCode::OK {
            let response = res.json::<Response>().await?;
            Ok(response)
        } else {
            // TODO: Parse Error description payload
            bail!("Request KBS resource failed")
        }
    }
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .cookie_store(true)
        .user_agent(format!("attestation-agent-cc-kbc/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC))
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}
