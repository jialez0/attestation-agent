// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};
use anyhow::*;
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use string_error::into_err;

pub mod protocol;
pub mod rats_tls;
use protocol::*;

#[derive(Serialize, Deserialize, Debug)]
struct AnnotationPacket {
    pub kid: String,
    pub wrapped_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub wrap_type: String,
}

pub struct EAAKbc {
    pub kbs_uri: String,
    pub protocol_version: String,
    pub encrypted_payload: Vec<u8>,
    pub key_id: String,
    pub iv: Vec<u8>,
    pub encrypt_type: String,
    pub kek_cache: HashMap<String, Vec<u8>>,
    pub tcp_stream: Option<TcpStream>,
    pub tls_handle: Option<rats_tls::RatsTls>,
}

impl KbcInterface for EAAKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("UNIMPLEMENT!"))
    }

    fn decrypt_payload(&mut self, messages: &str) -> Result<Vec<u8>> {
        debug!("EAA KBC decrypt_payload() is called!");
        let annotation_packet: AnnotationPacket = serde_json::from_str(messages)?;
        self.encrypted_payload = annotation_packet.wrapped_data;
        self.key_id = annotation_packet.kid;
        self.iv = annotation_packet.iv;
        self.encrypt_type = annotation_packet.wrap_type;
        if self.tcp_stream.is_none() {
            debug!("First request, connecting KBS...");
            self.establish_new_kbs_connection()?;
            debug!("attest success! TLS is established!");
        }

        debug!("start decrypt...");
        let decrypted_payload = self.kbs_decrypt_payload()?;
        debug!("decrypted success!");
        Ok(decrypted_payload)
    }
}

impl EAAKbc {
    pub fn new(kbs_uri: String) -> EAAKbc {
        EAAKbc {
            kbs_uri: kbs_uri,
            protocol_version: String::new(),
            encrypted_payload: vec![],
            key_id: String::new(),
            iv: vec![],
            encrypt_type: String::new(),
            kek_cache: HashMap::new(),
            tcp_stream: None,
            tls_handle: None,
        }
    }

    fn establish_new_kbs_connection(&mut self) -> Result<()> {
        self.tls_handle = match rats_tls::RatsTls::new(
            false,
            0,
            &Some("openssl".to_string()),
            &Some("openssl".to_string()),
            &Some("nullattester".to_string()),
            &Some("nullverifier".to_string()),
            true,
        ) {
            Ok(tls) => Some(tls),
            Err(_) => return Err(anyhow!("Something wrong when recreate rats_tls handle")),
        };
        self.tcp_stream = Some(TcpStream::connect(&self.kbs_uri)?);
        debug!("start negotiate (attestation) ...");
        match self
            .tls_handle
            .as_ref()
            .unwrap()
            .negotiate(self.tcp_stream.as_ref().unwrap().as_raw_fd())
        {
            Ok(()) => {
                self.protocol_version = self.kbs_query_version()?;
                return Ok(());
            }
            Err(_) => return Err(anyhow!("Something wrong when negotiate rats_tls")),
        };
    }

    fn kbs_query_version(&mut self) -> Result<String> {
        let request = VersionRequest {
            command: String::from("version"),
        };
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();
        let reciv_string: String = self.kbs_trans_and_reciv(trans_data, "Version")?;
        let response: VersionResponse =
            serde_json::from_str::<VersionResponse>(reciv_string.as_str())?;
        match response.status.as_str() {
            "OK" => return Ok(response.version),
            "Fail" => return Err(anyhow!("The VersionResponse status is 'Fail'!")),
            _ => return Err(anyhow!("Can't understand the VersionResponse status!")),
        }
    }

    fn kbs_decrypt_payload(&mut self) -> Result<Vec<u8>> {
        let request = DecryptionRequest {
            command: String::from("Decrypt"),
            blobs: vec![Blob {
                kid: self.key_id.clone(),
                encrypted_data: base64::encode(&self.encrypted_payload),
                algorithm: "AES".to_string(),
                key_length: 256,
                iv: base64::encode(&self.iv),
            }],
        };
        let trans_json = serde_json::to_string(&request)?;
        println!("decryption transmit data: {:?}", trans_json);
        let trans_data: &[u8] = trans_json.as_bytes();
        let reciv_string: String = self.kbs_trans_and_reciv(trans_data, "Dcryption")?;
        let response: DecryptionResponse =
            serde_json::from_str::<DecryptionResponse>(reciv_string.as_str())?;
        let payload_hashmap = match response.status.as_str() {
            "OK" => response.data,
            "Fail" => return Err(anyhow!(format!("Verdictd: {}", response.error.unwrap()))),
            _ => return Err(anyhow!("Can't understand the DcryptionResponse status!")),
        };
        if let Some(hashmap_content) = payload_hashmap {
            let encrypted_payload_string = base64::encode(&self.encrypted_payload);
            let decrypted_payload_string = match hashmap_content.get(&encrypted_payload_string) {
                Some(d) => d,
                None => return Err(anyhow!(
                    "There is no field matching the encrypted payload in the data field of DcryptionResponse"
                )),
            };
            let decrypted_payload = base64::decode(decrypted_payload_string)?;
            return Ok(decrypted_payload);
        } else {
            return Err(anyhow!(
                "DecryptionResponse status is OK but the data is null!"
            ));
        }
    }

    fn kbs_get_kek(&mut self) -> Result<()> {
        let request = GetKekRequest {
            command: String::from("Get KEK"),
            kids: vec![self.key_id.clone()],
        };
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();
        let reciv_string: String = self.kbs_trans_and_reciv(trans_data, "Get KEK")?;
        let response: GetKekResponse =
            serde_json::from_str::<GetKekResponse>(reciv_string.as_str())?;
        let kek_hashmap = match response.status.as_str() {
            "OK" => response.data,
            "Fail" => return Err(anyhow!(format!("Verdictd: {}", response.error.unwrap()))),
            _ => return Err(anyhow!("Can't understand the GetKekResponse status!")),
        };
        if let Some(hashmap_content) = kek_hashmap {
            for (kid, kek_string) in &hashmap_content {
                let kek = base64::decode(kek_string)?;
                self.kek_cache.insert(kid.to_string(), kek);
            }
        } else {
            return Err(anyhow!("GetKekResponse status is OK but the key is null!"));
        }
        Ok(())
    }

    fn kbs_trans_and_reciv(&mut self, trans_data: &[u8], error_info: &str) -> Result<String> {
        debug!("Transmit: {}", String::from_utf8(trans_data.to_vec())?);
        let _len_trans = match self.tls_handle.as_ref().unwrap().transmit(trans_data) {
            Ok(len) => len,
            Err(e) => {
                return Err(anyhow!(format!(
                    "Something wrong when transmit {}, error code: {}",
                    error_info, e
                )))
            }
        };
        let mut buffer = [0u8; 4096];
        let len_reciv = match self.tls_handle.as_ref().unwrap().receive(&mut buffer) {
            Ok(len) => len,
            Err(e) => {
                return Err(anyhow!(format!(
                    "Something wrong when recieve {}, error code: {}",
                    error_info, e
                )))
            }
        };
        let reciv_string: String = String::from_utf8(buffer[..len_reciv].to_vec())?;
        debug!("Recieve: {}", reciv_string);
        Ok(reciv_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_payload() {
        let plain_payload: Vec<u8> = [
            101, 121, 74, 122, 107, 87, 69, 112, 122, 83, 87, 112, 118, 97, 87, 70, 73, 85, 106,
            66, 106, 83, 69, 48, 50, 84, 72, 107, 53, 99, 108, 112, 89, 97, 51, 82, 106, 83, 69,
            112, 50, 90, 71, 49, 115, 97, 49, 112, 89, 83, 88, 90, 104, 77, 108, 89, 49, 84, 70,
            104, 87, 77, 61, 61,
        ]
        .to_vec();

        let encrypted_payload: Vec<u8> = [
            244, 176, 166, 37, 9, 240, 84, 85, 236, 190, 165, 125, 208, 226, 30, 189, 79, 212, 58,
            48, 4, 184, 245, 145, 180, 221, 25, 55, 165, 131, 104, 74, 100, 79, 210, 231, 183, 60,
            129, 69, 16, 55, 85, 227, 127, 118, 178, 88, 222, 135, 176, 14, 124, 89, 24, 226, 129,
            127, 47, 193, 42, 219, 237, 127, 12, 77, 107, 86, 214, 164, 111, 47, 107, 101, 91, 173,
            208, 99, 230, 154,
        ]
        .to_vec();

        let kek: Vec<u8> = [
            217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155,
            55, 27, 245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
        ]
        .to_vec();

        let iv: Vec<u8> = [
            116, 235, 143, 99, 70, 83, 228, 96, 9, 250, 168, 201, 234, 13, 84, 211,
        ]
        .to_vec();

        let annotation = AnnotationPacket {
            kid: "676913bf-9af2-4bbd-bee9-25359e2ca2e6".to_string(),
            wrapped_data: encrypted_payload,
            iv: iv,
            wrap_type: "aesm256-cbc".to_string(),
        };

        let mut eaa_kbc = EAAKbc::new("127.0.0.1:1122".to_string());

        assert_eq!(
            eaa_kbc
                .decrypt_payload(&serde_json::to_string(&annotation).unwrap())
                .unwrap(),
            plain_payload
        );
    }
}
