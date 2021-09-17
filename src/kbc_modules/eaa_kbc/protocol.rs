// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest {
    pub command: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    pub status: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptionRequest {
    pub command: String,
    pub blobs: Vec<Blob>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Blob {
    pub kid: String,
    pub encrypted_data: String,
    pub algorithm: String,
    pub key_length: u32,
    pub iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptionResponse {
    pub status: String,
    pub data: Option<HashMap<String, String>>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetKekRequest {
    pub command: String,
    pub kids: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetKekResponse {
    pub status: String,
    pub data: Option<HashMap<String, String>>,
    pub error: Option<String>,
}
