// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! ResourceUri is the identification information of all resources that need to be
//! obtained from `get_resource` endpoint. Also, `kid` field in an
//! [`super::AnnotationPacket`] of `decrypt_payload` should also follow this.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const RESOURCE_ID_ERROR_INFO: &str =
    "invalid kbs resource uri, should be kbs://<addr-of-kbs>/<repo>/<type>/<tag>";

const SCHEME: &str = "kbs";

/// Resource Id document <https://github.com/confidential-containers/attestation-agent/blob/main/docs/KBS_URI.md>
#[derive(Clone, Debug, PartialEq)]
pub struct ResourceUri {
    pub kbs_addr: String,
    pub repository: String,
    pub r#type: String,
    pub tag: String,
}

impl TryFrom<&str> for ResourceUri {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = url::Url::try_from(value).map_err(|_| RESOURCE_ID_ERROR_INFO)?;
        Self::try_from(url)
    }
}

impl TryFrom<url::Url> for ResourceUri {
    type Error = &'static str;

    fn try_from(value: url::Url) -> Result<Self, Self::Error> {
        let addr = value
            .host_str()
            .ok_or("can not parse kbs address from the url")?;
        if value.scheme() != SCHEME {
            return Err("scheme must be kbs");
        }

        if value.path().is_empty() {
            return Err(RESOURCE_ID_ERROR_INFO);
        }

        let path = &value.path()[1..];
        let values: Vec<&str> = path.split('/').collect();
        if values.len() == 3 {
            Ok(Self {
                kbs_addr: addr.into(),
                repository: values[0].into(),
                r#type: values[1].into(),
                tag: values[2].into(),
            })
        } else {
            Err(RESOURCE_ID_ERROR_INFO)
        }
    }
}

impl From<ResourceUri> for url::Url {
    fn from(val: ResourceUri) -> Self {
        url::Url::try_from(&val.whole_uri()[..]).expect("unexpected parse")
    }
}

impl ResourceUri {
    pub fn whole_uri(&self) -> String {
        format!(
            "{SCHEME}://{}/{}/{}/{}",
            self.kbs_addr, self.repository, self.r#type, self.tag
        )
    }

    /// Only return the resource path. This function is used
    /// currently because up to now the kbs-uri is given
    /// to create an AA instance.
    pub fn resource_path(&self) -> String {
        format!("{}/{}/{}", self.repository, self.r#type, self.tag)
    }
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let url = self.whole_uri();
        ser.serialize_str(&url)
    }
}

impl<'de> Deserialize<'de> for ResourceUri {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: &str = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceUri;

    const TEST_URL: &str = "kbs://example.org/alice/cosign-key/213";

    #[test]
    fn deserialize() {
        let resource: ResourceUri =
            serde_json::from_str(&format!("\"{TEST_URL}\"")).expect("deserialize failed");
        let expected = ResourceUri {
            kbs_addr: "example.org".into(),
            repository: "alice".into(),
            r#type: "cosign-key".into(),
            tag: "213".into(),
        };
        assert_eq!(expected, resource);
    }

    #[test]
    fn serialize() {
        let rid = ResourceUri {
            kbs_addr: "example.org".into(),
            repository: "alice".into(),
            r#type: "cosign-key".into(),
            tag: "213".into(),
        };

        let res = serde_json::to_string(&rid).expect("serialize failed");
        assert_eq!(res, format!("\"{TEST_URL}\""));
    }

    #[test]
    fn conversions() {
        let rid = ResourceUri {
            kbs_addr: "example.org".into(),
            repository: "alice".into(),
            r#type: "cosign-key".into(),
            tag: "213".into(),
        };

        let url = url::Url::try_from(TEST_URL).expect("failed to parse url");
        let try_into: url::Url = rid.clone().try_into().expect("failed to try into url");
        assert_eq!(url, try_into);

        let rid_try_from = ResourceUri::try_from(url).expect("failed to try from url");
        assert_eq!(rid, rid_try_from);
    }
}