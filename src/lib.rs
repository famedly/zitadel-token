//! Rust representation of a Zitadel token

use std::collections::HashMap;

use josekit::{jwk::Jwk, jws::JwsHeader, jwt::JwtPayload, Value};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Struct that represents a JWT from Zitadel
#[derive(Debug, Clone, PartialEq)]
pub struct ZitadelJWT {
	/// Token Issuer
	pub iss: String,
	/// Token expiration date
	pub exp: OffsetDateTime,
	/// Token issued at date
	pub iat: OffsetDateTime,
	/// Token subject
	pub sub: String,
	/// Homeserver of the project as a single URL
	pub homeserver: Option<String>,
	/// Map of project IDs to their homeserver URLs
	pub homeservers_list: Option<HashMap<String, String>>,
	/// Matrix localpart, optional because service accounts don't have it
	pub localpart: Option<String>,
	/// Profession oid
	pub profession_oid: String,
	/// TelematikId
	pub telematik_id: String,
	/// Map of roles to array of projects ids
	pub roles: HashMap<ZitadelUserRole, Vec<String>>,
}

/// User roles available on Zitadel
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
pub enum ZitadelUserRole {
	TimProviderApi,
	FederationlistApi,
	OrgAdmin,
	Provider,
	Admin,
	User,

	#[serde(untagged)]
	Unknown(String),
}

/// Enum for error parsing a JwtPayload into a ZitadelJWT
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Deserialize, Serialize, thiserror::Error)]
#[error("Missing or invalid claim `{0}`")]
#[repr(transparent)]
pub struct MissingClaim(pub &'static str);
pub use MissingClaim as JWTError;

impl TryFrom<JwtPayload> for ZitadelJWT {
	type Error = JWTError;
	fn try_from(value: JwtPayload) -> Result<Self, Self::Error> {
		fn claim<X>(
			value: &JwtPayload,
			claim: &'static str,
			f: impl Fn(&Value) -> Option<X>,
		) -> Result<X, MissingClaim> {
			value.claim(claim).and_then(f).ok_or(MissingClaim(claim))
		}

		// Parse homeserver entries for different projects
		let mut homeservers_list = HashMap::new();
		for (key, value) in value.claims_set() {
			if key.ends_with(".homeserver") {
				if let Some(homeserver_url) = value.as_str() {
					let project_id = key.trim_end_matches(".homeserver").to_owned();
					homeservers_list.insert(project_id, homeserver_url.to_owned());
				}
			}
		}

		Ok(Self {
			iss: value.issuer().map(ToOwned::to_owned).ok_or(MissingClaim("iss"))?,
			exp: value.expires_at().ok_or(MissingClaim("exp"))?.into(),
			iat: value.issued_at().ok_or(MissingClaim("iat"))?.into(),
			sub: value.subject().map(ToOwned::to_owned).ok_or(MissingClaim("sub"))?,
			homeserver: value.claim("homeserver").and_then(|v| v.as_str().map(ToOwned::to_owned)),
			homeservers_list: (!homeservers_list.is_empty()).then_some(homeservers_list),
			localpart: value.claim("localpart").and_then(|v| v.as_str().map(ToOwned::to_owned)),
			profession_oid: claim(&value, "professionOID", |v| Some(v.as_str()?.into()))?,
			telematik_id: claim(&value, "idNummer", |v| Some(v.as_str()?.into()))?,
			roles: claim(&value, "roles", |v| serde_json::from_value(v.clone()).ok())?,
		})
	}
}

impl TryFrom<ZitadelJWT> for JwtPayload {
	type Error = ToJwtPayloadError;
	fn try_from(value: ZitadelJWT) -> Result<Self, Self::Error> {
		let mut payload = JwtPayload::new();
		payload.set_issuer(value.iss);
		payload.set_expires_at(&value.exp.into());
		payload.set_issued_at(&value.iat.into());
		payload.set_subject(value.sub);

		// Set each homeserver entry as a separate claim
		if let Some(homeservers) = value.homeservers_list {
			for (project_id, homeserver_url) in homeservers {
				payload
					.set_claim(&format!("{project_id}.homeserver"), Some(homeserver_url.into()))?;
			}
		}

		payload.set_claim("homeserver", Some(value.homeserver.into()))?;
		payload.set_claim("localpart", Some(value.localpart.into()))?;
		payload.set_claim("professionOID", Some(value.profession_oid.into()))?;
		payload.set_claim("idNummer", Some(value.telematik_id.into()))?;
		payload.set_claim("roles", Some(serde_json::to_value(value.roles)?))?;

		Ok(payload)
	}
}

/// Enum for error converting ZitadelJWT into JwtPayload
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ToJwtPayloadError {
	#[error("Error serializing roles: {0}")]
	SerializeRoles(#[from] serde_json::Error),
	#[error("Error inserting into JwtPayload claim: {0}")]
	InsertClaim(#[from] josekit::JoseError),
}

/// Enum for errors on ZitadelJWT functions
#[derive(Debug, thiserror::Error)]
pub enum ZitadelJWTError {
	/// Signing private key missing kid
	#[error("Private key is missing kid")]
	MissingKeyId,
	/// Josekit error during creation of jwt
	#[error("Error creating the token: {0}")]
	JosekitError(#[from] josekit::JoseError),
	/// Error converting to a josekit::JwtPayload
	#[error("Error converting to JwtPayload: {0}")]
	ToJwtPayloadError(#[from] ToJwtPayloadError),
}

impl ZitadelJWT {
	/// Converts the zitadel token to jwt
	pub fn to_jwt(&self, private_key: &Jwk) -> Result<String, ZitadelJWTError> {
		let mut header = JwsHeader::new();
		header.set_algorithm("RS256");
		header.set_token_type("JWT");
		header.set_key_id(private_key.key_id().ok_or(ZitadelJWTError::MissingKeyId)?);

		let signer = josekit::jws::RS256.signer_from_jwk(private_key)?;

		josekit::jwt::encode_with_signer(&self.clone().try_into()?, &header, &signer)
			.map_err(ZitadelJWTError::JosekitError)
	}
}

#[cfg(test)]
mod tests {
	#![allow(clippy::expect_used)]
	use std::collections::HashMap;

	use anyhow::{Ok, Result};
	use josekit::{jwk::Jwk, jws::RS256, jwt::JwtPayload, Map};
	use serde_json::{from_value, json, Value};
	use time::OffsetDateTime;

	use super::*;

	#[test]
	fn test_parse_default() {
		let default_token: Result<ZitadelJWT, _> = JwtPayload::new().try_into();

		assert!(default_token.is_err());
	}

	#[allow(clippy::unwrap_used)]
	fn payload_fixture() -> Map<String, Value> {
		from_value(json!({
			"amr": [
				"pwd"
			],
			"at_hash": "IUt5Flxee-XJFqp0ei3jJw",
			"aud": [
				"292434404779753474",
				"regservice"
			],
			"auth_time": 1731573935,
			"azp": "regservice",
			"client_id": "regservice",
			"exp": 1731573935,
			"sub": "293728322112716802",
			"homeserver": "test.com",
			"my-project.homeserver": "my-project-url.com",
			"my-other-project.homeserver": "my-other-project-url.com",
			"localpart": "bobby",
			"iat": 1731573935,
			"idNummer": "1-1a25sd-d529",
			"iss": "https://zitadel.staging.famedly.de",
			"professionOID": "1.2.276.0.76.5.30",
			"roles": {
				"OrgAdmin": ["292434404779753474"],
				"FederationlistApi": ["292434404779753474"],
				"TimProviderApi": ["292434404779753474"],
				"Provider": ["292434404779753474"],
				"Admin": ["292434404779753474"],
				"User": ["292434404779753474"]
			},
		}))
		.unwrap()
	}

	#[allow(clippy::unwrap_used)]
	fn payload_fixture_none_optional() -> Map<String, Value> {
		from_value(json!({
			"amr": [
				"pwd"
			],
			"at_hash": "IUt5Flxee-XJFqp0ei3jJw",
			"aud": [
				"292434404779753474",
				"regservice"
			],
			"auth_time": 1731573935,
			"azp": "regservice",
			"client_id": "regservice",
			"exp": 1731573935,
			"sub": "293728322112716802",
			"iat": 1731573935,
			"idNummer": "1-1a25sd-d529",
			"iss": "https://zitadel.staging.famedly.de",
			"professionOID": "1.2.276.0.76.5.30",
			"roles": {
				"OrgAdmin": ["292434404779753474"],
				"FederationlistApi": ["292434404779753474"],
				"TimProviderApi": ["292434404779753474"],
				"Provider": ["292434404779753474"],
				"Admin": ["292434404779753474"],
				"User": ["292434404779753474"]
			},
		}))
		.unwrap()
	}

	#[allow(clippy::unwrap_used)]
	fn payload_fixture_unknown_role() -> Map<String, Value> {
		from_value(json!({
			"amr": [
				"pwd"
			],
			"at_hash": "IUt5Flxee-XJFqp0ei3jJw",
			"aud": [
				"292434404779753474",
				"regservice"
			],
			"auth_time": 1731573935,
			"azp": "regservice",
			"client_id": "regservice",
			"exp": 1731573935,
			"sub": "293728322112716802",
			"iat": 1731573935,
			"idNummer": "1-1a25sd-d529",
			"iss": "https://zitadel.staging.famedly.de",
			"professionOID": "1.2.276.0.76.5.30",
			"roles": {
				"OrgAdmin": ["292434404779753474"],
				"FederationlistApi": ["292434404779753474"],
				"TimProviderApi": ["292434404779753474"],
				"Provider": ["292434404779753474"],
				"Admin": ["292434404779753474"],
				"User": ["292434404779753474"],
				"UnknownRole": ["292434404779753474"]
			},
		}))
		.unwrap()
	}

	#[test]
	#[allow(clippy::unreadable_literal)]
	fn test_simple_parse() -> Result<()> {
		let parsed_token: ZitadelJWT = JwtPayload::from_map(payload_fixture())?.try_into()?;

		let mut homeservers_list = HashMap::new();
		homeservers_list.insert("my-project".to_owned(), "my-project-url.com".to_owned());
		homeservers_list
			.insert("my-other-project".to_owned(), "my-other-project-url.com".to_owned());

		let token = ZitadelJWT {
			iss: "https://zitadel.staging.famedly.de".to_owned(),
			exp: OffsetDateTime::from_unix_timestamp(1731573935)?,
			iat: OffsetDateTime::from_unix_timestamp(1731573935)?,
			sub: "293728322112716802".to_owned(),
			homeserver: Some("test.com".to_owned()),
			homeservers_list: Some(homeservers_list),
			localpart: Some("bobby".to_owned()),
			profession_oid: "1.2.276.0.76.5.30".to_owned(),
			telematik_id: "1-1a25sd-d529".to_owned(),
			roles: HashMap::from([
				(ZitadelUserRole::OrgAdmin, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::FederationlistApi, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::TimProviderApi, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::Provider, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::Admin, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::User, vec!["292434404779753474".to_owned()]),
			]),
		};

		assert_eq!(parsed_token, token);

		Ok(())
	}

	#[test]
	#[allow(clippy::unreadable_literal)]
	fn test_simple_parse_none_optional() -> Result<()> {
		let parsed_token: ZitadelJWT =
			JwtPayload::from_map(payload_fixture_none_optional())?.try_into()?;

		let token = ZitadelJWT {
			iss: "https://zitadel.staging.famedly.de".to_owned(),
			exp: OffsetDateTime::from_unix_timestamp(1731573935)?,
			iat: OffsetDateTime::from_unix_timestamp(1731573935)?,
			sub: "293728322112716802".to_owned(),
			homeserver: None,
			homeservers_list: None,
			localpart: None,
			profession_oid: "1.2.276.0.76.5.30".to_owned(),
			telematik_id: "1-1a25sd-d529".to_owned(),
			roles: HashMap::from([
				(ZitadelUserRole::OrgAdmin, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::FederationlistApi, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::TimProviderApi, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::Provider, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::Admin, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::User, vec!["292434404779753474".to_owned()]),
			]),
		};

		assert_eq!(parsed_token, token);

		Ok(())
	}

	#[test]
	fn test_to_jwt() -> Result<()> {
		let parsed_token: ZitadelJWT = JwtPayload::from_map(payload_fixture())?.try_into()?;
		let mut private_key =
			Jwk::generate_rsa_key(2048).expect("Error generating token private key");
		private_key.set_key_id("123456");
		let jwt = parsed_token.to_jwt(&private_key)?;

		let verifier = RS256.verifier_from_jwk(&private_key.to_public_key()?)?;
		let (payload, _) = josekit::jwt::decode_with_verifier(jwt, &verifier)?;

		let decoded_token: ZitadelJWT = payload.try_into()?;

		assert_eq!(parsed_token, decoded_token);

		Ok(())
	}

	#[test]
	fn test_unknown_role() -> Result<()> {
		let token = JwtPayload::from_map(payload_fixture_unknown_role())?;
		let parsed_token: ZitadelJWT = token.clone().try_into()?;

		let decoded_token: JwtPayload = parsed_token.try_into()?;

		assert_eq!(
			token.claim("roles").expect("Missing roles claim"),
			decoded_token.claim("roles").expect("Missing roles claim")
		);

		Ok(())
	}
}
