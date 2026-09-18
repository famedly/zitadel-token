//! Rust representation of a Zitadel token

use std::collections::HashMap;

pub use famedly_zitadel_rust_client::v2::token::JwtPayload;
use jsonwebtoken::{Algorithm, EncodingKey, Header, errors::Error as JwtError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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
			claims: &HashMap<String, Value>,
			claim: &'static str,
			f: impl Fn(&Value) -> Option<X>,
		) -> Result<X, MissingClaim> {
			claims.get(claim).and_then(f).ok_or(MissingClaim(claim))
		}

		let claims = value.claims();

		// Parse homeserver entries for different projects
		let mut homeservers_list = HashMap::new();
		for (key, claim_value) in claims {
			if key.ends_with(".homeserver")
				&& let Some(homeserver_url) = claim_value.as_str()
			{
				let project_id = key.trim_end_matches(".homeserver").to_owned();
				homeservers_list.insert(project_id, homeserver_url.to_owned());
			}
		}

		Ok(Self {
			iss: value.issuer().to_owned(),
			exp: value.expires_at().ok_or(MissingClaim("exp"))?,
			iat: value.issued_at().ok_or(MissingClaim("iat"))?,
			sub: claim(claims, "sub", |v| Some(v.as_str()?.into()))?,
			homeserver: claims.get("homeserver").and_then(|v| v.as_str().map(ToOwned::to_owned)),
			homeservers_list: (!homeservers_list.is_empty()).then_some(homeservers_list),
			localpart: claims.get("localpart").and_then(|v| v.as_str().map(ToOwned::to_owned)),
			profession_oid: claim(claims, "professionOID", |v| Some(v.as_str()?.into()))?,
			telematik_id: claim(claims, "idNummer", |v| Some(v.as_str()?.into()))?,
			roles: claim(claims, "roles", |v| serde_json::from_value(v.clone()).ok())?,
		})
	}
}

impl TryFrom<ZitadelJWT> for JwtPayload {
	type Error = ToJwtPayloadError;
	fn try_from(value: ZitadelJWT) -> Result<Self, Self::Error> {
		let mut claims = Map::new();
		claims.insert("iss".to_owned(), Value::String(value.iss));
		claims.insert("exp".to_owned(), value.exp.unix_timestamp().into());
		claims.insert("iat".to_owned(), value.iat.unix_timestamp().into());
		claims.insert("sub".to_owned(), Value::String(value.sub));

		if let Some(homeservers) = value.homeservers_list {
			for (project_id, homeserver_url) in homeservers {
				claims.insert(format!("{project_id}.homeserver"), Value::String(homeserver_url));
			}
		}

		claims.insert("homeserver".to_owned(), value.homeserver.into());
		claims.insert("localpart".to_owned(), value.localpart.into());
		claims.insert("professionOID".to_owned(), Value::String(value.profession_oid));
		claims.insert("idNummer".to_owned(), Value::String(value.telematik_id));
		claims.insert("roles".to_owned(), serde_json::to_value(value.roles)?);

		Ok(serde_json::from_value(Value::Object(claims))?)
	}
}

/// Enum for error converting ZitadelJWT into JwtPayload
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ToJwtPayloadError {
	#[error("Error converting to JwtPayload: {0}")]
	Serde(#[from] serde_json::Error),
}

/// Enum for errors on ZitadelJWT functions
#[derive(Debug, thiserror::Error)]
pub enum ZitadelJWTError {
	/// Signing key id is missing or empty
	#[error("Private key is missing kid")]
	MissingKeyId,
	/// Error creating the JWT
	#[error("Error creating the token: {0}")]
	EncodeError(#[from] JwtError),
	/// Error converting to a JwtPayload
	#[error("Error converting to JwtPayload: {0}")]
	ToJwtPayloadError(#[from] ToJwtPayloadError),
}

impl ZitadelJWT {
	/// Converts the zitadel token to jwt
	pub fn to_jwt(&self, private_key: &EncodingKey, kid: &str) -> Result<String, ZitadelJWTError> {
		if kid.is_empty() {
			return Err(ZitadelJWTError::MissingKeyId);
		}

		let mut header = Header::new(Algorithm::RS256);
		header.typ = Some("JWT".to_owned());
		header.kid = Some(kid.to_owned());

		let claims: JwtPayload = self.clone().try_into()?;
		jsonwebtoken::encode(&header, &claims, private_key).map_err(ZitadelJWTError::EncodeError)
	}
}

#[cfg(test)]
mod tests {
	#![allow(clippy::expect_used)]
	use std::collections::HashMap;

	use anyhow::{Ok, Result};
	use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation, decode, jwk::Jwk};
	use serde_json::{Map, Value, from_value, json};
	use time::OffsetDateTime;

	use super::*;

	const TEST_RSA_PEM: &str = include_str!("../tests/fixtures/test-rsa.key");
	const TEST_RSA_JWK: &str = include_str!("../tests/fixtures/test-rsa.jwk.key");

	fn jwt_payload(map: Map<String, Value>) -> Result<JwtPayload> {
		Ok(from_value(Value::Object(map))?)
	}

	#[test]
	fn test_parse_default() {
		assert!(from_value::<JwtPayload>(json!({})).is_err());
	}

	#[test]
	fn test_parse_missing_profession_oid() -> Result<()> {
		let payload = jwt_payload(from_value(json!({
			"iss": "https://zitadel.staging.famedly.de",
			"exp": 1731573935,
			"iat": 1731573935,
			"sub": "293728322112716802",
			"idNummer": "1-1a25sd-d529",
			"roles": {
				"User": ["292434404779753474"]
			},
		}))?)?;

		let token: Result<ZitadelJWT, _> = payload.try_into();
		assert_eq!(token, Err(MissingClaim("professionOID")));

		Ok(())
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
		let parsed_token: ZitadelJWT = jwt_payload(payload_fixture())?.try_into()?;

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
		let parsed_token: ZitadelJWT = jwt_payload(payload_fixture_none_optional())?.try_into()?;

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
		let parsed_token: ZitadelJWT = jwt_payload(payload_fixture())?.try_into()?;
		let private_key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes())?;
		let jwt = parsed_token.to_jwt(&private_key, "123456")?;

		let jwk: Jwk = serde_json::from_str(TEST_RSA_JWK)?;
		let decoding_key = DecodingKey::from_jwk(&jwk)?;
		let mut validation = Validation::new(Algorithm::RS256);
		validation.leeway = 0;
		validation.validate_exp = false;
		validation.validate_aud = false;
		validation.validate_nbf = false;
		validation.required_spec_claims.clear();

		let decoded = decode::<JwtPayload>(&jwt, &decoding_key, &validation)?;
		let decoded_token: ZitadelJWT = decoded.claims.try_into()?;

		assert_eq!(parsed_token, decoded_token);

		Ok(())
	}

	#[test]
	fn test_unknown_role() -> Result<()> {
		let token = jwt_payload(payload_fixture_unknown_role())?;
		let parsed_token: ZitadelJWT = token.clone().try_into()?;

		let decoded_token: JwtPayload = parsed_token.try_into()?;

		assert_eq!(
			token.claims().get("roles").expect("Missing roles claim"),
			decoded_token.claims().get("roles").expect("Missing roles claim")
		);

		Ok(())
	}
}
