//! Rust representation of a Zitadel token

use std::collections::HashMap;

use josekit::jwt::JwtPayload;
use serde::Deserialize;
use time::OffsetDateTime;

/// Struct that represents a JWT from Zitadel
#[derive(Debug, Clone, PartialEq)]
pub struct ZitadelJWT {
	/// Token Issuer
	pub iss: String,
	/// Token expiration date
	pub exp: OffsetDateTime,
	/// Token not before date
	pub nbf: OffsetDateTime,
	/// Token subject
	pub sub: String,
	/// Map of roles to array of projects ids
	pub roles: HashMap<ZitadelUserRole, Vec<String>>,
	/// Matrix Homeserver
	pub homeserver: String,
	/// Profession oid
	pub profession_oid: i64,
	/// TelematikId
	pub telematik_id: i64,
}

/// User roles available on Zitadel
#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
#[allow(missing_docs)]
pub enum ZitadelUserRole {
	TimProviderApi,
	FederationlistApi,
	OrgAdmin,
	Provider,
}

/// Enum for error parsing a JwtPayload into a ZitadelJWT
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum JWTError {
	#[error("Token missing iss claim")]
	MissingIss,
	#[error("Token missing exp claim")]
	MissingExp,
	#[error("Token missing nbf claim")]
	MissingNbf,
	#[error("Token missing sub claim")]
	MissingSub,
	#[error("Token missing roles claim")]
	MissingRoles,
	#[error("Token missing homeserver claim")]
	MissingHomeserver,
	#[error("Token missing professionOID claim")]
	MissingProfessionOid,
	#[error("Token missing idNummer claim")]
	MissingTelematikId,
}

impl TryFrom<JwtPayload> for ZitadelJWT {
	type Error = JWTError;
	fn try_from(value: JwtPayload) -> Result<Self, Self::Error> {
		use JWTError::*;
		let iss = value.issuer().map(ToOwned::to_owned).ok_or(MissingIss)?;
		let exp: OffsetDateTime = value.expires_at().ok_or(MissingExp)?.into();
		let nbf: OffsetDateTime = value.not_before().ok_or(MissingNbf)?.into();
		let sub = value.subject().map(ToOwned::to_owned).ok_or(MissingSub)?;

		let roles: HashMap<ZitadelUserRole, Vec<String>> = value
			.claim("roles")
			.and_then(|roles| serde_json::from_value(roles.clone()).ok())
			.ok_or(MissingRoles)?;
		let homeserver =
			value.claim("homeserver").and_then(|v| v.as_str()).ok_or(MissingHomeserver)?.to_owned();
		let profession_oid = value
			.claim("professionOID")
			.and_then(serde_json::Value::as_i64)
			.ok_or(MissingProfessionOid)?;
		let telematik_id = value
			.claim("idNummer")
			.and_then(serde_json::Value::as_i64)
			.ok_or(MissingTelematikId)?;

		Ok(Self { iss, exp, nbf, sub, roles, homeserver, profession_oid, telematik_id })
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use anyhow::{Ok, Result};
	use josekit::{jwt::JwtPayload, Map};
	use time::OffsetDateTime;

	use crate::{ZitadelJWT, ZitadelUserRole};

	#[test]
	fn test_parse_default() {
		let default_token: Result<ZitadelJWT, _> = JwtPayload::new().try_into();

		assert!(default_token.is_err());
	}

	#[test]
	#[allow(clippy::unreadable_literal)]
	fn test_simple_parse() -> Result<()> {
		let parsed_toke: Map<String, serde_json::Value> = serde_json::from_str(
			r#"{
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
				"nbf": 1731563935,
				"homeserver": "test.com",
				"iat": 1731573935,
				"idNummer": 123456,
				"iss": "https://zitadel.staging.famedly.de",
				"professionOID": 123456,
				"roles": {
							"OrgAdmin": ["292434404779753474"],
							"FederationlistApi": ["292434404779753474"],
							"TimProviderApi": ["292434404779753474"],
							"Provider": ["292434404779753474"]
						},
				"sub": "293728322112716802"
		}"#,
		)?;
		let parsed_toke: ZitadelJWT = JwtPayload::from_map(parsed_toke)?.try_into()?;

		let token = ZitadelJWT {
			iss: "https://zitadel.staging.famedly.de".to_owned(),
			exp: OffsetDateTime::from_unix_timestamp(1731573935)?,
			nbf: OffsetDateTime::from_unix_timestamp(1731563935)?,
			sub: "293728322112716802".to_owned(),
			roles: HashMap::from([
				(ZitadelUserRole::OrgAdmin, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::FederationlistApi, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::TimProviderApi, vec!["292434404779753474".to_owned()]),
				(ZitadelUserRole::Provider, vec!["292434404779753474".to_owned()]),
			]),
			homeserver: "test.com".to_owned(),
			profession_oid: 123456,
			telematik_id: 123456,
		};

		assert_eq!(parsed_toke, token);

		Ok(())
	}
}
