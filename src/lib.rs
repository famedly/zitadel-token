//! Rust representation of a Zitadel token

use std::collections::HashMap;

use josekit::{jwk::Jwk, jws::JwsHeader, jwt::JwtPayload};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
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

/// Enum for error converting ZitadelJWT into JwtPayload
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ToJwtPayloadError {
	#[error("Error serializing roles: {0}")]
	SerializeRoles(#[from] serde_json::Error),
	#[error("Error inserting into JwtPayload claim: {0}")]
	InsertClaim(#[from] josekit::JoseError),
}

impl TryFrom<ZitadelJWT> for JwtPayload {
	type Error = ToJwtPayloadError;
	fn try_from(value: ZitadelJWT) -> Result<Self, Self::Error> {
		let mut paylaod = JwtPayload::new();
		paylaod.set_issuer(value.iss);
		paylaod.set_expires_at(&value.exp.into());
		paylaod.set_not_before(&value.nbf.into());
		paylaod.set_subject(value.sub);

		// This should never fail
		let map = serde_json::to_value(value.roles)?;

		paylaod.set_claim("roles", Some(map))?;
		paylaod
			.set_claim("homeserver", Some(serde_json::Value::String(value.homeserver.clone())))?;
		paylaod.set_claim(
			"professionOID",
			Some(serde_json::Value::Number(value.profession_oid.into())),
		)?;
		paylaod
			.set_claim("idNummer", Some(serde_json::Value::Number(value.telematik_id.into())))?;

		Ok(paylaod)
	}
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

	#[test]
	fn test_to_jwt() -> Result<()> {
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
		let mut private_key =
			Jwk::generate_rsa_key(2048).expect("Error generating token private key");
		private_key.set_key_id("123456");
		let jwt = parsed_toke.to_jwt(&private_key)?;

		let verifier = RS256.verifier_from_jwk(&private_key.to_public_key()?)?;
		let (payload, _) = josekit::jwt::decode_with_verifier(jwt, &verifier)?;

		let decoded_token: ZitadelJWT = payload.try_into()?;

		assert_eq!(parsed_toke, decoded_token);

		Ok(())
	}
}
