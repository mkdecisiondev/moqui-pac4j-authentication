package org.mk.moqui.authentication

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyConverter
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.moqui.impl.context.ExecutionContextImpl
import org.pac4j.jwt.config.signature.RSASignatureConfiguration
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator
import org.pac4j.oidc.client.OidcClient
import com.nimbusds.jose.util.DefaultResourceRetriever

def resourceRetreiver = new DefaultResourceRetriever(10000, 10000)

ExecutionContextImpl eci = context.ec

// Find a client configuration
def clients = new OidcClientFactory().buildClients(eci.entity)
OidcClient client = clients.first() as OidcClient

// Download the OIDC metadata
def metadata = OIDCProviderMetadata.parse(resourceRetreiver.retrieveResource(new URL(client.configuration.discoveryURI)).getContent())
// Download the JWKs from the OIDC endpoint
def set = JWKSet.load(metadata.getJWKSetURI().toURL())

// Parse the token so we can use the header
def jwt = SignedJWT.parse(context.token)

// Get the keyID that was used to sign the token
def key = set.getKeyByKeyId(jwt.header.keyID)

// Create a verifier
// TODO: These may be replaced by a JWTProcessor
def verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jwt.header, KeyConverter.toJavaKeys([key])[0])
def claimsVerifier = new DefaultJWTClaimsVerifier()

try {
	// Verify JWT Signature
	jwt.verify(verifier)

	// Verify JWT Claims (expiration/not before date)
	claimsVerifier.verify(jwt.JWTClaimsSet)

	// Log user in using the username in the token
	eci.userFacade.internalLoginUser(jwt.JWTClaimsSet.getStringClaim("preferred_username"))

	// Get and send the api key
	def apiKey = eci.userFacade.getLoginKey()
	eci.web.sendJsonResponse([apiKey: apiKey])
} catch (JOSEException | BadJWTException e) {
	if (e instanceof JOSEException) {
		eci.logger.warn("JWT signature verification failed")
	} else if (e instanceof BadJWTException) {
		eci.logger.warn("${e.message} for ${jwt.JWTClaimsSet.getStringClaim("preferred_username")}")
	}
	// JWT was not valid
	eci.web.response.setContentType('application/json')
	eci.web.response.setStatus(403)
	eci.web.response.writer.write('{"error": "403"}')
}
