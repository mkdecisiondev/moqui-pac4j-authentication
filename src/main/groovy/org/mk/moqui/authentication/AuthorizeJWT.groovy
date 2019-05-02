package org.mk.moqui.authentication

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyConverter
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.moqui.entity.EntityCondition
import org.moqui.impl.context.ExecutionContextImpl
import org.pac4j.oidc.client.OidcClient
import com.nimbusds.jose.util.DefaultResourceRetriever

import java.sql.Timestamp

static void saveApiKey(ExecutionContextImpl eci, String key, long exp) {
    // Copied from UserFacadeImpl
    def userId = eci.user.getUserId()
    String hashedKey = eci.ecfi.getSimpleHash(key, "", eci.ecfi.getLoginKeyHashType(), false)
    Timestamp fromDate = new Timestamp(System.currentTimeMillis())

    // Check to see if the key already exists
    def existing = eci.entity.find('moqui.security.UserLoginKey').condition([userId: userId, loginKey: hashedKey]).one()
    if (!existing) {
        eci.serviceFacade.sync().name("create", "moqui.security.UserLoginKey")
            .parameters([loginKey: hashedKey, userId: userId, fromDate: fromDate, thruDate: new Timestamp(exp)])
            .disableAuthz().requireNewTransaction(true).call()
    }

    // clean out expired keys
    eci.entity.find("moqui.security.UserLoginKey").condition("userId", userId)
        .condition("thruDate", EntityCondition.LESS_THAN, fromDate).disableAuthz().deleteAll()
}

static void sendUnauthorized(ExecutionContextImpl eci) {
    // JWT was not valid
    eci.web.response.setContentType('application/json')
    eci.web.response.setStatus(403)
    eci.web.response.writer.write('{"error": "403"}')
}

def resourceRetreiver = new DefaultResourceRetriever(10000, 10000)

ExecutionContextImpl eci = context.ec

try {
// Disable artifact permissions
    eci.artifactExecution.disableAuthz()

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
    // Verify JWT Signature
    jwt.verify(verifier)

    // Verify JWT Claims (expiration/not before date)
    claimsVerifier.verify(jwt.JWTClaimsSet)

    // Log user in using the username in the token
    eci.userFacade.internalLoginUser(jwt.JWTClaimsSet.getStringClaim("preferred_username"))

    // Save the api key so it can be used to authenticate requests
    saveApiKey(eci, jwt.parsedString, jwt.JWTClaimsSet.getExpirationTime().toInstant().toEpochMilli())
} catch (JOSEException | BadJWTException e) {
    if (e instanceof JOSEException) {
        eci.logger.warn("JWT signature verification failed")
    } else if (e instanceof BadJWTException) {
        eci.logger.warn("${e.message} for ${jwt.JWTClaimsSet.getStringClaim("preferred_username")}")
    }
    sendUnauthorized(eci)
} catch(Exception err) {
    eci.logger.error('There was a problem parsing JWT request')
    err.printStackTrace()
    sendUnauthorized(eci)
} finally {
    eci.artifactExecution.enableAuthz()

}
