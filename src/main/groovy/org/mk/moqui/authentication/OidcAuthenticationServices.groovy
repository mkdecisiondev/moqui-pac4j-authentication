package org.mk.moqui.authentication

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyConverter
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.moqui.context.ExecutionContext
import org.moqui.impl.context.ExecutionContextImpl
import org.moqui.impl.context.UserFacadeImpl
import org.pac4j.core.client.Client
import org.pac4j.oidc.client.OidcClient
import org.slf4j.LoggerFactory

class OidcAuthenticationServices {
    static final def resourceRetreiver = new DefaultResourceRetriever(10000, 10000)
    static final def logger = LoggerFactory.getLogger(OidcAuthenticationServices.class)

    static Map<String, Object> verifyToken(ExecutionContext ec) {
        def token = ec.web.request.getHeader("api_token")
        def username = null
        if (!token) return [:]

        def clients = new OidcClientFactory().buildClients(ec.entity)
        if (!clients) return [:] // No clients configured, return

        if (ec.user.userId) {
            username = ec.user.username
        } else {
            def jwt = verifyOidcToken(clients, token)
            if (jwt) {
                username = jwt.JWTClaimsSet.getStringClaim('preferred_username')
                (ec.user as UserFacadeImpl).internalLoginUser(username)
            } else {
                ec.logger.warn('Failed to verify api_token')
            }
        }

        return [username: username]
    }

    static Map<String, Object> getRealmConfiguration(ExecutionContext ec) {
        Map<String, Object> result = [:]
        def clients = new OidcClientFactory().buildClients(ec.entity)
        if (clients) {
            result.oidcRealmUrl = (clients.first() as OidcClient).configuration.discoveryURI
        }
        return result
    }

    /**
     * Returns the parsed and verified token
     * @param clients
     * @param token
     * @return
     */
    static SignedJWT verifyOidcToken(List<Client> clients, String token) {
        SignedJWT jwt = null

        try {
            // Find a client configuration
            OidcClient client = clients.first() as OidcClient

            // Download the OIDC metadata
            def metadata = OIDCProviderMetadata.parse(resourceRetreiver.retrieveResource(new URL(client.configuration.discoveryURI)).getContent())
            // Download the JWKs from the OIDC endpoint
            def set = JWKSet.load(metadata.getJWKSetURI().toURL())

            // Parse the token so we can use the header
            jwt = SignedJWT.parse(token)

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
        } catch (JOSEException e) {
            if (e instanceof BadJWTException) {
                logger.warn("${e.message} for ${jwt.JWTClaimsSet.getStringClaim("preferred_username")}")
            } else {
                logger.warn("JWT signature verification failed")
            }
        } catch (Exception err) {
            logger.error('There was a problem parsing JWT request', err)
        } finally {
            return jwt
        }
    }
}
