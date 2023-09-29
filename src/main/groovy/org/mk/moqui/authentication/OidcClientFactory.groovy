package org.mk.moqui.authentication

import org.moqui.entity.EntityFacade
import org.pac4j.core.client.Client
import org.pac4j.oidc.client.OidcClient
import org.pac4j.oidc.config.OidcConfiguration
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod

class OidcClientFactory implements AuthenticationClientFactory{

    List<Client> buildClients(EntityFacade ef) {
        def clients = ef
                .find('mk.authentication.OidcAuthenticationClient')
                .list()
                .collect { entity ->
            OidcConfiguration config = new OidcConfiguration()
            config.setDiscoveryURI(entity.discoveryUri)
            config.setClientId(entity.id)
            config.setSecret(entity.secret)
            config.setClientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            config.setPreferredJwsAlgorithmAsString(entity.preferredJwsAlgorithm as String)
            config.setUseNonce(entity.useNonce == 'Y')
            def client = new OidcClient(config)
            client.setName(entity.clientId)
            return client
        }
        return clients
    }
}
