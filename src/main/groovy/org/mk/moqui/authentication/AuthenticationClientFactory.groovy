package org.mk.moqui.authentication

import org.moqui.entity.EntityFacade
import org.pac4j.core.client.Client

interface AuthenticationClientFactory {
    List<Client> buildClients(EntityFacade ef)
}
