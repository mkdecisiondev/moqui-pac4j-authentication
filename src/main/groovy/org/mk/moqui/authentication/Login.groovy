package org.mk.moqui.authentication

import groovy.transform.CompileStatic
import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityFacade
import org.moqui.impl.context.UserFacadeImpl
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.authorization.authorizer.DefaultAuthorizers
import org.pac4j.core.context.session.SessionStore
import org.pac4j.jee.context.JEEContext
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.context.WebContext
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.engine.SecurityGrantedAccessAdapter
import org.pac4j.core.profile.UserProfile
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter


@CompileStatic
class Login {

    static Config globalConfig
    static List<AuthenticationClientFactory> clientFactories = [
            new OidcClientFactory() as AuthenticationClientFactory
    ]

    static List<Client> getClients(EntityFacade ef) {
        List<List<Client>> list = clientFactories.collect({factory -> factory.buildClients(ef)})
        return list.flatten() as List<Client>
    }

    static Config getConfig(ExecutionContext ec) {
        return new Config("${getMoquiUrl(ec)}/Login/callback", getClients(ec.entity))
    }

    static List<String> getEnabledClients(EntityFacade ef) {
        return ef.find('mk.authentication.AuthenticationClient')
                .condition('enabled', 'Y')
                .list()
                .collect { entity -> entity.clientId as String }
    }

    static JEEContext buildContext(ExecutionContext ec) {
        def request = ec.getWeb().getRequest()
        def response = ec.getWeb().getResponse()

        return new JEEContext(request, response)
    }

    static String getMoquiUrl(ExecutionContext ec) {
        return ec.web.getWebappRootUrl(true, true)
    }


    static login(ExecutionContext ec) {
        ec.artifactExecution.disableAuthz()
        def logger = ec.getLogger()
        JEESessionStore sessionStore = JEESessionStore.INSTANCE


        def clients = getEnabledClients(ec.entity)
        if (clients.size() < 1) {
            ec.logger.warn('No identity clients configured for moqui-pac4j-authentication')
            errorRedirect(ec)
        }

        try {
            def result = DefaultSecurityLogic.INSTANCE.perform(
                    buildContext(ec),
                    sessionStore,
                    getConfig(ec),
                    new MoquiAccessGrantedAdapter(),
                    JEEHttpActionAdapter.INSTANCE,
                    clients.join(','),
                    DefaultAuthorizers.IS_AUTHENTICATED,
                    ''
            )
        }
        catch (Exception e) {
            ec.logger.log(200, "Encounter login error", e)
            errorRedirect(ec)
        } finally {
            ec.artifactExecution.enableAuthz()
        }
    }

    // Called when there is an error to redirect the user to /Login/Local
    static void errorRedirect(ExecutionContext ec) {
        if (!ec.web.response.isCommitted()) {
            ec.logger.warn('Encountered login error, redirecting to /Login/Local')
            ec.web.response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private")
            ec.web.response.sendRedirect('/Login/Local')
        }
    }

    static void callback(ExecutionContext ec) {
        ec.artifactExecution.disableAuthz()
        def logger = ec.getLogger()
        def context = buildContext(ec)
        JEESessionStore sessionStore = JEESessionStore.INSTANCE

        try {
            DefaultCallbackLogic.INSTANCE.perform(
                context,
                sessionStore,
                getConfig(ec),
                JEEHttpActionAdapter.INSTANCE,
                null,
                false,
                null
            )

            // handle incoming profiles
            ProfileManager profileManager = new ProfileManager(context, sessionStore)
            new MoquiAccessGrantedAdapter().adapt(context, sessionStore, profileManager.getProfiles())

            // login user
            Optional<UserProfile> optionalProfile = profileManager.getProfile()
            if (optionalProfile.isPresent()) {
                UserProfile profile = optionalProfile.get()
                ((UserFacadeImpl)ec.user).internalLoginUser(profile.username)
            }
        }
        catch (Exception e) {
            e.printStackTrace()
        } finally {
            ec.artifactExecution.enableAuthz()
        }
    }

    static void logout(ExecutionContext ec) {
        ec.artifactExecution.disableAuthz()

        def loginUrl = "${getMoquiUrl(ec)}/Login"
        JEESessionStore sessionStore = JEESessionStore.INSTANCE

        try {
            DefaultLogoutLogic.INSTANCE.perform(
                buildContext(ec),
                sessionStore,
                getConfig(ec),
                JEEHttpActionAdapter.INSTANCE,
                loginUrl,
                '/',
                false,
                false,
                true
            )

            ec.user.logoutUser()
        } finally {
            ec.artifactExecution.enableAuthz()
        }
    }
}

class MoquiAccessGrantedAdapter implements SecurityGrantedAccessAdapter {
    Object adapt(WebContext context, SessionStore sessionStore, Collection<UserProfile> profiles, Object... parameters) throws Exception {
        return null
    }
}
