package org.mk.moqui.authentication

import groovy.transform.CompileStatic
import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityFacade
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.context.DefaultAuthorizers
import org.pac4j.core.context.J2EContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.J2ESessionStore
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.SecurityGrantedAccessAdapter
import org.pac4j.core.http.adapter.J2ENopHttpActionAdapter
import org.pac4j.core.profile.CommonProfile
import org.pac4j.core.profile.ProfileManager

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.WebConnection
import java.util.function.Function

@CompileStatic
class Login {
    static final J2ESessionStore sessionStore = new J2ESessionStore()

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

    static J2EContext buildContext(ExecutionContext ec) {
        def request = ec.getWeb().getRequest()
        def response = ec.getWeb().getResponse()

        return new J2EContext(request, response, sessionStore)
    }

    static String getMoquiUrl(ExecutionContext ec) {
        return ec.web.getWebappRootUrl(true, true)
    }

    static Function getProfileManagerFactory(ExecutionContext ec) {
        return { WebContext ctx -> new MoquiProfileManager(ctx, ec) } as Function<WebContext, ProfileManager>
    }

    static login(ExecutionContext ec) {
        ec.artifactExecution.disableAuthz()
        def logger = ec.getLogger()

        DefaultSecurityLogic logic = new DefaultSecurityLogic()
        logic.setProfileManagerFactory(getProfileManagerFactory(ec))

        def clients = getEnabledClients(ec.entity)
        if (clients.size() < 1) {
            ec.logger.warn('No identity clients configured for moqui-pac4j-authentication')
            errorRedirect(ec)
        }

        try {
            def result = logic.perform(
                    buildContext(ec),
                    getConfig(ec),
                    new MoquiAccessGrantedAdapter(),
                    J2ENopHttpActionAdapter.INSTANCE,
                    clients.join(','),
                    DefaultAuthorizers.IS_AUTHENTICATED,
                    '',
                    false
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

        DefaultCallbackLogic callback = new DefaultCallbackLogic()
        callback.setProfileManagerFactory(getProfileManagerFactory(ec))
        try {
            def result = callback.perform(
                    context,
                    getConfig(ec),
                    J2ENopHttpActionAdapter.INSTANCE,
                null,
                    true,
                    false,
                    true,
                    getEnabledClients(ec.entity).join(',')
            )
        }
        catch (Exception e) {
            e.printStackTrace()
        } finally {
            ec.artifactExecution.enableAuthz()
        }
    }

    static void logout(ExecutionContext ec) {
        ec.artifactExecution.disableAuthz()
        DefaultLogoutLogic logout = new DefaultLogoutLogic()
        logout.setProfileManagerFactory(getProfileManagerFactory(ec))
        def loginUrl = "${getMoquiUrl(ec)}/Login"

        try {
            logout.perform(
                buildContext(ec),
                getConfig(ec),
                J2ENopHttpActionAdapter.INSTANCE,
                loginUrl,
                '/',
                true,
                true,
                true
            )
        } finally {
            ec.artifactExecution.enableAuthz()
        }
    }
}

class MoquiAccessGrantedAdapter implements SecurityGrantedAccessAdapter<Object, WebContext> {
    Object adapt(WebContext context, Collection<CommonProfile> profiles, Object... parameters) {
        return null
    }
}
