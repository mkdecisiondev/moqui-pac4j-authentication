# pac4j Authentication for Moqui

Allows users to sign into Moqui using a variety of SSO [clients](http://www.pac4j.org/3.0.x/docs/clients.html) supported
by [pac4j](https://github.com/pac4j/pac4j).

Users in Moqui are directly correlated using the `username` of the identity provider token. If users in Moqui and the identity
provider are not synced, users should not be able to create accounts with their own usernames with the identity provider
as that would allow them to assume the account of the Moqui user.

So far, this has only been tested with the OpenID Connect client using Keycloak as the authentication server. More entities
would need to be created for other client types such as SAML or Oauth.

pac4j supports multiple clients at the same time, but the current use case is just one SSO client being used to authenticate
to any user. Perhaps the other clients could be used with more specific endpoints for customer logins through social media.

OpenID clients are configured in the `mk.authentication.AuthenticationClient` and the `mk.authentication.OidcAuthenticationClient`
entities. The first is used to allow enabling/disabling a client and could store other data for the client later, like
roles required to use the client. The latter has client-type specific configuration data for OpenID Connect clients.

## Login Paths

The default Moqui login is moved to `/Login/Local`. Hitting /Login will automatically try to sign you in using the enabled
clients. All other paths, such as logout, function as they do with the default login.

The callback path for configuring clients is `/Login/callback`. Logging out will attempt to redirect to `/Login/Local`.

## TODO
- Error handling. Any errors returned by the authentication provider are not handled or communicated to the user.
- More Client support: SAML, Oauth
- Allow extension by other components. Adding client support should be as easy as adding to the `clientFactories` in
`Login.groovy` and making sure that an `AuthenticationClient` is added and enabled for created clients.
- Role-based access: a use case may exist where only certain users from an identity provider are allowed to authenticate
with Moqui.

Possible features

- Account linking. Instead trusting the identity provider fully, require a sign-in to Moqui to link the accounts. This is
somewhat bad UX for an SSO solution, since, in a pure SSO, the user would not have any credentials in the service.