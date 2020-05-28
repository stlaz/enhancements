## OpenShift Authentication

## The OpenShift OAuth Server

This section describes the function and authentication mechanisms used in
the OpenShift integrated OAuth2 server.

### Browser vs CLI Authentication

The OpenShift oauth-server distinguishes two paths an authenticating user
might use when approaching it - "challenge" and "login". To perform either of these,
one needs to be able to refer a name of an existing oauthclient object in
authentication requests so that the oauth-server can perform additional checks
when user gets authenticated.

#### Challenge flows

Challenge flows are used for command-line login and need to be
specifically allowed in the oauthclient the request is made with by setting the
`RespondWithChallenges` field to `true`.

The name "challenge" comes from a challenge request sent by the authentication
server in the `WWW-Authenticate` header (https://tools.ietf.org/html/rfc7235##section-4.1).

The `oc` binary currently handles two kinds of challenges:
- `Basic` - handled by HTTP basic authentication
- `Negotiate` - commonly used for SSO delivered by Kerberos, it's handled by
                using GSSAPI (linux, https://tools.ietf.org/html/rfc4178) or
                SSPI (windows) mechanisms

For identity providers that allow user/password authentication, the OpenShift
oauth-server issues the basic challenges itself and then passes the credentials
it obtains from the queried user further to the actual identity provider. To be
able to leverage the power of negotiate challenges, OpenShift allows configuring
the RequestHeader provider that makes it possible to redirect the challenge flows
to an external entity.

#### Login flows

Login flows are used to authenticate by using a browser. Login flows are allowed
for every configurable identity provider with the exception of RequestHeader that
needs to specifically configure "LoginURL" to allow it.

Login flows are useful for 3rd party applications so that if such an application wants to
use OpenShift authentication, the user does not have to give out their password to
the application but instead:
1. is redirected to an instance of the OpenShift oauth-server the user - and, more
   importantly, the administrator of the cluster - trusts
2. the user enters their credentials to the oauth-server's login form and optionally
   agrees to permissions the issued access token should provide to the 3rd party
   application
3. the user is redirected back to the 3rd party application with an authorization token
4. the 3rd party application can use the authorization token in order to get an access
   token so that it can act on behalf of the authenticated user.

During this flow, multiple checks are being performed:
1. the oauth-server checks that the scopes requested are within what the oauthclient
   representing the 3rd party application contains in its "ScopeRestrictions" field
2. the oauth-server checks whether the redirection URI can be found among the redirection
   URIs set in the "redirectURIs"  field of the oauthclient used for the flow
3. once the 3rd application obtains its authorization token, it performs client\_id/client\_secret
   authentication in order to retrieve the access token. The presented client\_id and client\_secret
   correspond to the name of an existing oauthclient object and the value of its "Secret"
   field respectively.

The simplest case of login flow is using a web-browser to login to OpenShift from the
oauth-server login form. The same process as for any 3rd-party application is applied.
Note that some identity providers only allow login flows to prevent the user of directly
having to pass their password to the oauth-serveri (more on that in
[Authenticating to the External Identity Providers](#authenticating-to-the-external-identity-providers)
section).

### External Identity Providers
The OpenShift OAuth2 Server needs a source of identities so that it can authenticate users to
the cluster, it alone does serve as an identity management solution.

There's currently 9 available types of identity providers that can be configured:
```golang
    // IdentityProviderTypeBasicAuth provides identities for users authenticating with HTTP Basic Auth
    IdentityProviderTypeBasicAuth IdentityProviderType = "BasicAuth"

    // IdentityProviderTypeGitHub provides identities for users authenticating using GitHub credentials
    IdentityProviderTypeGitHub IdentityProviderType = "GitHub"

    // IdentityProviderTypeGitLab provides identities for users authenticating using GitLab credentials
    IdentityProviderTypeGitLab IdentityProviderType = "GitLab"

    // IdentityProviderTypeGoogle provides identities for users authenticating using Google credentials
    IdentityProviderTypeGoogle IdentityProviderType = "Google"

    // IdentityProviderTypeHTPasswd provides identities from an HTPasswd file
    IdentityProviderTypeHTPasswd IdentityProviderType = "HTPasswd"

    // IdentityProviderTypeKeystone provides identitities for users authenticating using keystone password credentials
    IdentityProviderTypeKeystone IdentityProviderType = "Keystone"

    // IdentityProviderTypeLDAP provides identities for users authenticating using LDAP credentials
    IdentityProviderTypeLDAP IdentityProviderType = "LDAP"

    // IdentityProviderTypeOpenID provides identities for users authenticating using OpenID credentials
    IdentityProviderTypeOpenID IdentityProviderType = "OpenID"

    // IdentityProviderTypeRequestHeader provides identities for users authenticating using request header credentials
    IdentityProviderTypeRequestHeader IdentityProviderType = "RequestHeader"
```

#### Request Header Identity Provider
The `RequestHeader` identity provider is special as it allows the use of any other
authentication mechanism (like SAML or GSSAPI) by offloading authentication
to a login proxy that's capable of handling that kind of a mechanism and, after
successful authentication, set a user-defined header to a client-certificate-authenticated
request that is sent back to the OpenShift OAuth server.

#### KubeAdmin
KubeAdmin can be considered an identity provider of a single user called `kubeadmin`
It's been coined out during the development of 4.1 so that there exists a "demo" user.

KubeAdmin identity provider:
- acts as SSO
  - the oauth-server always keeps its session so that it's possible to demo
    different applications (like prometheus, grafana) throughout the cluster
    without having to relogin
- has credentials generated in the installer during the installation
  - the password of the user is stored in `$INSTALL_DIR/auth/kubeadmin-password`
  - a bcrypt hash of the password is stored in the `kubeadmin` secret in the `kube-system`
    NS, this secret is used by the oauth-server to validate the user's credentials during
    login
- cannot be brought back once disabled
  - once the password-hash secret is removed from the cluster, there is no way of getting
    the user back
  - this is true with the exception when the secret gets recreated within 1st hour of the
    life of the cluster to allow configuring the IdP for testing
- has restrictions on the minimal password length
  - the password for the user of this IdP  MUST be at least 23 characters long (forces
    structure 5char-5char-5char-5char)
- provides unrestricted access to the cluster
  - the single user of this IdP can perform any action in the cluster, it gets the
    "system:cluster-admins" group upon successful authentication
- unlike "system:admin", it allows simple login via web console, making it easier to
  configure the first identity provider for the cluster for people only used to manage
  the cluster using the web UI

Upon successful login, the user appears as `kube:admin` in authorization checks, this further
prevents the danger of it being impersonated by a user of a different identity provider.

Since the KubeAdmin identity provider allows highly-privileged access to the cluster, it's
not supposed to be used in production clusters and should be removed after installation,
possibly after the setup of the first "real" identity provider.

### Authenticating to the External Identity Providers
Different identity providers require different approaches when trying to get authentication
details of a user from them.

To allow command-line login with `oc`, the identity provider must provide an authentication
path that allows using username/password combination, or it must at least be capable to
function as required by [Request Header Identity Provider](#request-header-identity-provider).

If there is a known username/password authentication path, challenge-based flows are
enabled in the oauth-server for the identity provider by the openshift-authentication-operator,
which effectively means the **oauth-server issues basic authentication `WWW-Authenticate` challenges
and forwards the retrieved credentials to the identity provider.**

Some identity providers require browser-based authentication only. This is typical for OIDC
as browser-based login makes it possible for the user not to pass their password to other
parties (like OpenShift oauth-server in this case), but to authenticate the user against
themselves and then pass an authorization token to a client that can then use this authorization
token to retrieve information about the user from the OIDC provider. This way, as well as
configuring login redirection with Request Header identity provider, it is possible to
**avoid from having the oauth-server directly handle a user password.**

When a user authentication succeeds, the following objects are created:
- `Identity`
- `User` (unless `lookup` identity mapping method is used)
- `OAuthAccessToken`

Web-browser login also generates `OAuthAuthorizeToken` which is used for retrieving
an `OAuthAccessToken`, and the authorization token is removed right after the access
token gets issued.

#### User
`User` objects represent the users of the system, can be used in RoleBindings etc.:
```golang
// Upon log in, every user of the system receives a User and Identity resource. Administrators
// may directly manipulate the attributes of the users for their own tracking, or set groups
// via the API. The user name is unique and is chosen based on the value provided by the
// identity provider - if a user already exists with the incoming name, the user name may have
// a number appended to it depending on the configuration of the system.
type User struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

    // FullName is the full name of user
    FullName string `json:"fullName,omitempty" protobuf:"bytes,2,opt,name=fullName"`

    // Identities are the identities associated with this user
    Identities []string `json:"identities" protobuf:"bytes,3,rep,name=identities"`

    // Groups specifies group names this user is a member of.
    // This field is deprecated and will be removed in a future release.
    // Instead, create a Group object containing the name of this User.
    Groups []string `json:"groups" protobuf:"bytes,4,rep,name=groups"`
}
```

#### Identity
`Identity` objects describe from which identity provider a `User` object comes from:
```golang
// Identity records a successful authentication of a user with an identity provider. The
// information about the source of authentication is stored on the identity, and the identity
// is then associated with a single user object. Multiple identities can reference a single
// user. Information retrieved from the authentication provider is stored in the extra field
// using a schema determined by the provider.
type Identity struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

    // ProviderName is the source of identity information
    ProviderName string `json:"providerName" protobuf:"bytes,2,opt,name=providerName"`

    // ProviderUserName uniquely represents this identity in the scope of the provider
    ProviderUserName string `json:"providerUserName" protobuf:"bytes,3,opt,name=providerUserName"`

    // User is a reference to the user this identity is associated with
    // Both Name and UID must be set
    User corev1.ObjectReference `json:"user" protobuf:"bytes,4,opt,name=user"`

    // Extra holds extra information about this identity
    Extra map[string]string `json:"extra,omitempty" protobuf:"bytes,5,rep,name=extra"`
}
```

Usually, a single `Identity` object is tied to each `User` object, but the `mappingMethod`
configuration field for each identity provider allows for a `1 User : N Identities` kind
of relation (mapping methods are described clearly in the [docs](https://docs.openshift.com/container-platform/latest/authentication/understanding-identity-provider.html#identity-provider-parameters_understanding-identity-provider)).

The `Extra` field can be used to store a preferred username, name to be displayed in the web console,
or the user's email.

The main reason for the existence of identities is the ability to handle authentication
of users that share the same username but come from different identity providers. This can
be disabled - `lookup` and `claim` identity mappings - only allow 1:1 user:IdP mapping, or
handled in two distinguished ways:
- `generate` - users with clashing usernames will appear as separate `User` objects
- `add`      - users with clashing usernames are mapped to the same `User` object

In both the cases, the user uses the username from the identity provider to login, but since they
may appear as different `User` objects, handling of policies, like RBAC, might be different.

#### OAuthAccessToken
`OAuthAccessToken` is a token that allows an entity to act on behalf of an end-user:
```golang
// OAuthAccessToken describes an OAuth access token
type OAuthAccessToken struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

    // ClientName references the client that created this token.
    ClientName string `json:"clientName,omitempty" protobuf:"bytes,2,opt,name=clientName"`

    // ExpiresIn is the seconds from CreationTime before this token expires.
    ExpiresIn int64 `json:"expiresIn,omitempty" protobuf:"varint,3,opt,name=expiresIn"`

    // Scopes is an array of the requested scopes.
    Scopes []string `json:"scopes,omitempty" protobuf:"bytes,4,rep,name=scopes"`

    // RedirectURI is the redirection associated with the token.
    RedirectURI string `json:"redirectURI,omitempty" protobuf:"bytes,5,opt,name=redirectURI"`

    // UserName is the user name associated with this token
    UserName string `json:"userName,omitempty" protobuf:"bytes,6,opt,name=userName"`

    // UserUID is the unique UID associated with this token
    UserUID string `json:"userUID,omitempty" protobuf:"bytes,7,opt,name=userUID"`

    // AuthorizeToken contains the token that authorized this token
    AuthorizeToken string `json:"authorizeToken,omitempty" protobuf:"bytes,8,opt,name=authorizeToken"`

    // RefreshToken is the value by which this token can be renewed. Can be blank.
    RefreshToken string `json:"refreshToken,omitempty" protobuf:"bytes,9,opt,name=refreshToken"`

    // InactivityTimeoutSeconds is the value in seconds, from the
    // CreationTimestamp, after which this token can no longer be used.
    // The value is automatically incremented when the token is used.
    InactivityTimeoutSeconds int32 `json:"inactivityTimeoutSeconds,omitempty" protobuf:"varint,10,opt,name=inactivityTimeoutSeconds"`
}
```

The name of the token acts as the bearer token for authenticated requests against
OpenShift-authentication protected endpoints. In the context of oauth-server, the token
gets generated with a random, base64-encodedi, 43-bytes-long name. Generally, the name
can be arbitrary.

Both an `OAuthAccessToken` and a `User` object need to exist and have correct references
in order for the token to be considered valid (along with other requirements, like expiration).

##### Token Scopes
The actions an entity can do with an access token are restricted both by the RBAC for the user
the token represents, but also the scopes contained in that access token (the scopes may reduce
the set of policy rules allowed by RBAC).

Scoping tokens is described in the [docs](https://docs.openshift.com/container-platform/latest/authentication/tokens-scoping.html).

### Using Service Accounts as OAuth Clients
An application that wants to use OpenShift authentication needs a way to authenticate
itself to OpenShift as a part of the authorization code OAuth2 grant. Usually, this is
done by creating an `OAuthClient` object with its `Secret` field populated and proper
redirect URIs set.

Since creating an `OAuthClient` object is quite a privileged action, for the mere use
of OpenShift authentication, it is also possible to use `ServiceAccounts` as OAuth2
clients by specifying annotation as described in [docs](https://docs.openshift.com/container-platform/4.4/authentication/using-service-accounts-as-oauth-client.html).

The capabilities of `ServiceAccounts` when used as OAuth2 clients are restricted
to `user:info`, `user:check-access` scopes, or, in case of role scopes, to scopes
that only allow role access in the namespace of the service account.

## Patching the Kubernetes API Server
Kubernetes API server requires most requests against the API to be authenticated. This
is done by nesting golang HTTP handlers into several layers so that each layer attempts
to perform a certain kind of authentication (for example request-header, client-cert,
basic and token authentication each get one authenticators layer). There was a
[deep-dive talk](https://www.youtube.com/watch?v=-2xcNjKLU9E) on how Kubernetes authenticators
and authorizers work at KubeCon EU 2019.

In order to be able to use the OpenShift-minted access tokens against the Kubernetes
API, there are a couple of patches in Kubernetes API server token authenticators that
add `OAuthAccessToken` retrieval and validation.

### OpenShift Token Authenticator
- validation - user UID, expiration, token inactivity
- authorization - scopeauthorizer
### NewBootstrapAuthenticator

## Analysing `oc login`

## OAuth-proxy

## API
##TODO: describe oauthaccess/authorizetokens, oauthaccessclients, identity and user/group objects with
references to the previous text
