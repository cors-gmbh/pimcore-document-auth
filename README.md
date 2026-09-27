CORS Document Auth
--------

> This bundle is released under the [MIT license](LICENSE.md).
> The 2026.x line supports Pimcore 2026 only. For Pimcore 10–12 use the `12.x` branch.

This bundle protects Pimcore documents with a username and password based on document properties,
either with HTTP basic auth (default) or with a login form.

Set these properties on a document. The bundle ships them as predefined properties ("Document
Auth: …"), so they can be picked in the properties tab of Pimcore Studio:

 - **password_enabled** Checkbox: enables or disables the password
 - **password_username** Text: username
 - **password_password** Text: password as raw text
 - **password_mode** Text (optional): `basic` or `form`, overrides the configured default mode (see [Login Mode](#login-mode))
 - **password_template** Text (optional): Twig template of the login form, overrides the configured template (see [Login Template](#login-template))

Requests from Pimcore Studio (edit mode, preview) are not protected.

## Requirements

 - PHP 8.4 or 8.5
 - Pimcore ^2026.2

## Installation

1. Install the bundle: ```composer require cors/document-auth```
2. Enable the bundle: ```bin/console pimcore:bundle:enable CORSDocumentAuthBundle```
3. Add the security config below to your project's security config

## Security Config
```yaml
security:
    providers:
        document_auth_provider:
            id: CORS\Bundle\DocumentAuthBundle\Security\UserProvider

    firewalls:
        # after the Pimcore Studio firewall
        document_auth:
            request_matcher: CORS\Bundle\DocumentAuthBundle\Security\RequestMatcher
            provider: document_auth_provider
            custom_authenticators:
                - CORS\Bundle\DocumentAuthBundle\Security\DocumentAuthenticator

    access_control:
        # as the last entry
        - { path: ^/, roles: ROLE_USER, attributes: { '_firewall_context': 'document_auth' } }
```

The bundle registers the password hasher for its users itself, a `password_hashers` entry is not
needed.

A login grants access to all documents with the same username and password. Documents with other
credentials ask for a new login, and changing the credentials of a document ends existing logins.

## Login Mode
```yaml
cors_document_auth:
    # "basic" (default): HTTP basic auth, the browser shows its login dialog
    # "form": a login form is rendered on the protected document URL itself
    mode: form
    realm: Site                     # basic auth realm (mode "basic")
    form:
        template: '@CORSDocumentAuth/login.html.twig'
        csrf_protection: true       # needs framework.csrf_protection
```

Use `form` when the application sits behind another HTTP basic auth (e.g. on a load balancer or
reverse proxy of a staging system): both would need the `Authorization` header, which the browser
can only fill with one set of credentials. In `form` mode the login is kept in the session and the
`Authorization` header stays untouched.

The mode can be set per environment, e.g. with a `when@staging:` block, and per document with the
property `password_mode` (`basic` or `form`, inheritable like the other properties). Other values
fall back to the configured mode.

## Login Template

The login form (mode `form`) is rendered with, in this order of precedence:

1. the template in the document property `password_template` (inheritable), if it exists
2. `cors_document_auth.form.template`
3. `@CORSDocumentAuth/login.html.twig`, which can also be overridden in
   `templates/bundles/CORSDocumentAuthBundle/login.html.twig`

For a customer CI, extend the default template and override only what differs. Colors, font and
radius are CSS custom properties:

```twig
{% extends '@CORSDocumentAuth/login.html.twig' %}

{% block theme %}
    :root {
        --document-auth-primary: #e30613;
        --document-auth-background: #1d1d1b;
        --document-auth-font: "Inter", sans-serif;
        --document-auth-radius: 0;
    }
{% endblock %}

{% block head %}
    <link rel="stylesheet" href="{{ asset('build/app.css') }}">
{% endblock %}

{% block logo %}
    <img class="document-auth__logo" src="/static/logo.svg" alt="Customer">
{% endblock %}
```

Available blocks: `title`, `stylesheets`, `theme`, `head`, `body_attributes`, `body`, `logo`,
`heading`, `error`, `fields`, `hidden_fields`, `submit`, `footer`. Custom properties:
`--document-auth-primary`, `-primary-text`, `-background`, `-surface`, `-text`, `-border`,
`-error-background`, `-error-text`, `-radius`, `-font`.

A completely own template receives `document`, `error`, `last_username`, `csrf_token`,
`form_marker` and `action`. The form must post `_username`, `_password`, `_csrf_token` and a
field named after `form_marker` to `action`. Texts use the translation domain `cors_document_auth`.

Protect the login against brute force with Symfony's
[login throttling](https://symfony.com/doc/current/security.html#limiting-login-attempts)
(`login_throttling` on the `document_auth` firewall, requires `symfony/rate-limiter`).

### Upgrading from the `http_basic` config

The previous firewall config with `http_basic` and the `InMemoryUser` password hasher keeps
working. Switching to `custom_authenticators` as shown above enables the `mode` option. Existing
sessions of the old config require a new login once.

## Development

The repository doubles as a runnable Pimcore application on **Pimcore 2026 with Studio** (the
CORS bundle template: `Kernel.php`, `bin/console`, `config/`, `dev/`, `docker-compose.yaml`
including the shared `dev-compose` stack). The bundle itself is `src/`; everything else at the
repository root only serves the dev harness or the CI, and `.gitattributes` keeps it out of the
distributed composer package.

```bash
docker compose up -d
docker compose exec -T php composer install
docker compose exec -T php vendor/bin/pimcore-install \
    --install-profile='App\InstallProfile\StudioInstallProfile' \
    --admin-username=admin --admin-password=admin --no-interaction
```

Studio is then served at `https://cors-pimcore-document-auth.dev.localhost/pimcore-studio/`.
`config/packages/security.yaml` already contains the `document_auth` firewall, so any document
with the properties above is protected in the harness.

Pimcore 2026 refuses to boot without a registered instance: the instance identifier
(`cors-pimcore-document-auth`) is committed in `config/license.yaml`, and
`PIMCORE_ENCRYPTION_SECRET` plus `PIMCORE_PRODUCT_KEY` go into your uncommitted `.env.local`.
CI reads the same values from the repository secrets `PIMCORE_ENCRYPTION_SECRET`,
`PIMCORE_INSTANCE_IDENTIFIER` and `PIMCORE_PRODUCT_KEY` (`.github/workflows/static.yaml`).

Static checks run the same way as in CI. This repository is public, so the shared rule set comes
from the public `coreshop/test-setup` package instead of the private `cors/dev`:

```bash
vendor/bin/ecs check src tests
vendor/bin/phpstan analyse
vendor/bin/psalm
```

Tests: the unit tests run without Pimcore. The functional tests send requests through Pimcore
routing, the `document_auth` firewall and the session of the installed dev harness (they create
and delete their own documents) and only run with `PIMCORE_FUNCTIONAL=1`:

```bash
docker compose exec php vendor/bin/phpunit --testsuite unit
docker compose exec -e PIMCORE_FUNCTIONAL=1 php vendor/bin/phpunit
```

## License

[MIT](https://opensource.org/license/mit), see [LICENSE.md](LICENSE.md).
