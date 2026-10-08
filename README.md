[![CORS - One system. Down to the Core.](https://raw.githubusercontent.com/cors-gmbh/.github/refs/heads/main/cors-banner.jpg)](https://cors.gmbh)

CORS Document Auth
--------

> This bundle is released under the [MIT license](LICENSE.md).
> The 2026.x line supports Pimcore 2026 only. For Pimcore 10–12 use the `12.x` branch.

This bundle adds HTTP basic auth to Pimcore documents based on document properties.

Set these properties on a document:

 - **password_enabled** Checkbox: enables or disables the password
 - **password_username** Text: username
 - **password_password** Text: password as raw text

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
    password_hashers:
        Symfony\Component\Security\Core\User\InMemoryUser: 'auto'

    providers:
        document_auth_provider:
            id: CORS\Bundle\DocumentAuthBundle\Security\UserProvider

    firewalls:
        # after the Pimcore Studio firewall
        document_auth:
            request_matcher: CORS\Bundle\DocumentAuthBundle\Security\RequestMatcher
            http_basic:
                realm: Site
                provider: document_auth_provider

    access_control:
        # as the last entry
        - { path: ^/, roles: ROLE_USER, attributes: { '_firewall_context': 'document_auth' } }
```

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
vendor/bin/ecs check src
vendor/bin/phpstan analyse
vendor/bin/psalm
```

## License

[MIT](https://opensource.org/license/mit), see [LICENSE.md](LICENSE.md).
