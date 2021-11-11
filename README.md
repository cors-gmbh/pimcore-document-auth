CORS Property Basic Auth
--------

This bundles allows to add basic auth based on Properties on Pimcore Documents.

Simply use these properties

 - **password_enabled** Checkbox: Enable and disable the password
 - **password_username** Text: Username
 - **password_password** Text: Password as RAW Text

## Installation

1. Install Bundle ```composer require cors/document-auth```
2. Enable Bundle ```bin/console pimcore:bundle:enable CORSDocumentAuthBundle```
3. Copy Security config into the security config


## Security Config
```yaml
security:
    encoders:
        Symfony\Component\Security\Core\User\User: 'auto'

    providers:
        document_auth_provider:
            id: CORS\Bundle\DocumentAuthBundle\Security\UserProvider

    firewalls:
        document_auth:
            request_matcher: CORS\Bundle\DocumentAuthBundle\Security\RequestMatcher
            http_basic:
                realm: Site
                provider: document_auth_provider
```
