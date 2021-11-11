CORS Property Basic Auth
--------

## Security Config
```yaml
security:
    encoders:
        Symfony\Component\Security\Core\User\User: 'auto'

    providers:
        document_auth_provider:
            id: CORS\Bundle\DocumentAuthBundle\Security\UserProvider

    firewalls:
        doucment_auth:
            request_matcher: CORS\Bundle\DocumentAuthBundle\Security\RequestMatcher
            http_basic:
                realm: Site
                provider: document_auth_provider
```
