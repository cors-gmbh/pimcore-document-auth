<?php

declare(strict_types=1);

/*
 * CORS GmbH
 *
 * This source file is available under the MIT license
 *
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) CORS GmbH (https://www.cors.gmbh)
 * @license    https://opensource.org/license/mit MIT
 */

namespace CORS\Bundle\DocumentAuthBundle\Tests\Unit\Security;

use CORS\Bundle\DocumentAuthBundle\Config\AuthConfig;
use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigProviderInterface;
use CORS\Bundle\DocumentAuthBundle\Security\DocumentAuthenticator;
use CORS\Bundle\DocumentAuthBundle\Security\DocumentUser;
use PHPUnit\Framework\Attributes\DataProvider;
use Pimcore\Model\Document\Page;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

final class DocumentAuthenticatorTest extends DocumentTestCase
{
    private const string TEMPLATE = '{{ template }}|{{ error ? error.messageKey : "" }}|{{ last_username }}|{{ csrf_token }}|{{ form_marker }}|{{ action }}';

    /**
     * @return iterable<string, array{string, array<string, mixed>, string}>
     */
    public static function modes(): iterable
    {
        yield 'configured basic' => [DocumentAuthenticator::MODE_BASIC, [], DocumentAuthenticator::MODE_BASIC];
        yield 'configured form' => [DocumentAuthenticator::MODE_FORM, [], DocumentAuthenticator::MODE_FORM];
        yield 'property form overrides basic' => [DocumentAuthenticator::MODE_BASIC, ['password_mode' => 'form'], DocumentAuthenticator::MODE_FORM];
        yield 'property basic overrides form' => [DocumentAuthenticator::MODE_FORM, ['password_mode' => 'basic'], DocumentAuthenticator::MODE_BASIC];
        yield 'invalid property falls back' => [DocumentAuthenticator::MODE_FORM, ['password_mode' => 'popup'], DocumentAuthenticator::MODE_FORM];
    }

    /**
     * @param array<string, mixed> $properties
     */
    #[DataProvider('modes')]
    public function testModeIsResolvedFromConfigAndDocumentProperty(
        string $defaultMode,
        array $properties,
        string $expectedMode,
    ): void {
        $response = $this->createAuthenticator($this->createProtectedDocument(properties: $properties), $defaultMode)
            ->start(Request::create('/protected'))
        ;

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame(
            DocumentAuthenticator::MODE_BASIC === $expectedMode,
            $response->headers->has('WWW-Authenticate'),
        );
    }

    public function testBasicModeSupportsRequestsWithBasicAuthHeader(): void
    {
        $authenticator = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_BASIC);

        self::assertTrue($authenticator->supports($this->createBasicAuthRequest('max', 'secret')));
        self::assertFalse($authenticator->supports(Request::create('/protected')));
        self::assertFalse($authenticator->supports($this->createLoginRequest('max', 'secret')));
    }

    public function testFormModeIgnoresBasicAuthHeaderOfLoadBalancer(): void
    {
        $authenticator = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM);

        self::assertFalse($authenticator->supports($this->createBasicAuthRequest('lb', 'lb-password')));
        self::assertFalse($authenticator->supports(Request::create('/protected')));
        self::assertFalse($authenticator->supports(Request::create('/protected', 'POST', ['_username' => 'max'])));
        self::assertTrue($authenticator->supports($this->createLoginRequest('max', 'secret')));
    }

    public function testBasicModeCreatesPassportFromHeader(): void
    {
        $passport = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_BASIC)
            ->authenticate($this->createBasicAuthRequest('max', 'secret'))
        ;

        self::assertSame('max', $passport->getBadge(UserBadge::class)?->getUserIdentifier());
        self::assertSame('max', $passport->getUser()->getUserIdentifier());
        self::assertSame('secret', $passport->getBadge(PasswordCredentials::class)?->getPassword());
        self::assertFalse($passport->hasBadge(CsrfTokenBadge::class));
    }

    public function testFormModeCreatesPassportWithCsrfBadge(): void
    {
        $passport = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM)
            ->authenticate($this->createLoginRequest('max', 'secret', 'csrf-value'))
        ;

        self::assertSame('max', $passport->getBadge(UserBadge::class)?->getUserIdentifier());
        self::assertSame('secret', $passport->getBadge(PasswordCredentials::class)?->getPassword());

        $csrfBadge = $passport->getBadge(CsrfTokenBadge::class);
        self::assertInstanceOf(CsrfTokenBadge::class, $csrfBadge);
        self::assertSame(DocumentAuthenticator::CSRF_TOKEN_ID, $csrfBadge->getCsrfTokenId());
        self::assertSame('csrf-value', $csrfBadge->getCsrfToken());
    }

    public function testFormModeSkipsCsrfWhenDisabled(): void
    {
        $passport = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM, csrfProtection: false)
            ->authenticate($this->createLoginRequest('max', 'secret'))
        ;

        self::assertFalse($passport->hasBadge(CsrfTokenBadge::class));
    }

    public function testFormModeSkipsCsrfWithoutTokenManager(): void
    {
        $passport = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM, withCsrfManager: false)
            ->authenticate($this->createLoginRequest('max', 'secret'))
        ;

        self::assertFalse($passport->hasBadge(CsrfTokenBadge::class));
    }

    public function testBasicChallengeUsesConfiguredRealm(): void
    {
        $response = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_BASIC)
            ->start(Request::create('/protected'))
        ;

        self::assertSame('Basic realm="Intranet"', $response->headers->get('WWW-Authenticate'));
    }

    public function testFormRendersLoginWithoutErrorOnFirstAccess(): void
    {
        $response = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM)
            ->start(Request::create('/protected?page=2'), new BadCredentialsException())
        ;

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('default.html.twig|||csrf-token|_document_auth|/protected?page=2', $response->getContent());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertTrue($response->headers->hasCacheControlDirective('private'));
        self::assertSame('noindex, nofollow', $response->headers->get('X-Robots-Tag'));
    }

    public function testFormRendersErrorAndLastUsernameAfterFailedLogin(): void
    {
        $response = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM)
            ->onAuthenticationFailure($this->createLoginRequest('max', 'wrong'), new BadCredentialsException())
        ;

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('default.html.twig|Invalid credentials.|max|csrf-token|_document_auth|/protected', $response->getContent());
    }

    public function testFormRendersTemplateOfDocumentProperty(): void
    {
        $document = $this->createProtectedDocument(properties: ['password_template' => 'customer.html.twig']);

        $response = $this->createAuthenticator($document, DocumentAuthenticator::MODE_FORM)
            ->start(Request::create('/protected'))
        ;

        self::assertStringStartsWith('customer.html.twig|', (string) $response->getContent());
    }

    public function testFormFallsBackToConfiguredTemplateForUnknownTemplate(): void
    {
        $document = $this->createProtectedDocument(properties: ['password_template' => 'missing.html.twig']);

        $response = $this->createAuthenticator($document, DocumentAuthenticator::MODE_FORM)
            ->start(Request::create('/protected'))
        ;

        self::assertStringStartsWith('default.html.twig|', (string) $response->getContent());
    }

    public function testFormRedirectsBackToDocumentAfterLogin(): void
    {
        $response = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_FORM)
            ->onAuthenticationSuccess(
                $this->createLoginRequest('max', 'secret', uri: 'https://example.com/protected?page=2'),
                $this->createStub(TokenInterface::class),
                'document_auth',
            )
        ;

        self::assertNotNull($response);
        self::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode());
        self::assertSame('https://example.com/protected?page=2', $response->headers->get('Location'));
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    public function testBasicContinuesRequestAfterLogin(): void
    {
        $response = $this->createAuthenticator($this->createProtectedDocument(), DocumentAuthenticator::MODE_BASIC)
            ->onAuthenticationSuccess(
                $this->createBasicAuthRequest('max', 'secret'),
                $this->createStub(TokenInterface::class),
                'document_auth',
            )
        ;

        self::assertNull($response);
    }

    public function testModeAndTemplateComeFromCustomProvider(): void
    {
        $provider = $this->createFixedProvider(new AuthConfig('site', 'secret', mode: 'form', template: 'customer.html.twig'));

        $response = $this->createAuthenticator(null, DocumentAuthenticator::MODE_BASIC, providers: [$provider])
            ->start(Request::create('/site'))
        ;

        self::assertFalse($response->headers->has('WWW-Authenticate'));
        self::assertStringStartsWith('customer.html.twig|', (string) $response->getContent());
    }

    public function testCustomProviderPassportLoadsUserOfProvider(): void
    {
        $hash = password_hash('secret', \PASSWORD_BCRYPT);
        $provider = $this->createFixedProvider(new AuthConfig('site', $hash, true));
        $request = $this->createBasicAuthRequest('site', 'secret');

        $passport = $this->createAuthenticator(null, DocumentAuthenticator::MODE_BASIC, providers: [$provider], request: $request)
            ->authenticate($request)
        ;

        $user = $passport->getUser();
        self::assertInstanceOf(DocumentUser::class, $user);
        self::assertSame(DocumentUser::PASSWORD_HASHER_HASHED, $user->getPasswordHasherName());
    }

    /**
     * @param list<AuthConfigProviderInterface> $providers
     */
    private function createAuthenticator(
        ?Page $document,
        string $mode,
        bool $csrfProtection = true,
        bool $withCsrfManager = true,
        array $providers = [],
        ?Request $request = null,
    ): DocumentAuthenticator {
        $resolver = $this->createResolver($document);
        $configResolver = $this->createConfigResolver($document, ...$providers);

        $csrfManager = null;
        if ($withCsrfManager) {
            $csrfManager = $this->createStub(CsrfTokenManagerInterface::class);
            $csrfManager->method('getToken')->willReturn(new CsrfToken(DocumentAuthenticator::CSRF_TOKEN_ID, 'csrf-token'));
        }

        $twig = new Environment(new ArrayLoader([
            'default.html.twig' => '{% set template = "default.html.twig" %}' . self::TEMPLATE,
            'customer.html.twig' => '{% set template = "customer.html.twig" %}' . self::TEMPLATE,
        ]));

        return new DocumentAuthenticator(
            $this->createUserProvider($configResolver, $request),
            $configResolver,
            $resolver,
            $twig,
            $csrfManager,
            $mode,
            'Intranet',
            'default.html.twig',
            $csrfProtection,
        );
    }

    private function createBasicAuthRequest(string $username, string $password): Request
    {
        return Request::create('/protected', server: ['PHP_AUTH_USER' => $username, 'PHP_AUTH_PW' => $password]);
    }

    private function createLoginRequest(
        string $username,
        string $password,
        string $csrfToken = 'csrf-token',
        string $uri = '/protected',
    ): Request {
        return Request::create($uri, 'POST', [
            '_username' => $username,
            '_password' => $password,
            '_csrf_token' => $csrfToken,
            '_document_auth' => '1',
        ]);
    }
}
