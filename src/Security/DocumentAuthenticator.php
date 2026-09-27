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

namespace CORS\Bundle\DocumentAuthBundle\Security;

use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigResolver;
use Pimcore\Http\Request\Resolver\DocumentResolver;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Twig\Environment;

/**
 * Authenticates requests to protected documents, either with HTTP basic auth (mode "basic")
 * or with a login form rendered on the document URL itself (mode "form"). The form mode does
 * not touch the Authorization header, so a basic auth in front of the application (e.g. on a
 * load balancer) keeps working.
 *
 * Mode and login form template are configured with cors_document_auth.mode and
 * cors_document_auth.form.template and can be overridden by the AuthConfig of the request (e.g. the
 * document properties "password_mode" and "password_template").
 */
final class DocumentAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public const string MODE_BASIC = 'basic';

    public const string MODE_FORM = 'form';

    public const string CSRF_TOKEN_ID = 'cors_document_auth';

    private const string FORM_MARKER = '_document_auth';

    public function __construct(
        private readonly UserProvider $userProvider,
        private readonly AuthConfigResolver $configResolver,
        private readonly DocumentResolver $documentResolver,
        private readonly Environment $twig,
        private readonly ?CsrfTokenManagerInterface $csrfTokenManager,
        private readonly string $defaultMode,
        private readonly string $realm,
        private readonly string $template,
        private readonly bool $csrfProtection,
    ) {
    }

    public function supports(Request $request): bool
    {
        if ($this->isFormMode($request)) {
            return $request->isMethod('POST') && $request->request->has(self::FORM_MARKER);
        }

        return $request->headers->has('PHP_AUTH_USER');
    }

    public function authenticate(Request $request): Passport
    {
        $badges = [];

        if ($this->isFormMode($request)) {
            $username = $request->request->getString('_username');
            $password = $request->request->getString('_password');

            if ($this->isCsrfEnabled()) {
                $badges[] = new CsrfTokenBadge(self::CSRF_TOKEN_ID, $request->request->getString('_csrf_token'));
            }
        } else {
            $username = (string) $request->headers->get('PHP_AUTH_USER');
            $password = (string) $request->headers->get('PHP_AUTH_PW');
        }

        return new Passport(
            new UserBadge($username, $this->userProvider->loadUserByIdentifier(...)),
            new PasswordCredentials($password),
            $badges,
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if (!$this->isFormMode($request)) {
            return null;
        }

        // Post/Redirect/Get back to the document itself
        $response = new RedirectResponse($request->getUri(), Response::HTTP_SEE_OTHER);
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->start($request, $exception);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        if (!$this->isFormMode($request)) {
            $response = new Response('', Response::HTTP_UNAUTHORIZED);
            $response->headers->set('WWW-Authenticate', sprintf('Basic realm="%s"', $this->realm));

            return $response;
        }

        // Only show an error for a failed login attempt, not for the initial access
        $error = $this->supports($request) ? $authException : null;

        $content = $this->twig->render($this->resolveTemplate($request), [
            'document' => $this->documentResolver->getDocument($request),
            'error' => $error,
            'last_username' => $error ? $request->request->getString('_username') : '',
            'csrf_token' => $this->isCsrfEnabled()
                ? $this->csrfTokenManager?->getToken(self::CSRF_TOKEN_ID)->getValue()
                : null,
            'form_marker' => self::FORM_MARKER,
            'action' => $request->getRequestUri(),
        ]);

        $response = new Response($content, Response::HTTP_UNAUTHORIZED);
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('X-Robots-Tag', 'noindex, nofollow');

        return $response;
    }

    private function isFormMode(Request $request): bool
    {
        $mode = $this->configResolver->resolve($request)?->mode;

        if (!in_array($mode, [self::MODE_BASIC, self::MODE_FORM], true)) {
            $mode = $this->defaultMode;
        }

        return self::MODE_FORM === $mode;
    }

    private function resolveTemplate(Request $request): string
    {
        $template = $this->configResolver->resolve($request)?->template;

        if (null !== $template && $this->twig->getLoader()->exists($template)) {
            return $template;
        }

        return $this->template;
    }

    private function isCsrfEnabled(): bool
    {
        return $this->csrfProtection && null !== $this->csrfTokenManager;
    }
}
