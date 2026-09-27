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

namespace CORS\Bundle\DocumentAuthBundle\Tests\Unit\Resources;

use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Twig\Extension\TranslationExtension;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;

final class LoginTemplateTest extends TestCase
{
    private const string TEMPLATE = '@CORSDocumentAuth/login.html.twig';

    public function testRendersLoginForm(): void
    {
        $html = $this->render(self::TEMPLATE);

        self::assertStringContainsString('<form class="document-auth" method="post" action="/protected?page=2">', $html);
        self::assertStringContainsString('name="_username" value=""', $html);
        self::assertStringContainsString('name="_password"', $html);
        self::assertSame(1, substr_count($html, '<input type="hidden" name="_document_auth" value="1">'));
        self::assertSame(1, substr_count($html, '<input type="hidden" name="_csrf_token" value="csrf-token">'));
        self::assertStringNotContainsString('role="alert"', $html);
        self::assertStringEndsWith('</html>', trim($html));
    }

    public function testRendersErrorAndLastUsername(): void
    {
        $html = $this->render(self::TEMPLATE, ['error' => new BadCredentialsException(), 'last_username' => 'max']);

        self::assertStringContainsString('<div class="document-auth__error" role="alert">Invalid credentials.</div>', $html);
        self::assertStringContainsString('name="_username" value="max"', $html);
    }

    public function testOmitsCsrfFieldWithoutToken(): void
    {
        self::assertStringNotContainsString('_csrf_token', $this->render(self::TEMPLATE, ['csrf_token' => null]));
    }

    public function testCustomerTemplateCanOverrideThemeAndLogo(): void
    {
        $html = $this->render('customer.html.twig');

        self::assertStringContainsString('--document-auth-primary: #e30613;', $html);
        self::assertStringContainsString('<img class="document-auth__logo" src="/logo.svg" alt="Customer">', $html);
        self::assertSame(1, substr_count($html, 'name="_document_auth"'));
    }

    public function testCustomBodyKeepsHiddenFields(): void
    {
        $html = $this->render('custom-body.html.twig');

        self::assertStringContainsString('<main>', $html);
        self::assertSame(1, substr_count($html, 'name="_document_auth"'));
        self::assertSame(1, substr_count($html, 'name="_csrf_token"'));
    }

    /**
     * @param array<string, mixed> $context
     */
    private function render(string $template, array $context = []): string
    {
        $filesystemLoader = new FilesystemLoader();
        $filesystemLoader->addPath(dirname(__DIR__, 3) . '/src/Resources/views', 'CORSDocumentAuth');

        $twig = new Environment(new ChainLoader([
            $filesystemLoader,
            new ArrayLoader([
                'customer.html.twig' => <<<'TWIG'
                    {% extends '@CORSDocumentAuth/login.html.twig' %}
                    {% block theme %}:root { --document-auth-primary: #e30613; }{% endblock %}
                    {% block logo %}<img class="document-auth__logo" src="/logo.svg" alt="Customer">{% endblock %}
                    TWIG,
                'custom-body.html.twig' => <<<'TWIG'
                    {% extends '@CORSDocumentAuth/login.html.twig' %}
                    {% block body %}<main><form method="post" action="{{ action }}">{{ block('hidden_fields') }}</form></main>{% endblock %}
                    TWIG,
            ]),
        ]), ['strict_variables' => true]);
        $twig->addExtension(new TranslationExtension());
        $twig->addGlobal('app', ['request' => Request::create('/protected?page=2')]);

        return $twig->render($template, $context + [
            'document' => null,
            'error' => null,
            'last_username' => '',
            'csrf_token' => 'csrf-token',
            'form_marker' => '_document_auth',
            'action' => '/protected?page=2',
        ]);
    }
}
