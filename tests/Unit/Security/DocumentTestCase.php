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
use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigResolver;
use CORS\Bundle\DocumentAuthBundle\Config\DocumentPropertyAuthConfigProvider;
use CORS\Bundle\DocumentAuthBundle\Security\UserProvider;
use PHPUnit\Framework\TestCase;
use Pimcore\Http\Request\Resolver\DocumentResolver;
use Pimcore\Model\Document\Page;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Stubs for the document resolved from the request, its (inherited) properties and the config
 * providers.
 */
abstract class DocumentTestCase extends TestCase
{
    /**
     * @param array<string, mixed> $properties
     */
    protected function createDocument(array $properties): Page
    {
        $document = $this->createStub(Page::class);
        $document->method('getProperty')->willReturnCallback(
            static fn (string $name): mixed => $properties[$name] ?? null,
        );

        return $document;
    }

    /**
     * @param array<string, mixed> $properties
     */
    protected function createProtectedDocument(
        string $username = 'max',
        string $password = 'secret',
        array $properties = [],
    ): Page {
        return $this->createDocument($properties + [
            'password_enabled' => true,
            'password_username' => $username,
            'password_password' => $password,
        ]);
    }

    protected function createResolver(?Page $document): DocumentResolver
    {
        $resolver = $this->createStub(DocumentResolver::class);
        $resolver->method('getDocument')->willReturn($document);

        return $resolver;
    }

    /**
     * Resolver with the extra providers first and the document properties as default source.
     */
    protected function createConfigResolver(?Page $document, AuthConfigProviderInterface ...$providers): AuthConfigResolver
    {
        return new AuthConfigResolver([
            ...$providers,
            new DocumentPropertyAuthConfigProvider($this->createResolver($document)),
        ]);
    }

    protected function createUserProvider(AuthConfigResolver $configResolver, ?Request $request = null): UserProvider
    {
        $requestStack = new RequestStack();
        $requestStack->push($request ?? Request::create('/protected'));

        return new UserProvider($configResolver, $requestStack, 'kernel-secret');
    }

    protected function createFixedProvider(?AuthConfig $config): AuthConfigProviderInterface
    {
        return new readonly class($config) implements AuthConfigProviderInterface {
            public function __construct(
                private ?AuthConfig $config,
            ) {
            }

            public function getConfig(Request $request): ?AuthConfig
            {
                return $this->config;
            }
        };
    }
}
