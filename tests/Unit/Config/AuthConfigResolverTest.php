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

namespace CORS\Bundle\DocumentAuthBundle\Tests\Unit\Config;

use CORS\Bundle\DocumentAuthBundle\Config\AuthConfig;
use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigProviderInterface;
use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigResolver;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class AuthConfigResolverTest extends TestCase
{
    public function testFirstProviderWithConfigWins(): void
    {
        $site = new AuthConfig('site', 'secret');
        $document = new AuthConfig('document', 'secret');

        $resolver = new AuthConfigResolver([
            $this->createProvider(null),
            $this->createProvider($site),
            $this->createProvider($document),
        ]);

        self::assertSame($site, $resolver->resolve(Request::create('/')));
    }

    public function testReturnsNullWithoutResponsibleProvider(): void
    {
        $resolver = new AuthConfigResolver([$this->createProvider(null), $this->createProvider(null)]);

        self::assertNull($resolver->resolve(Request::create('/')));
    }

    public function testAsksProvidersOncePerRequest(): void
    {
        $provider = $this->createMock(AuthConfigProviderInterface::class);
        $provider->expects(self::exactly(2))->method('getConfig')->willReturn(null);

        $resolver = new AuthConfigResolver([$provider]);
        $request = Request::create('/');

        self::assertNull($resolver->resolve($request));
        self::assertNull($resolver->resolve($request));

        // A new request is resolved again
        self::assertNull($resolver->resolve(Request::create('/')));
    }

    public function testStopsAtFirstConfig(): void
    {
        $second = $this->createMock(AuthConfigProviderInterface::class);
        $second->expects(self::never())->method('getConfig');

        $resolver = new AuthConfigResolver([$this->createProvider(new AuthConfig('site', 'secret')), $second]);

        self::assertNotNull($resolver->resolve(Request::create('/')));
    }

    private function createProvider(?AuthConfig $config): AuthConfigProviderInterface
    {
        $provider = $this->createStub(AuthConfigProviderInterface::class);
        $provider->method('getConfig')->willReturn($config);

        return $provider;
    }
}
