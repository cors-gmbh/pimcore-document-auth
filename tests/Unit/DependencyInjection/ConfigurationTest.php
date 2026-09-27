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

namespace CORS\Bundle\DocumentAuthBundle\Tests\Unit\DependencyInjection;

use CORS\Bundle\DocumentAuthBundle\DependencyInjection\Configuration;
use CORS\Bundle\DocumentAuthBundle\DependencyInjection\CORSDocumentAuthExtension;
use CORS\Bundle\DocumentAuthBundle\Security\DocumentUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class ConfigurationTest extends TestCase
{
    public function testDefaultsToBasicAuth(): void
    {
        self::assertSame([
            'mode' => 'basic',
            'realm' => 'Site',
            'form' => [
                'template' => '@CORSDocumentAuth/login.html.twig',
                'csrf_protection' => true,
            ],
        ], $this->process([]));
    }

    public function testAcceptsFormMode(): void
    {
        $config = $this->process([['mode' => 'form', 'form' => ['template' => 'login.html.twig', 'csrf_protection' => false]]]);

        self::assertSame('form', $config['mode']);
        self::assertSame('login.html.twig', $config['form']['template']);
        self::assertFalse($config['form']['csrf_protection']);
    }

    public function testRejectsUnknownMode(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process([['mode' => 'popup']]);
    }

    public function testExtensionExposesConfigAsParameters(): void
    {
        $container = new ContainerBuilder();
        (new CORSDocumentAuthExtension())->load([['mode' => 'form', 'realm' => 'Intranet']], $container);

        self::assertSame('form', $container->getParameter('cors_document_auth.mode'));
        self::assertSame('Intranet', $container->getParameter('cors_document_auth.realm'));
        self::assertSame('@CORSDocumentAuth/login.html.twig', $container->getParameter('cors_document_auth.form.template'));
        self::assertTrue($container->getParameter('cors_document_auth.form.csrf_protection'));
    }

    public function testExtensionRegistersPlaintextPasswordHasher(): void
    {
        $container = new ContainerBuilder();
        (new CORSDocumentAuthExtension())->prepend($container);

        self::assertSame(
            [['password_hashers' => [DocumentUser::PASSWORD_HASHER => ['algorithm' => 'plaintext']]]],
            $container->getExtensionConfig('security'),
        );
    }

    public function testExtensionRegistersPredefinedDocumentProperties(): void
    {
        $container = new ContainerBuilder();
        (new CORSDocumentAuthExtension())->prepend($container);

        $definitions = $container->getExtensionConfig('pimcore')[0]['properties']['predefined']['definitions'];
        $keys = array_column($definitions, 'key');

        self::assertSame(
            ['password_enabled', 'password_username', 'password_password', 'password_mode', 'password_template'],
            $keys,
        );

        foreach ($definitions as $definition) {
            self::assertSame('document', $definition['ctype']);
            self::assertTrue($definition['inheritable']);
        }
    }

    /**
     * @param list<array<string, mixed>> $configs
     *
     * @return array<string, mixed>
     */
    private function process(array $configs): array
    {
        return (new Processor())->processConfiguration(new Configuration(), $configs);
    }
}
