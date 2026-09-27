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
use CORS\Bundle\DocumentAuthBundle\Config\DocumentPropertyAuthConfigProvider;
use CORS\Bundle\DocumentAuthBundle\Tests\Unit\Security\DocumentTestCase;
use Pimcore\Model\Document\Page;
use Symfony\Component\HttpFoundation\Request;

final class DocumentPropertyAuthConfigProviderTest extends DocumentTestCase
{
    public function testReadsConfigFromDocumentProperties(): void
    {
        $document = $this->createProtectedDocument('max', 'secret', [
            'password_mode' => 'form',
            'password_template' => 'customer.html.twig',
        ]);

        $config = $this->getConfig($document);

        self::assertNotNull($config);
        self::assertSame('max', $config->username);
        self::assertSame('secret', $config->password);
        self::assertFalse($config->passwordHashed);
        self::assertSame('form', $config->mode);
        self::assertSame('customer.html.twig', $config->template);
    }

    public function testIsNotResponsibleWithoutDocument(): void
    {
        self::assertNull($this->getConfig(null));
    }

    public function testIsNotResponsibleForUnprotectedDocument(): void
    {
        self::assertNull($this->getConfig($this->createDocument(['password_username' => 'max', 'password_password' => 'secret'])));
        self::assertNull($this->getConfig($this->createProtectedDocument(properties: ['password_enabled' => false])));
    }

    public function testKeepsMisconfiguredDocumentProtected(): void
    {
        $config = $this->getConfig($this->createDocument([
            'password_enabled' => true,
            'password_username' => '',
            'password_mode' => ['no string'],
        ]));

        self::assertNotNull($config);
        self::assertNull($config->username);
        self::assertNull($config->password);
        self::assertNull($config->mode);
        self::assertNull($config->template);
    }

    private function getConfig(?Page $document): ?AuthConfig
    {
        return (new DocumentPropertyAuthConfigProvider($this->createResolver($document)))->getConfig(Request::create('/'));
    }
}
