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

use PHPUnit\Framework\TestCase;
use Pimcore\Http\Request\Resolver\DocumentResolver;
use Pimcore\Model\Document\Page;

/**
 * Stubs for the document resolved from the request and its (inherited) properties.
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
}
