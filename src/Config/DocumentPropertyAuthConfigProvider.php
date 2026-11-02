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

namespace CORS\Bundle\DocumentAuthBundle\Config;

use Pimcore\Http\Request\Resolver\DocumentResolver;
use Symfony\Component\HttpFoundation\Request;

/**
 * Default source: the (inheritable) properties of the requested document.
 */
final readonly class DocumentPropertyAuthConfigProvider implements AuthConfigProviderInterface
{
    public const string ENABLED_PROPERTY = 'password_enabled';

    public const string USERNAME_PROPERTY = 'password_username';

    public const string PASSWORD_PROPERTY = 'password_password';

    public const string MODE_PROPERTY = 'password_mode';

    public const string TEMPLATE_PROPERTY = 'password_template';

    public function __construct(
        private DocumentResolver $documentResolver,
    ) {
    }

    public function getConfig(Request $request): ?AuthConfig
    {
        $document = $this->documentResolver->getDocument($request);

        if (null === $document || !$document->getProperty(self::ENABLED_PROPERTY)) {
            return null;
        }

        return new AuthConfig(
            username: self::string($document->getProperty(self::USERNAME_PROPERTY)),
            password: self::string($document->getProperty(self::PASSWORD_PROPERTY)),
            mode: self::string($document->getProperty(self::MODE_PROPERTY)),
            template: self::string($document->getProperty(self::TEMPLATE_PROPERTY)),
        );
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && '' !== $value ? $value : null;
    }
}
