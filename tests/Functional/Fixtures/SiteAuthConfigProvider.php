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

namespace CORS\Bundle\DocumentAuthBundle\Tests\Functional\Fixtures;

use CORS\Bundle\DocumentAuthBundle\Config\AuthConfig;
use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigProviderInterface;
use Symfony\Component\DependencyInjection\Attribute\AsTaggedItem;
use Symfony\Component\HttpFoundation\Request;

/**
 * Stands for a project source like a site config data object: protects every document named
 * "site-config" with a hashed password, before the document properties are asked.
 */
#[AsTaggedItem(priority: 10)]
final class SiteAuthConfigProvider implements AuthConfigProviderInterface
{
    public const string USERNAME = 'site';

    public const string PASSWORD = 'site-secret';

    private static ?string $hash = null;

    public function getConfig(Request $request): ?AuthConfig
    {
        if (!str_ends_with($request->getPathInfo(), '/site-config')) {
            return null;
        }

        self::$hash ??= password_hash(self::PASSWORD, \PASSWORD_BCRYPT);

        return new AuthConfig(self::USERNAME, self::$hash, true, 'form');
    }
}
