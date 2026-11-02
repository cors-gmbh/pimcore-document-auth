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

use Symfony\Component\HttpFoundation\Request;

/**
 * Asks the config providers by priority. The result is kept on the request, as the firewall needs it
 * several times per request.
 */
final readonly class AuthConfigResolver
{
    private const string ATTRIBUTE = '_cors_document_auth_config';

    /**
     * @param iterable<AuthConfigProviderInterface> $providers
     */
    public function __construct(
        private iterable $providers,
    ) {
    }

    public function resolve(Request $request): ?AuthConfig
    {
        if ($request->attributes->has(self::ATTRIBUTE)) {
            $config = $request->attributes->get(self::ATTRIBUTE);

            return $config instanceof AuthConfig ? $config : null;
        }

        $config = null;

        foreach ($this->providers as $provider) {
            $config = $provider->getConfig($request);

            if (null !== $config) {
                break;
            }
        }

        $request->attributes->set(self::ATTRIBUTE, $config);

        return $config;
    }
}
