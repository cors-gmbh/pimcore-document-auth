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
 * Source of the credentials of protected requests. Implementations are registered automatically
 * (autoconfigure) and asked by priority of the tag "cors_document_auth.config_provider"; the first
 * one returning a config wins. The document properties are the default source (priority 0).
 */
interface AuthConfigProviderInterface
{
    public const string TAG = 'cors_document_auth.config_provider';

    /**
     * @return AuthConfig|null the config if the request is protected by this source, null if the
     *                         source is not responsible (the next provider is asked)
     */
    public function getConfig(Request $request): ?AuthConfig;
}
