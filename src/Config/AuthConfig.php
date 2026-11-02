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

/**
 * Credentials and login settings for a protected request. A missing username or password keeps the
 * request protected, but no login can succeed.
 */
final readonly class AuthConfig
{
    /**
     * @param bool        $passwordHashed true if the password is a password_hash() hash (e.g. a Pimcore
     *                                    password field), false for a raw password
     * @param string|null $mode           "basic" or "form", null for the configured default
     * @param string|null $template       Twig template of the login form, null for the configured one
     */
    public function __construct(
        public ?string $username,
        #[\SensitiveParameter]
        public ?string $password,
        public bool $passwordHashed = false,
        public ?string $mode = null,
        public ?string $template = null,
    ) {
    }
}
