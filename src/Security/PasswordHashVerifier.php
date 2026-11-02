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

namespace CORS\Bundle\DocumentAuthBundle\Security;

use Symfony\Component\PasswordHasher\PasswordHasherInterface;

/**
 * Verifies passwords stored as password_hash() hash, the way Pimcore password fields store them.
 * The bundle never hashes passwords itself.
 */
final class PasswordHashVerifier implements PasswordHasherInterface
{
    public function hash(#[\SensitiveParameter] string $plainPassword): string
    {
        throw new \LogicException('Document auth passwords are managed by their source and never hashed by the bundle.');
    }

    public function verify(string $hashedPassword, #[\SensitiveParameter] string $plainPassword): bool
    {
        return '' !== $plainPassword && password_verify($plainPassword, $hashedPassword);
    }

    public function needsRehash(string $hashedPassword): bool
    {
        return false;
    }
}
