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

use CORS\Bundle\DocumentAuthBundle\Security\PasswordHashVerifier;
use PHPUnit\Framework\TestCase;

final class PasswordHashVerifierTest extends TestCase
{
    public function testVerifiesPasswordHashLikePimcorePasswordFields(): void
    {
        $verifier = new PasswordHashVerifier();

        foreach ([\PASSWORD_BCRYPT, \PASSWORD_ARGON2ID] as $algorithm) {
            $hash = password_hash('secret', $algorithm);

            self::assertTrue($verifier->verify($hash, 'secret'));
            self::assertFalse($verifier->verify($hash, 'wrong'));
        }
    }

    public function testRejectsEmptyPasswordAndRawValues(): void
    {
        $verifier = new PasswordHashVerifier();

        self::assertFalse($verifier->verify(password_hash('', \PASSWORD_BCRYPT), ''));
        // A raw stored password is not accepted as hash
        self::assertFalse($verifier->verify('secret', 'secret'));
    }

    public function testNeverHashesOrRehashes(): void
    {
        $verifier = new PasswordHashVerifier();

        self::assertFalse($verifier->needsRehash(password_hash('secret', \PASSWORD_BCRYPT)));

        $this->expectException(\LogicException::class);
        $verifier->hash('secret');
    }
}
