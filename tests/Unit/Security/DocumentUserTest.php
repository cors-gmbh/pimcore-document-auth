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

use CORS\Bundle\DocumentAuthBundle\Security\DocumentUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactory;
use Symfony\Component\PasswordHasher\Hasher\PlaintextPasswordHasher;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

final class DocumentUserTest extends TestCase
{
    public function testExposesIdentityAndRoles(): void
    {
        $user = new DocumentUser('max', 'secret', 'fingerprint');

        self::assertSame('max', $user->getUserIdentifier());
        self::assertSame('secret', $user->getPassword());
        self::assertSame('fingerprint', $user->getFingerprint());
        self::assertSame(['ROLE_USER'], $user->getRoles());
        self::assertSame(DocumentUser::PASSWORD_HASHER, $user->getPasswordHasherName());
    }

    public function testSerializedTokenDoesNotContainThePassword(): void
    {
        $user = new DocumentUser('max', 'top-secret-password', 'fingerprint');
        $serialized = serialize(new UsernamePasswordToken($user, 'document_auth', $user->getRoles()));

        self::assertStringNotContainsString('top-secret-password', $serialized);

        $restored = unserialize($serialized)->getUser();

        self::assertInstanceOf(DocumentUser::class, $restored);
        self::assertSame('max', $restored->getUserIdentifier());
        self::assertSame('fingerprint', $restored->getFingerprint());
        self::assertNull($restored->getPassword());
    }

    public function testIsEqualToComparesIdentifierAndFingerprint(): void
    {
        $user = new DocumentUser('max', null, 'fingerprint');

        self::assertTrue($user->isEqualTo(new DocumentUser('max', 'secret', 'fingerprint')));
        self::assertFalse($user->isEqualTo(new DocumentUser('max', 'secret', 'other')));
        self::assertFalse($user->isEqualTo(new DocumentUser('anna', 'secret', 'fingerprint')));
        self::assertFalse($user->isEqualTo(new InMemoryUser('max', 'secret')));
    }

    public function testPlaintextHasherIsUsedForTheRawDocumentPassword(): void
    {
        $factory = new PasswordHasherFactory([DocumentUser::PASSWORD_HASHER => ['algorithm' => 'plaintext']]);
        $user = new DocumentUser('max', 'secret', 'fingerprint');
        $hasher = $factory->getPasswordHasher($user);

        self::assertInstanceOf(PlaintextPasswordHasher::class, $hasher);
        self::assertTrue($hasher->verify((string) $user->getPassword(), 'secret'));
        self::assertFalse($hasher->verify((string) $user->getPassword(), 'wrong'));
    }
}
