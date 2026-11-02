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

use CORS\Bundle\DocumentAuthBundle\Config\AuthConfig;
use CORS\Bundle\DocumentAuthBundle\Security\DocumentUser;
use CORS\Bundle\DocumentAuthBundle\Security\UserProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use Pimcore\Model\Document\Page;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

final class UserProviderTest extends DocumentTestCase
{
    public function testLoadsUserFromDocumentProperties(): void
    {
        $user = $this->createProvider($this->createProtectedDocument())->loadUserByIdentifier('max');

        self::assertSame('max', $user->getUserIdentifier());
        self::assertSame('secret', $user->getPassword());
        self::assertSame(hash_hmac('sha256', "max\0secret", 'kernel-secret'), $user->getFingerprint());
    }

    public function testThrowsWithoutDocument(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->createProvider(null)->loadUserByIdentifier('max');
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function misconfiguredDocuments(): iterable
    {
        yield 'no password' => [['password_enabled' => true, 'password_username' => 'max']];
        yield 'empty password' => [['password_enabled' => true, 'password_username' => 'max', 'password_password' => '']];
        yield 'no username' => [['password_enabled' => true, 'password_password' => 'secret']];
    }

    /**
     * @param array<string, mixed> $properties
     */
    #[DataProvider('misconfiguredDocuments')]
    public function testThrowsForMisconfiguredDocument(array $properties): void
    {
        $this->expectException(AuthenticationServiceException::class);

        $this->createProvider($this->createDocument($properties))->loadUserByIdentifier('max');
    }

    public function testThrowsForUnprotectedDocument(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->createProvider($this->createProtectedDocument(properties: ['password_enabled' => false]))
            ->loadUserByIdentifier('max')
        ;
    }

    public function testThrowsWithoutRequest(): void
    {
        $this->expectException(UserNotFoundException::class);

        (new UserProvider($this->createConfigResolver($this->createProtectedDocument()), new RequestStack(), 'kernel-secret'))
            ->loadUserByIdentifier('max')
        ;
    }

    public function testLoadsUserWithHashedPasswordFromProvider(): void
    {
        $hash = password_hash('secret', \PASSWORD_BCRYPT);
        $configResolver = $this->createConfigResolver(null, $this->createFixedProvider(new AuthConfig('max', $hash, true)));

        $user = $this->createUserProvider($configResolver)->loadUserByIdentifier('max');

        self::assertSame($hash, $user->getPassword());
        self::assertSame(DocumentUser::PASSWORD_HASHER_HASHED, $user->getPasswordHasherName());
        self::assertSame(hash_hmac('sha256', "max\0" . $hash, 'kernel-secret'), $user->getFingerprint());
    }

    public function testProviderWithHigherPriorityWins(): void
    {
        $configResolver = $this->createConfigResolver(
            $this->createProtectedDocument('max', 'secret'),
            $this->createFixedProvider(new AuthConfig('site', 'site-secret')),
        );

        $this->expectException(BadCredentialsException::class);

        $this->createUserProvider($configResolver)->loadUserByIdentifier('max');
    }

    public function testThrowsForWrongUsername(): void
    {
        $this->expectException(BadCredentialsException::class);

        $this->createProvider($this->createProtectedDocument())->loadUserByIdentifier('anna');
    }

    public function testRefreshKeepsSessionForSameCredentials(): void
    {
        $sessionUser = $this->createSessionUser('max', 'secret');

        $refreshed = $this->createProvider($this->createProtectedDocument())->refreshUser($sessionUser);

        self::assertTrue($sessionUser->isEqualTo($refreshed));
    }

    public function testRefreshRejectsSessionOfDocumentWithOtherPassword(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->createProvider($this->createProtectedDocument('max', 'other'))
            ->refreshUser($this->createSessionUser('max', 'secret'))
        ;
    }

    public function testRefreshRejectsSessionOfDocumentWithOtherUsername(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->createProvider($this->createProtectedDocument('anna', 'secret'))
            ->refreshUser($this->createSessionUser('max', 'secret'))
        ;
    }

    public function testRefreshRejectsSessionWhenProtectionWasDisabled(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->createProvider($this->createProtectedDocument(properties: ['password_enabled' => false]))
            ->refreshUser($this->createSessionUser('max', 'secret'))
        ;
    }

    public function testRefreshRejectsLegacyInMemoryUserSession(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->createProvider($this->createProtectedDocument())->refreshUser(new InMemoryUser('max', 'hash'));
    }

    public function testRefreshRejectsForeignUserClass(): void
    {
        $this->expectException(UnsupportedUserException::class);

        $this->createProvider($this->createProtectedDocument())->refreshUser($this->createStub(UserInterface::class));
    }

    public function testSupportsDocumentUserAndLegacyInMemoryUser(): void
    {
        $provider = $this->createProvider(null);

        self::assertTrue($provider->supportsClass(DocumentUser::class));
        self::assertTrue($provider->supportsClass(InMemoryUser::class));
        self::assertFalse($provider->supportsClass(UserInterface::class));
    }

    private function createProvider(?Page $document): UserProvider
    {
        return $this->createUserProvider($this->createConfigResolver($document));
    }

    /**
     * The user as it comes back from the session: without password.
     */
    private function createSessionUser(string $username, string $password): DocumentUser
    {
        $user = $this->createProvider($this->createProtectedDocument($username, $password))
            ->loadUserByIdentifier($username)
        ;

        $sessionUser = unserialize(serialize($user));
        self::assertInstanceOf(DocumentUser::class, $sessionUser);

        return $sessionUser;
    }
}
