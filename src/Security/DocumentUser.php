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

use Symfony\Component\PasswordHasher\Hasher\PasswordHasherAwareInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * User authenticated against the credentials of a protected request. The fingerprint binds the
 * session to that set of credentials: a document with different credentials (or changed
 * credentials) no longer accepts the session. The raw password is never serialized.
 */
final readonly class DocumentUser implements
    UserInterface,
    PasswordAuthenticatedUserInterface,
    PasswordHasherAwareInterface,
    EquatableInterface
{
    public const string PASSWORD_HASHER = 'cors_document_auth';

    public const string PASSWORD_HASHER_HASHED = 'cors_document_auth_hashed';

    /**
     * @param non-empty-string $identifier
     */
    public function __construct(
        private string $identifier,
        private ?string $password,
        private string $fingerprint,
        private bool $passwordHashed = false,
    ) {
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function getPasswordHasherName(): string
    {
        return $this->passwordHashed ? self::PASSWORD_HASHER_HASHED : self::PASSWORD_HASHER;
    }

    #[\Deprecated]
    public function eraseCredentials(): void
    {
    }

    public function isEqualTo(UserInterface $user): bool
    {
        return $user instanceof self &&
            $user->identifier === $this->identifier &&
            hash_equals($this->fingerprint, $user->fingerprint);
    }

    /**
     * @return array{identifier: non-empty-string, fingerprint: string}
     */
    public function __serialize(): array
    {
        return [
            'identifier' => $this->identifier,
            'fingerprint' => $this->fingerprint,
        ];
    }

    /**
     * @param array{identifier: non-empty-string, fingerprint: string} $data
     */
    public function __unserialize(array $data): void
    {
        $this->identifier = $data['identifier'];
        $this->password = null;
        $this->fingerprint = $data['fingerprint'];
        $this->passwordHashed = false;
    }
}
