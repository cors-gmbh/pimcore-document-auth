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

use Pimcore\Http\Request\Resolver\DocumentResolver;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * @implements UserProviderInterface<InMemoryUser>
 */
final readonly class UserProvider implements UserProviderInterface
{
    public function __construct(
        private DocumentResolver $documentResolver,
        private PasswordHasherFactoryInterface $passwordHasherFactory,
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $document = $this->documentResolver->getDocument();

        if (null === $document) {
            throw new UserNotFoundException('No Document found');
        }

        $rawPassword = $document->getProperty('password_password');
        $configuredUsername = $document->getProperty('password_username');

        if (!is_string($rawPassword) || '' === $rawPassword) {
            throw new AuthenticationServiceException('Password not configured!');
        }

        if (!is_string($configuredUsername) || '' === $configuredUsername) {
            throw new AuthenticationServiceException('Username not configured');
        }

        if (!$document->getProperty('password_enabled')) {
            throw new AuthenticationServiceException('Password Access disabled');
        }

        if ($configuredUsername !== $identifier) {
            throw new BadCredentialsException('Wrong Username');
        }

        $user = new InMemoryUser($identifier, $rawPassword, ['ROLE_USER']);

        $hasher = $this->passwordHasherFactory->getPasswordHasher($user);
        $password = $hasher->hash($rawPassword);

        return new InMemoryUser($identifier, $password, ['ROLE_USER']);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof InMemoryUser) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', $user::class));
        }

        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return InMemoryUser::class === $class;
    }
}
