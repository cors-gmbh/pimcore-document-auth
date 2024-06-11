<?php

declare(strict_types=1);

/**
 * CORS GmbH.
 *
 * This source file is available under two different licenses:
 * - GNU General Public License version 3 (GPLv3)
 * - Pimcore Commercial License (PCL)
 * Full copyright and license information is available in
 * LICENSE.md which is distributed with this source code.
 *
 * @copyright  Copyright (c) CORS GmbH (https://www.cors.gmbh)
 * @license    https://www.cors.gmbh/license     GPLv3 and PCL
 */

namespace CORS\Bundle\DocumentAuthBundle\Security;

use Pimcore\Http\Request\Resolver\DocumentResolver;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface
{
    public function __construct(
        private DocumentResolver $documentResolver,
        private PasswordHasherFactoryInterface $passwordHasherFactory
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $document = $this->documentResolver->getDocument();

        if (!$document) {
            throw new \Exception('No Document found');
        }

        $rawPassword = $document->getProperty('password_password');
        $configuredUsername = $document->getProperty('password_username');

        if (!$rawPassword) {
            throw new AuthenticationServiceException('Password not configured!');
        }

        if (!$configuredUsername) {
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
        $password = $hasher->hash($rawPassword, null);

        return new InMemoryUser($identifier, $password, ['ROLE_USER']);
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof InMemoryUser) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
        }

        return $user;
    }

    public function supportsClass($class)
    {
        return InMemoryUser::class === $class;
    }
}
