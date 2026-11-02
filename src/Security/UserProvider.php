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
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * @implements UserProviderInterface<DocumentUser|InMemoryUser>
 */
final readonly class UserProvider implements UserProviderInterface
{
    public function __construct(
        private DocumentResolver $documentResolver,
        #[\SensitiveParameter]
        private string $secret,
    ) {
    }

    public function loadUserByIdentifier(string $identifier): DocumentUser
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

        return new DocumentUser(
            $configuredUsername,
            $rawPassword,
            hash_hmac('sha256', $configuredUsername . "\0" . $rawPassword, $this->secret),
        );
    }

    public function refreshUser(UserInterface $user): DocumentUser
    {
        if (!$this->supportsClass($user::class)) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', $user::class));
        }

        if (!$user instanceof DocumentUser) {
            // Session from a version before DocumentUser existed: force a new login
            throw $this->createUserNotFound($user, 'Legacy document auth session');
        }

        try {
            $currentUser = $this->loadUserByIdentifier($user->getUserIdentifier());
        } catch (AuthenticationException $exception) {
            throw $this->createUserNotFound($user, 'Document credentials not valid anymore', $exception);
        }

        // The session belongs to a document with other (or changed) credentials
        if (!$user->isEqualTo($currentUser)) {
            throw $this->createUserNotFound($user, 'Document credentials do not match the session');
        }

        return $currentUser;
    }

    public function supportsClass(string $class): bool
    {
        return DocumentUser::class === $class || InMemoryUser::class === $class;
    }

    private function createUserNotFound(
        UserInterface $user,
        string $message,
        ?\Throwable $previous = null,
    ): UserNotFoundException {
        $exception = new UserNotFoundException($message, 0, $previous);
        $exception->setUserIdentifier($user->getUserIdentifier());

        return $exception;
    }
}
