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

use CORS\Bundle\DocumentAuthBundle\Config\AuthConfigResolver;
use Symfony\Component\HttpFoundation\RequestStack;
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
        private AuthConfigResolver $configResolver,
        private RequestStack $requestStack,
        #[\SensitiveParameter]
        private string $secret,
    ) {
    }

    public function loadUserByIdentifier(string $identifier): DocumentUser
    {
        $request = $this->requestStack->getCurrentRequest();
        $config = null !== $request ? $this->configResolver->resolve($request) : null;

        if (null === $config) {
            throw new UserNotFoundException('Request is not protected');
        }

        if (null === $config->password || '' === $config->password) {
            throw new AuthenticationServiceException('Password not configured!');
        }

        if (null === $config->username || '' === $config->username) {
            throw new AuthenticationServiceException('Username not configured');
        }

        if ($config->username !== $identifier) {
            throw new BadCredentialsException('Wrong Username');
        }

        return new DocumentUser(
            $config->username,
            $config->password,
            hash_hmac('sha256', $config->username . "\0" . $config->password, $this->secret),
            $config->passwordHashed,
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
            throw $this->createUserNotFound($user, 'Credentials not valid anymore', $exception);
        }

        // The session belongs to a request with other (or changed) credentials
        if (!$user->isEqualTo($currentUser)) {
            throw $this->createUserNotFound($user, 'Credentials do not match the session');
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
