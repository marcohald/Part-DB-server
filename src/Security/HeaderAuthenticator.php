<?php
/*
 * This file is part of Part-DB (https://github.com/Part-DB/Part-DB-symfony).
 *
 *  Copyright (C) 2019 - 2024 Jan Böhmer (https://github.com/jbtronics)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

declare(strict_types=1);

namespace App\Security;

use App\Entity\UserSystem\Group;
use App\Entity\UserSystem\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class HeaderAuthenticator extends AbstractAuthenticator
{
    final public const HEADER_PASSWORD_PLACEHOLDER = '!!HEADER_AUTH!!';

    public function __construct(
        #[Autowire('%partdb.header_auth.enabled%')]
        private readonly bool $enabled,
        #[Autowire('%partdb.header_auth.header_name%')]
        private readonly string $headerName,
        #[Autowire('%partdb.header_auth.auto_create%')]
        private readonly bool $autoCreate,
        #[Autowire('%partdb.header_auth.disable_password_expiration%')]
        private readonly bool $disablePasswordExpiration,
        #[Autowire('%partdb.header_auth.default_group%')]
        private readonly string $defaultGroup,
        private readonly EntityManagerInterface $entityManager,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        if (!$this->enabled) {
            return false;
        }

        return $request->headers->has($this->headerName) && $request->headers->get($this->headerName) !== '';
    }

    public function authenticate(Request $request): Passport
    {
        $username = $request->headers->get($this->headerName);

        if (null === $username || '' === $username) {
            throw new AuthenticationException('Header authentication failed: Missing or empty username.');
        }

        return new SelfValidatingPassport(
            new UserBadge($username, function (string $userIdentifier) {
                $userRepository = $this->entityManager->getRepository(User::class);
                $user = $userRepository->findOneBy(['name' => $userIdentifier]);

                if (!$user) {
                    if (!$this->autoCreate) {
                        throw new UserNotFoundException(sprintf('User "%s" not found.', $userIdentifier));
                    }

                    $user = new User();
                    $user->setName($userIdentifier);
                    $user->setPassword(self::HEADER_PASSWORD_PLACEHOLDER);

                    if ($this->disablePasswordExpiration) {
                        $user->setNeedPwChange(false);
                    }

                    if ('' !== $this->defaultGroup) {
                        $groupRepository = $this->entityManager->getRepository(Group::class);
                        $group = $groupRepository->findOneBy(['name' => $this->defaultGroup]);

                        if ($group) {
                            $user->setGroup($group);
                        }
                    }

                    $this->entityManager->persist($user);
                    $this->entityManager->flush();
                }

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null; // Let the request continue to the original destination
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new Response(
            strtr($exception->getMessageKey(), $exception->getMessageData()),
            Response::HTTP_UNAUTHORIZED
        );
    }
}
