<?php

namespace App\Tests\Security;

use App\Entity\UserSystem\User;
use App\Entity\UserSystem\Group;
use App\Security\HeaderAuthenticator;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class HeaderAuthenticatorTest extends TestCase
{
    private $entityManager;
    private $userRepository;
    private $groupRepository;

    protected function setUp(): void
    {
        $this->entityManager = $this->createMock(EntityManagerInterface::class);
        $this->userRepository = $this->createMock(EntityRepository::class);
        $this->groupRepository = $this->createMock(EntityRepository::class);
    }

    public function testSupportsWhenDisabled(): void
    {
        $authenticator = new HeaderAuthenticator(false, 'X-Forwarded-User', true, true, '', $this->entityManager);
        $request = new Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => 'alice']);
        $this->assertFalse($authenticator->supports($request));
    }

    public function testSupportsWhenHeaderMissing(): void
    {
        $authenticator = new HeaderAuthenticator(true, 'X-Forwarded-User', true, true, '', $this->entityManager);
        $request = new Request();
        $this->assertFalse($authenticator->supports($request));
    }

    public function testSupportsWhenHeaderPresent(): void
    {
        $authenticator = new HeaderAuthenticator(true, 'X-Forwarded-User', true, true, '', $this->entityManager);
        $request = new Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => 'alice']);
        $this->assertTrue($authenticator->supports($request));
    }

    public function testAuthenticateThrowsIfHeaderEmpty(): void
    {
        $authenticator = new HeaderAuthenticator(true, 'X-Forwarded-User', true, true, '', $this->entityManager);
        $request = new Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => '']);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testAuthenticateExistingUser(): void
    {
        $user = new User();
        $this->userRepository->method('findOneBy')->with(['name' => 'alice'])->willReturn($user);

        $this->entityManager->method('getRepository')->willReturnCallback(function ($class) {
            if ($class === User::class) {
                return $this->userRepository;
            }
            return null;
        });

        $authenticator = new HeaderAuthenticator(true, 'X-Forwarded-User', false, true, '', $this->entityManager);
        $request = new Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => 'alice']);

        $passport = $authenticator->authenticate($request);
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);

        $userBadge = $passport->getBadge(UserBadge::class);
        $this->assertSame($user, $userBadge->getUserLoader()('alice'));
    }

    public function testAuthenticateNewUserWithoutAutoCreateThrows(): void
    {
        $this->userRepository->method('findOneBy')->with(['name' => 'alice'])->willReturn(null);

        $this->entityManager->method('getRepository')->willReturnCallback(function ($class) {
            if ($class === User::class) {
                return $this->userRepository;
            }
            return null;
        });

        $authenticator = new HeaderAuthenticator(true, 'X-Forwarded-User', false, true, '', $this->entityManager);
        $request = new Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => 'alice']);

        $passport = $authenticator->authenticate($request);
        $userBadge = $passport->getBadge(UserBadge::class);

        $this->expectException(UserNotFoundException::class);
        $userBadge->getUserLoader()('alice');
    }

    public function testAuthenticateNewUserWithAutoCreate(): void
    {
        $this->userRepository->method('findOneBy')->with(['name' => 'alice'])->willReturn(null);

        $group = new Group();
        $this->groupRepository->method('findOneBy')->with(['name' => 'default_group'])->willReturn($group);

        $this->entityManager->method('getRepository')->willReturnCallback(function ($class) {
            if ($class === User::class) {
                return $this->userRepository;
            }
            if ($class === Group::class) {
                return $this->groupRepository;
            }
            return null;
        });

        $this->entityManager->expects($this->once())->method('persist')->with($this->isInstanceOf(User::class));
        $this->entityManager->expects($this->once())->method('flush');

        $authenticator = new HeaderAuthenticator(true, 'X-Forwarded-User', true, true, 'default_group', $this->entityManager);
        $request = new Request([], [], [], [], [], ['HTTP_X_FORWARDED_USER' => 'alice']);

        $passport = $authenticator->authenticate($request);
        $userBadge = $passport->getBadge(UserBadge::class);
        $user = $userBadge->getUserLoader()('alice');

        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('alice', $user->getName());
        $this->assertFalse($user->isNeedPwChange());
        $this->assertSame($group, $user->getGroup());
    }
}
