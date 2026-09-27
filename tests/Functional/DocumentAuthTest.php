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

namespace CORS\Bundle\DocumentAuthBundle\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use Pimcore\Model\Document;
use Pimcore\Model\Document\Page;
use Pimcore\Model\User;
use Pimcore\Test\WebTestCase;
use Pimcore\Tool\Authentication;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Component\HttpFoundation\Response;

/**
 * Full stack: Pimcore routing, the document_auth firewall and the session. Requires the installed
 * dev harness (see README) and is skipped otherwise:
 *
 *   docker compose exec -e PIMCORE_FUNCTIONAL=1 php vendor/bin/phpunit --testsuite functional
 */
final class DocumentAuthTest extends WebTestCase
{
    private const string ADMIN_PASSWORD = 'document-auth-test-password';

    private static string $root = '';

    private static string $adminUsername = '';

    private KernelBrowser $client;

    public static function setUpBeforeClass(): void
    {
        if ('1' !== getenv('PIMCORE_FUNCTIONAL')) {
            self::markTestSkipped('Set PIMCORE_FUNCTIONAL=1 to run the functional tests against the dev harness.');
        }

        self::bootKernel();

        $root = self::createPage(1, 'document-auth-test-' . bin2hex(random_bytes(4)));
        self::$root = $root->getRealFullPath();

        self::createPage($root->getId(), 'open');

        $basic = self::createPage($root->getId(), 'basic', ['password_mode' => 'basic'] + self::credentials('max', 'secret'));
        self::createPage($basic->getId(), 'child');

        $form = self::createPage($root->getId(), 'form', ['password_mode' => 'form'] + self::credentials('max', 'secret'));
        self::createPage($form->getId(), 'child');

        self::createPage($root->getId(), 'other', ['password_mode' => 'form'] + self::credentials('anna', 'other'));
        self::createPage($root->getId(), 'customer', [
            'password_mode' => 'form',
            'password_template' => 'document-auth/customer.html.twig',
        ] + self::credentials('max', 'secret'));

        self::$adminUsername = 'document-auth-test-' . bin2hex(random_bytes(4));
        $admin = new User();
        $admin->setName(self::$adminUsername);
        $admin->setPassword(Authentication::getPasswordHash(self::$adminUsername, self::ADMIN_PASSWORD));
        $admin->setAdmin(true);
        $admin->setActive(true);
        $admin->setParentId(0);
        $admin->save();

        self::ensureKernelShutdown();
    }

    public static function tearDownAfterClass(): void
    {
        if ('' === self::$root) {
            return;
        }

        self::bootKernel();
        Document::getByPath(self::$root)?->delete();
        User::getByName(self::$adminUsername)?->delete();
        self::ensureKernelShutdown();
        self::$root = '';
    }

    protected function setUp(): void
    {
        $this->client = self::createClient();
        // One kernel (and DB connection) per test, so documents saved by the test don't lock each other
        $this->client->disableReboot();
    }

    public function testUnprotectedDocumentIsPublic(): void
    {
        $this->client->request('GET', $this->url('/open'));

        self::assertResponseStatusCodeSame(Response::HTTP_OK);
    }

    public function testBasicModeChallengesWithoutCredentials(): void
    {
        $this->client->request('GET', $this->url('/basic'));

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertResponseHeaderSame('WWW-Authenticate', 'Basic realm="Site"');
    }

    public function testBasicModeRejectsWrongPassword(): void
    {
        $this->client->request('GET', $this->url('/basic'), server: $this->basicAuth('max', 'wrong'));

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    public function testBasicModeGrantsAccessToDocumentAndChildren(): void
    {
        $this->client->request('GET', $this->url('/basic'), server: $this->basicAuth('max', 'secret'));
        self::assertResponseStatusCodeSame(Response::HTTP_OK);
        self::assertSelectorTextContains('strong', 'max');

        $this->client->request('GET', $this->url('/basic/child'), server: $this->basicAuth('max', 'secret'));
        self::assertResponseStatusCodeSame(Response::HTTP_OK);
    }

    public function testFormModeRendersLoginPageWithoutBasicChallenge(): void
    {
        $this->client->request('GET', $this->url('/form'));

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertResponseNotHasHeader('WWW-Authenticate');
        self::assertSelectorExists('form.document-auth input[name="_document_auth"]');
        self::assertSelectorExists('form.document-auth input[name="_csrf_token"]');
        self::assertSelectorNotExists('[role="alert"]');
    }

    public function testFormModeRejectsWrongPassword(): void
    {
        $this->login('/form', 'max', 'wrong');

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertSelectorExists('[role="alert"]');
        self::assertInputValueSame('_username', 'max');
    }

    public function testFormModeRejectsLoginWithoutCsrfToken(): void
    {
        $this->client->request('POST', $this->url('/form'), [
            '_username' => 'max',
            '_password' => 'secret',
            '_document_auth' => '1',
        ]);

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertSelectorExists('[role="alert"]');
    }

    public function testFormModeLoginRedirectsBackAndKeepsSession(): void
    {
        $this->login('/form', 'max', 'secret');

        self::assertResponseStatusCodeSame(Response::HTTP_SEE_OTHER);
        self::assertResponseRedirects($this->url('/form'));

        $this->client->followRedirect();
        self::assertResponseStatusCodeSame(Response::HTTP_OK);
        self::assertSelectorTextContains('strong', 'max');

        $this->client->request('GET', $this->url('/form/child'));
        self::assertResponseStatusCodeSame(Response::HTTP_OK);
    }

    public function testFormModeIgnoresBasicAuthOfLoadBalancer(): void
    {
        $loadBalancer = $this->basicAuth('lb', 'lb-password');

        $this->client->request('GET', $this->url('/form'), server: $loadBalancer);
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertResponseNotHasHeader('WWW-Authenticate');

        $this->client->setServerParameters($loadBalancer);
        $this->login('/form', 'max', 'secret');
        $this->client->followRedirect();

        self::assertResponseStatusCodeSame(Response::HTTP_OK);
    }

    public function testSessionDoesNotGrantAccessToDocumentWithOtherCredentials(): void
    {
        $this->login('/form', 'max', 'secret');
        self::assertResponseStatusCodeSame(Response::HTTP_SEE_OTHER);

        $this->client->request('GET', $this->url('/other'));

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertSelectorExists('form.document-auth');
    }

    public function testSessionEndsWhenPasswordChanges(): void
    {
        $this->login('/form/child', 'max', 'secret');
        $this->client->followRedirect();
        self::assertResponseStatusCodeSame(Response::HTTP_OK);

        $this->changePassword('/form', 'changed');

        try {
            $this->client->request('GET', $this->url('/form/child'));
            self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        } finally {
            $this->changePassword('/form', 'secret');
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function adminParameters(): iterable
    {
        foreach (['pimcore_editmode', 'pimcore_preview', 'pimcore_admin', 'pimcore_object_preview', 'pimcore_version'] as $parameter) {
            yield $parameter => [$parameter];
        }
    }

    #[DataProvider('adminParameters')]
    public function testAdminParametersDoNotBypassProtectionWithoutAdminSession(string $parameter): void
    {
        $this->client->request('GET', $this->url('/form') . '?' . $parameter . '=1');

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    public function testStudioPreviewOfLoggedInAdminIsNotProtected(): void
    {
        $this->client->jsonRequest('POST', '/pimcore-studio/api/login', [
            'username' => self::$adminUsername,
            'password' => self::ADMIN_PASSWORD,
        ]);
        self::assertResponseIsSuccessful();

        $this->client->request('GET', $this->url('/form') . '?pimcore_preview=1');
        self::assertResponseStatusCodeSame(Response::HTTP_OK);

        // Without the preview parameter the admin session does not open the document
        $this->client->request('GET', $this->url('/form'));
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    public function testFormModeUsesTemplateOfDocumentProperty(): void
    {
        $this->client->request('GET', $this->url('/customer'));

        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
        self::assertSelectorTextContains('form.document-auth strong', 'CUSTOMER');
    }

    private function login(string $path, string $username, string $password): void
    {
        $crawler = $this->client->request('GET', $this->url($path));
        $csrfToken = (string) $crawler->filter('input[name="_csrf_token"]')->attr('value');

        $this->client->request('POST', $this->url($path), [
            '_username' => $username,
            '_password' => $password,
            '_csrf_token' => $csrfToken,
            '_document_auth' => '1',
        ]);
    }

    private function changePassword(string $path, string $password): void
    {
        $page = Page::getByPath($this->url($path), ['force' => true]);
        self::assertInstanceOf(Page::class, $page);

        $page->setProperty('password_password', 'text', $password, false, true);
        $page->save();

        // Requests of the test client share the process: drop the runtime cached documents
        \Pimcore::collectGarbage();
    }

    private function url(string $path): string
    {
        return self::$root . $path;
    }

    /**
     * @return array{PHP_AUTH_USER: string, PHP_AUTH_PW: string}
     */
    private function basicAuth(string $username, string $password): array
    {
        return ['PHP_AUTH_USER' => $username, 'PHP_AUTH_PW' => $password];
    }

    /**
     * @return array<string, bool|string>
     */
    private static function credentials(string $username, string $password): array
    {
        return [
            'password_enabled' => true,
            'password_username' => $username,
            'password_password' => $password,
        ];
    }

    /**
     * @param array<string, bool|string> $properties
     */
    private static function createPage(int $parentId, string $key, array $properties = []): Page
    {
        $page = new Page();
        $page->setParentId($parentId);
        $page->setKey($key);
        $page->setPublished(true);

        foreach ($properties as $name => $value) {
            $page->setProperty($name, is_bool($value) ? 'bool' : 'text', $value, false, true);
        }

        $page->save();

        return $page;
    }
}
