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

use CORS\Bundle\DocumentAuthBundle\Tests\Functional\Fixtures\SiteAuthConfigProvider;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * The dev harness kernel with the Symfony test client, a mock session storage and a custom config
 * provider. The harness is
 * used instead of the "test" environment, because it holds the Pimcore product registration.
 */
final class FunctionalKernel extends \Kernel
{
    public function getCacheDir(): string
    {
        return $this->getProjectDir() . '/var/cache/functional';
    }

    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        parent::registerContainerConfiguration($loader);

        $loader->load(static function (ContainerBuilder $container): void {
            $container->loadFromExtension('framework', [
                'test' => true,
                'profiler' => ['enabled' => false],
                'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
            ]);

            // Registered like a project would: autoconfigure tags it as config provider
            $container->register(SiteAuthConfigProvider::class)->setAutoconfigured(true);
        });
    }
}
