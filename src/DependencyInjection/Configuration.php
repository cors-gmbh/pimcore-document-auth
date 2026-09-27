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

namespace CORS\Bundle\DocumentAuthBundle\DependencyInjection;

use CORS\Bundle\DocumentAuthBundle\Security\DocumentAuthenticator;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('cors_document_auth');

        $treeBuilder->getRootNode()
            ->children()
                ->enumNode('mode')
                    ->info('Default mode, overridable per document with the property "password_mode": "basic" uses HTTP basic auth, "form" renders a login form on the protected document')
                    ->values([DocumentAuthenticator::MODE_BASIC, DocumentAuthenticator::MODE_FORM])
                    ->defaultValue(DocumentAuthenticator::MODE_BASIC)
                ->end()
                ->scalarNode('realm')
                    ->info('Realm of the HTTP basic auth challenge (mode "basic")')
                    ->defaultValue('Site')
                ->end()
                ->arrayNode('form')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('template')
                            ->info('Twig template of the login form (mode "form")')
                            ->defaultValue('@CORSDocumentAuth/login.html.twig')
                        ->end()
                        ->booleanNode('csrf_protection')
                            ->info('Requires framework.csrf_protection to be enabled')
                            ->defaultTrue()
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
