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
use CORS\Bundle\DocumentAuthBundle\Security\DocumentUser;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class CORSDocumentAuthExtension extends Extension implements PrependExtensionInterface
{
    /**
     * Predefined document properties, so editors can pick them in the properties tab.
     */
    // Pimcore Studio requires creation and modification date for every predefined property
    private const int PREDEFINED_PROPERTIES_DATE = 1790467200;

    public const array PREDEFINED_PROPERTIES = [
        'cors_document_auth_enabled' => [
            'name' => 'Document Auth: enabled',
            'description' => 'Protects the document (and its children) with username and password',
            'key' => 'password_enabled',
            'type' => 'bool',
            'data' => '1',
            'ctype' => 'document',
            'inheritable' => true,
        ],
        'cors_document_auth_username' => [
            'name' => 'Document Auth: username',
            'description' => 'Username for the protected document',
            'key' => 'password_username',
            'type' => 'text',
            'ctype' => 'document',
            'inheritable' => true,
        ],
        'cors_document_auth_password' => [
            'name' => 'Document Auth: password',
            'description' => 'Password for the protected document (raw text)',
            'key' => 'password_password',
            'type' => 'text',
            'ctype' => 'document',
            'inheritable' => true,
        ],
        'cors_document_auth_mode' => [
            'name' => 'Document Auth: login mode',
            'description' => 'basic = browser login dialog, form = login page; empty uses the configured default',
            'key' => DocumentAuthenticator::MODE_PROPERTY,
            'type' => 'select',
            'config' => DocumentAuthenticator::MODE_BASIC . ',' . DocumentAuthenticator::MODE_FORM,
            'ctype' => 'document',
            'inheritable' => true,
        ],
        'cors_document_auth_template' => [
            'name' => 'Document Auth: login template',
            'description' => 'Twig template of the login page (mode form), e.g. document-auth/customer.html.twig',
            'key' => DocumentAuthenticator::TEMPLATE_PROPERTY,
            'type' => 'text',
            'ctype' => 'document',
            'inheritable' => true,
        ],
    ];

    public function load(array $configs, ContainerBuilder $container): void
    {
        /**
         * @var array{mode: string, realm: string, form: array{template: string, csrf_protection: bool}} $config
         */
        $config = $this->processConfiguration(new Configuration(), $configs);

        $container->setParameter('cors_document_auth.mode', $config['mode']);
        $container->setParameter('cors_document_auth.realm', $config['realm']);
        $container->setParameter('cors_document_auth.form.template', $config['form']['template']);
        $container->setParameter('cors_document_auth.form.csrf_protection', $config['form']['csrf_protection']);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }

    public function prepend(ContainerBuilder $container): void
    {
        // Document passwords are stored as raw text in the document properties
        $container->prependExtensionConfig('security', [
            'password_hashers' => [
                DocumentUser::PASSWORD_HASHER => ['algorithm' => 'plaintext'],
            ],
        ]);

        $container->prependExtensionConfig('pimcore', [
            'properties' => [
                'predefined' => [
                    'definitions' => array_map(
                        static fn (array $definition): array => $definition + [
                            'creationDate' => self::PREDEFINED_PROPERTIES_DATE,
                            'modificationDate' => self::PREDEFINED_PROPERTIES_DATE,
                        ],
                        self::PREDEFINED_PROPERTIES,
                    ),
                ],
            ],
        ]);
    }
}
