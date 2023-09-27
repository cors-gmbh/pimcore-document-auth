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
use Pimcore\Http\RequestHelper;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

class RequestMatcher implements RequestMatcherInterface
{
    protected $documentResolver;
    protected $requestHelper;

    public function __construct(DocumentResolver $documentResolver, RequestHelper $requestHelper)
    {
        $this->documentResolver = $documentResolver;
        $this->requestHelper = $requestHelper;
    }

    public function matches(Request $request)
    {
        if ($this->requestHelper->isFrontendRequestByAdmin($request)) {
            return false;
        }

        try {
            $document = $this->documentResolver->getDocument($request);

            if (!$document) {
                return false;
            }

            if ($document->getProperty('password_enabled')) {
                return true;
            }
        } catch (\Exception $exception) {
            //Ignore and return false
        }

        return false;
    }
}
