<?php

declare(strict_types=1);

/*
 * CORS GmbH
 *
 * This software is available under the GNU General Public License version 3 (GPLv3).
 *
 * @copyright  Copyright (c) CORS GmbH (https://www.cors.gmbh)
 * @license    https://www.cors.gmbh/license GPLv3
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

    public function __construct(
        DocumentResolver $documentResolver,
        RequestHelper $requestHelper,
    ) {
        $this->documentResolver = $documentResolver;
        $this->requestHelper = $requestHelper;
    }

    public function matches(Request $request): bool
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
