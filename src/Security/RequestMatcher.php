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
use Pimcore\Http\RequestHelper;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

final readonly class RequestMatcher implements RequestMatcherInterface
{
    public function __construct(
        private DocumentResolver $documentResolver,
        private RequestHelper $requestHelper,
    ) {
    }

    public function matches(Request $request): bool
    {
        if ($this->requestHelper->isFrontendRequestByAdmin($request)) {
            return false;
        }

        try {
            $document = $this->documentResolver->getDocument($request);
        } catch (\Exception) {
            return false;
        }

        return null !== $document && (bool) $document->getProperty('password_enabled');
    }
}
