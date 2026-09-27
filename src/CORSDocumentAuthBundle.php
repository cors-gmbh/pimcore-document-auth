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

namespace CORS\Bundle\DocumentAuthBundle;

use Pimcore\Extension\Bundle\AbstractPimcoreBundle;

final class CORSDocumentAuthBundle extends AbstractPimcoreBundle
{
    public function getNiceName(): string
    {
        return 'CORS - Document Auth Bundle';
    }

    public function getDescription(): string
    {
        return 'CORS Document Auth Bundle';
    }
}
