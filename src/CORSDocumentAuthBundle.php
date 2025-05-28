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

namespace CORS\Bundle\DocumentAuthBundle;

use Pimcore\Extension\Bundle\AbstractPimcoreBundle;

class CORSDocumentAuthBundle extends AbstractPimcoreBundle
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
