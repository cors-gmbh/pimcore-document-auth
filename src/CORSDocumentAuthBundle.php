<?php

declare(strict_types=1);

/*
 * CORS GmbH
 *
 * This source file is available under two different licenses:
 *  *  - GNU General Public License version 3 (GPLv3) for Pimcore 10 and 11
 *  *  - MIT License (MIT) for Pimcore 12 and later
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
