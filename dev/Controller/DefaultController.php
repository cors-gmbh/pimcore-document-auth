<?php

declare(strict_types=1);

namespace App\Controller;

use Pimcore\Controller\FrontendController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Dev harness only: renders documents so the document auth can be tested in the browser.
 */
final class DefaultController extends FrontendController
{
    public function defaultAction(Request $request): Response
    {
        return $this->render('default/default.html.twig');
    }
}
