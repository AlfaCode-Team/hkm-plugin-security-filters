<?php

declare(strict_types=1);

namespace Plugins\SecurityFilters\Infrastructure\Http\Stages;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\Contracts\HttpStageContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Routing\UrlGenerator;

/**
 * Enforces the kernel's SIGNED-URL contract on a route, declaratively.
 *
 *     { "method": "GET", "path": "/verify/{id:num}", "handler": "…@verify",
 *       "filters": ["signed"] }
 *
 * The kernel could already MINT signed URLs (`UrlGenerator::signedRoute()`) and
 * CHECK them (`hasValidSignature()`), but checking was a manual call every
 * controller had to remember to make — and forgetting it looks exactly like
 * working code. As a filter, the enforcement is declared next to the route it
 * protects and cannot be forgotten.
 *
 * This is the URL-signature counterpart to {@see HmacSignedStage}, which signs
 * an API REQUEST (method + path + timestamp + body via headers). Use `signed`
 * for links you hand to a person — email verification, one-time actions,
 * unsubscribe endpoints; use `hmac` for machine-to-machine calls.
 *
 * FAIL-CLOSED. A missing or empty APP_KEY makes `hasValidSignature()` return
 * false for everything, so a misconfigured deployment rejects these links rather
 * than accepting forgeries. Expiry, when the link carries one, is covered by the
 * same signature and is checked by the generator.
 *
 * Only the PATH and QUERY are signed — never the host. A proxy that rewrites the
 * Host header would otherwise invalidate every link it forwards.
 */
final class SignedUrlStage implements HttpStageContract
{
    /** Built once per worker; it reads the compiled route-name index, not the route table. */
    private ?UrlGenerator $urls = null;

    public function handle(Request $request, callable $next): Response
    {
        $query = $request->server('QUERY_STRING');
        $url   = $request->path() . (is_string($query) && $query !== '' ? '?' . $query : '');

        if (!$this->urls()->hasValidSignature($url)) {
            return Response::forbidden('This link is invalid or has expired.');
        }

        return $next($request);
    }

    private function urls(): UrlGenerator
    {
        return $this->urls ??= UrlGenerator::fromManifest();
    }
}
