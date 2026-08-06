<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\SecurityFilters;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\SecurityFilters\Infrastructure\Http\Stages\ApiRateLimitStage;
use Plugins\SecurityFilters\Infrastructure\Http\Stages\ShieldStage;

/**
 * Regression cover for S-03 (rate-limit key trusted a client-controlled header)
 * and S-17 (Shield prefix matching was boundary-unaware and case-sensitive).
 */
#[CoversClass(ShieldStage::class)]
#[CoversClass(ApiRateLimitStage::class)]
final class ShieldAndRateLimitSecurityTest extends TestCase
{
    // ── S-17 ────────────────────────────────────────────────────────────────

    private function prefixMatches(string $path, string $prefix): bool
    {
        $m = new \ReflectionMethod(ShieldStage::class, 'pathMatchesPrefix');

        return (bool) $m->invoke(null, strtolower($path), $prefix);
    }

    /** @return list<array{string,string,bool}> */
    public static function prefixCases(): array
    {
        return [
            // path, prefix, should match
            ['/admin',                   '/admin', true],
            ['/admin/users',             '/admin', true],
            ['/admin/users/1',           '/admin', true],
            // The bypass: a longer, unrelated path that merely SHARES the prefix.
            ['/administrators-public',   '/admin', false],
            ['/adminsecrets',            '/admin', false],
            // Case: this used to sail through unguarded.
            ['/Admin/users',             '/admin', true],
            ['/ADMIN',                   '/admin', true],
            // Trailing slash on the rule must not change the meaning.
            ['/admin/users',             '/admin/', true],
            ['/other',                   '/admin', false],
        ];
    }

    #[DataProvider('prefixCases')]
    public function test_prefix_matching_respects_segment_boundaries_and_case(
        string $path,
        string $prefix,
        bool $expected,
    ): void {
        self::assertSame($expected, $this->prefixMatches($path, $prefix));
    }

    public function test_a_bare_slash_rule_guards_everything(): void
    {
        self::assertTrue($this->prefixMatches('/anything/at/all', '/'));
    }

    // ── S-03 ────────────────────────────────────────────────────────────────

    private function identityFor(Request $request): string
    {
        $m = new \ReflectionMethod(ApiRateLimitStage::class, 'resolveIdentity');

        return (string) $m->invoke(new ApiRateLimitStage(), $request);
    }

    public function test_rate_limit_key_ignores_the_client_supplied_forwarded_header(): void
    {
        // Rotating X-Forwarded-For used to hand out a fresh bucket per request,
        // defeating every per-IP throttle including login and password reset.
        $a = $this->identityFor(
            Request::build(method: 'POST', path: '/auth/login')
                ->withHeader('X-Forwarded-For', '1.1.1.1')
                ->withAttribute('client_ip', '203.0.113.9'),
        );
        $b = $this->identityFor(
            Request::build(method: 'POST', path: '/auth/login')
                ->withHeader('X-Forwarded-For', '2.2.2.2')
                ->withAttribute('client_ip', '203.0.113.9'),
        );

        self::assertSame($a, $b, 'the same real client must share one bucket');
        self::assertStringContainsString('203.0.113.9', $a);
        self::assertStringNotContainsString('1.1.1.1', $a);
    }

    public function test_distinct_clients_still_get_distinct_buckets(): void
    {
        $a = $this->identityFor(Request::build(method: 'GET', path: '/x')->withAttribute('client_ip', '198.51.100.1'));
        $b = $this->identityFor(Request::build(method: 'GET', path: '/x')->withAttribute('client_ip', '198.51.100.2'));

        self::assertNotSame($a, $b);
    }

    public function test_an_unknown_client_falls_back_rather_than_erroring(): void
    {
        self::assertSame('ip_unknown', $this->identityFor(Request::build(method: 'GET', path: '/x')));
    }
}
