<?php

declare(strict_types=1);

use App\Services\HashIdentifier\HashCandidate;
use App\Services\HashIdentifier\HashIdentifier;
use App\Services\HashIdentifier\RuleRepository;
use App\Services\HashIdentifier\RuleValidationException;

/** Detection engine backed by the real resources/rules.json. */
function hashId(): HashIdentifier
{
    return new HashIdentifier(new RuleRepository);
}

/** Write a throwaway rules file and return its path. */
function tempRules(string $json): string
{
    $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'rules_'.uniqid().'.json';
    file_put_contents($path, $json);

    return $path;
}

// ---------------------------------------------------------------------------
// HashCandidate value object
// ---------------------------------------------------------------------------

it('is an immutable value object', function () {
    $candidate = new HashCandidate('MD5', 'medium', 'hex length match');

    expect($candidate->algorithm)->toBe('MD5')
        ->and($candidate->confidence)->toBe('medium')
        ->and($candidate->reason)->toBe('hex length match');

    expect(fn () => $candidate->algorithm = 'SHA-1')->toThrow(Error::class);
});

// ---------------------------------------------------------------------------
// Prefix rules
// ---------------------------------------------------------------------------

it('identifies bcrypt by prefix at high confidence', function () {
    $result = hashId()->identify('$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW');

    expect($result)->toHaveCount(1)
        ->and($result[0]->algorithm)->toBe('bcrypt')
        ->and($result[0]->confidence)->toBe('high')
        ->and($result[0]->reason)->toContain("matched prefix '\$2b\$'");
});

it('identifies the older $2y$ bcrypt variant as bcrypt', function () {
    $result = hashId()->identify('$2y$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW');

    expect($result)->toHaveCount(1)
        ->and($result[0]->algorithm)->toBe('bcrypt')
        ->and($result[0]->confidence)->toBe('high');
});

it('identifies yescrypt by its $y$ prefix, distinct from bcrypt', function () {
    $result = hashId()->identify('$y$j9T$5RS9ML0kEsQzGgnFtQGiF0$3eNTsAdEfwF9SPZR6RQmYhV1234567890abcd');

    expect($result)->toHaveCount(1)
        ->and($result[0]->algorithm)->toBe('yescrypt')
        ->and($result[0]->confidence)->toBe('high');
});

it('identifies Argon2id, Kerberoast and AS-REP by prefix', function () {
    expect(hashId()->identify('$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA')[0]->algorithm)->toBe('Argon2id');
    expect(hashId()->identify('$krb5tgs$23$*user$realm*$abcd1234')[0]->algorithm)->toBe('Kerberoast-TGS-RC4');
    expect(hashId()->identify('$krb5asrep$23$user@realm:abcd1234')[0]->algorithm)->toBe('AS-REP-Roast-RC4');
});

it('downgrades a prefix match below its min_length to low', function () {
    $result = hashId()->identify('$2b$short');

    expect($result[0]->algorithm)->toBe('bcrypt')
        ->and($result[0]->confidence)->toBe('low')
        ->and($result[0]->reason)->toContain('shorter than the expected minimum 60');
});

it('is self-consistent for every prefix rule in rules.json', function () {
    $rules = (new RuleRepository)->prefixRules();

    foreach ($rules as $prefix => $rule) {
        $prefix = (string) $prefix;
        $minLength = $rule['min_length'] ?? 0;
        $sample = $prefix.str_repeat('a', max(0, $minLength - strlen($prefix)));

        $result = hashId()->identify($sample);

        expect($result)->not->toBeEmpty("prefix {$prefix} produced no candidate");
        expect($result[0]->algorithm)->toBe($rule['algorithm'], "prefix {$prefix} misclassified");
        expect($result[0]->confidence)->toBe($rule['confidence'], "prefix {$prefix} wrong confidence");
    }
});

// ---------------------------------------------------------------------------
// Special shapes
// ---------------------------------------------------------------------------

it('identifies NetNTLMv1 and NetNTLMv2 by their distinct shapes', function () {
    $v1 = 'u4-netntlm::kNS:333333333333333333333333333333333333333333333333:999999999999999999999999999999999999999999999999:1111111111111111';
    $v2 = 'admin::N46iSNekpT:0000000000000000:88888888888888888888888888888888:55555555555555555555555555555555555555555555';

    expect(hashId()->identify($v1)[0]->algorithm)->toBe('NetNTLMv1');
    expect(hashId()->identify($v1)[0]->confidence)->toBe('high');
    expect(hashId()->identify($v2)[0]->algorithm)->toBe('NetNTLMv2');
    expect(hashId()->identify($v2)[0]->confidence)->toBe('high');
});

it('accepts uppercase MySQL5 but rejects a lowercase look-alike', function () {
    $upper = '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';
    $lower = '*2470c0c06dee42fd1618bb99005adca2ec9d1e19';

    expect(hashId()->identify($upper)[0]->algorithm)->toBe('MySQL5');
    // The lowercase form is not a valid MySQL5; it falls through to no match.
    expect(hashId()->identify($lower))->toBeEmpty();
});

it('identifies a 13-char DES-Crypt at medium confidence', function () {
    $result = hashId()->identify('abcdefghijklm');

    expect($result[0]->algorithm)->toBe('DES-Crypt')
        ->and($result[0]->confidence)->toBe('medium');
});

// ---------------------------------------------------------------------------
// Hex length
// ---------------------------------------------------------------------------

it('ranks MD5 first for a 32-hex string, then lower-confidence peers', function () {
    $result = hashId()->identify('5f4dcc3b5aa765d61d8327deb882cf99');

    expect($result[0]->algorithm)->toBe('MD5')
        ->and($result[0]->confidence)->toBe('medium');

    $algorithms = array_map(fn (HashCandidate $c) => $c->algorithm, $result);
    expect($algorithms)->toBe(['MD5', 'NTLM', 'MD4', 'RIPEMD-128', 'LM']);

    // Every candidate after the first is low confidence.
    foreach (array_slice($result, 1) as $candidate) {
        expect($candidate->confidence)->toBe('low');
    }
});

it('ranks SHA-256 first for a 64-hex string', function () {
    $result = hashId()->identify('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');

    expect($result[0]->algorithm)->toBe('SHA-256')
        ->and($result[0]->confidence)->toBe('medium');
});

it('does not match a 32-char non-hex string via the hex path', function () {
    // 32 chars, but the '-' makes it neither hex nor Base64, so no detector fires.
    expect(hashId()->identify(str_repeat('z', 31).'-'))->toBeEmpty();
});

// ---------------------------------------------------------------------------
// Fallbacks and shape hints
// ---------------------------------------------------------------------------

it('flags a generic PHC string, a JWT, and Base64 at low confidence', function () {
    expect(hashId()->identify('$unknownalgo$v=1$c29tZXNhbHQ$c29tZWhhc2g')[0]->algorithm)->toBe('PHC');
    expect(hashId()->identify('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc')[0]->algorithm)->toBe('JWT');
    expect(hashId()->identify('SGVsbG9Xb3JsZEJhc2U2NA==')[0]->algorithm)->toBe('Base64');

    foreach (['$unknownalgo$v=1$c29tZXNhbHQ$c29tZWhhc2g', 'eyJhbGciOiJIUzI1NiJ9.a.b', 'SGVsbG9Xb3JsZEJhc2U2NA=='] as $input) {
        expect(hashId()->identify($input)[0]->confidence)->toBe('low');
    }
});

it('returns an empty array for empty or unrecognizable input', function () {
    expect(hashId()->identify(''))->toBe([]);
    expect(hashId()->identify('this-is-not-a-hash-at-all'))->toBe([]);
});

// ---------------------------------------------------------------------------
// Hashcat modes
// ---------------------------------------------------------------------------

it('looks up hashcat modes, returning "-" for unmapped algorithms', function () {
    expect(hashId()->hashcatModeFor('MD5'))->toBe('0');
    expect(hashId()->hashcatModeFor('bcrypt'))->toBe('3200');
    expect(hashId()->hashcatModeFor('MSSQL'))->toBe('131 / 132 / 1731');
    expect(hashId()->hashcatModeFor('RIPEMD-128'))->toBe('-');
    expect(hashId()->hashcatModeFor('Totally-Unknown'))->toBe('-');
});

// ---------------------------------------------------------------------------
// Confidence sorting
// ---------------------------------------------------------------------------

it('sorts candidates highest-confidence first, stably', function () {
    $sorted = HashIdentifier::sortByConfidence([
        new HashCandidate('C', 'low', ''),
        new HashCandidate('B', 'high', ''),
        new HashCandidate('A', 'medium', ''),
        new HashCandidate('D', 'low', ''),
    ]);

    expect(array_map(fn (HashCandidate $c) => $c->algorithm, $sorted))->toBe(['B', 'A', 'C', 'D']);
});

// ---------------------------------------------------------------------------
// Rules-file validation
// ---------------------------------------------------------------------------

it('throws when the rules file does not exist', function () {
    $missing = sys_get_temp_dir().DIRECTORY_SEPARATOR.'nope_'.uniqid().'.json';

    expect(fn () => (new RuleRepository($missing))->prefixRules())
        ->toThrow(RuleValidationException::class, 'rules file not found');
});

it('throws on invalid JSON', function () {
    $path = tempRules('{ this is not json');

    expect(fn () => (new RuleRepository($path))->prefixRules())
        ->toThrow(RuleValidationException::class, 'not valid JSON');
});

it('throws when a required key is missing', function () {
    $path = tempRules('{"hex_rules": {}}');

    expect(fn () => (new RuleRepository($path))->prefixRules())
        ->toThrow(RuleValidationException::class, "missing required key 'prefix_rules'");
});

it('throws on an invalid confidence value', function () {
    $path = tempRules('{"prefix_rules": {"$x$": {"algorithm": "X", "confidence": "bogus"}}, "hex_rules": {}}');

    expect(fn () => (new RuleRepository($path))->prefixRules())
        ->toThrow(RuleValidationException::class, 'invalid confidence');
});

it('throws when a prefix rule is missing its algorithm', function () {
    $path = tempRules('{"prefix_rules": {"$x$": {"confidence": "high"}}, "hex_rules": {}}');

    expect(fn () => (new RuleRepository($path))->prefixRules())
        ->toThrow(RuleValidationException::class, 'missing algorithm');
});

it('throws when hashcat_modes is not an object', function () {
    $path = tempRules('{"prefix_rules": {}, "hex_rules": {}, "hashcat_modes": "nope"}');

    expect(fn () => (new RuleRepository($path))->hashcatModeFor('MD5'))
        ->toThrow(RuleValidationException::class, "invalid 'hashcat_modes'");
});
