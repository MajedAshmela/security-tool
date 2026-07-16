<?php

declare(strict_types=1);

namespace App\Services\HashIdentifier;

/**
 * Inspects a string and guesses which hashing algorithm (or hash-like format)
 * produced it. Identification is purely structural — it looks at the prefix,
 * length, and character set of the input; it never tries to reverse or crack
 * the hash.
 *
 * Detection strategy, tried in order by {@see identify()}:
 *   1. Known prefix        (e.g. `$2b$` -> bcrypt)             -> high
 *   2. Special fixed shapes (NetNTLMv1/v2, MySQL5, DES-Crypt)  -> high/medium
 *   3. Hex length          (e.g. 32 hex chars -> MD5/NTLM/...) -> medium/low
 *   4. Generic PHC string   (`$name$...` with no rule)         -> low
 *   5. Non-hash shape hints  (JWT, Base64)                     -> low
 *
 * Detection rules live in `rules.json`, loaded through {@see RuleRepository},
 * so new algorithms can be added without touching this code.
 */
final class HashIdentifier
{
    /** Sort order for confidence levels (highest first). */
    public const CONFIDENCE_RANK = ['high' => 0, 'medium' => 1, 'low' => 2];

    public function __construct(private readonly RuleRepository $rules) {}

    /**
     * Identify the hash type(s) of `$text` by trying each detector in order.
     *
     * Returns as soon as one detector produces a result. The return value is
     * always an array — it may contain several candidates (ambiguous hex
     * lengths) or be empty if nothing matched — so callers never have to
     * type-check it.
     *
     * @return list<HashCandidate>
     */
    public function identify(string $text): array
    {
        if (($result = $this->detectByPrefix($text)) !== null) {
            return [$result];
        }

        if (($result = $this->detectSpecial($text)) !== null) {
            return [$result];
        }

        if (($results = $this->detectByHexLength($text)) !== []) {
            return $results;
        }

        if (($result = $this->detectGenericPhc($text)) !== null) {
            return [$result];
        }

        if (($result = $this->detectShapeHint($text)) !== null) {
            return [$result];
        }

        return [];
    }

    /** Return the hashcat `-m` mode for an algorithm, or "-" if unknown. */
    public function hashcatModeFor(string $algorithm): string
    {
        return $this->rules->hashcatModeFor($algorithm);
    }

    /**
     * Sort candidates by confidence, highest first (stable for equal ranks).
     *
     * @param  list<HashCandidate>  $candidates
     * @return list<HashCandidate>
     */
    public static function sortByConfidence(array $candidates): array
    {
        usort(
            $candidates,
            fn (HashCandidate $a, HashCandidate $b): int => self::CONFIDENCE_RANK[$a->confidence] <=> self::CONFIDENCE_RANK[$b->confidence],
        );

        return $candidates;
    }

    /**
     * Identify a hash by matching a known leading prefix (strongest signal).
     *
     * Returns a candidate for the first prefix `$text` starts with. If the rule
     * defines a `min_length` and the input is shorter, the confidence is
     * downgraded to "low" rather than blindly trusting the prefix.
     */
    private function detectByPrefix(string $text): ?HashCandidate
    {
        foreach ($this->rules->prefixRules() as $prefix => $rule) {
            $prefix = (string) $prefix;
            if (! str_starts_with($text, $prefix)) {
                continue;
            }

            $confidence = $rule['confidence'];
            $reason = "matched prefix '{$prefix}'";
            $minLength = $rule['min_length'] ?? null;
            if ($minLength && strlen($text) < $minLength) {
                $confidence = 'low';
                $reason .= ', but length '.strlen($text)." is shorter than the expected minimum {$minLength}";
            }

            return new HashCandidate($rule['algorithm'], $confidence, $reason);
        }

        return null;
    }

    /**
     * Identify fixed-shape formats that have no prefix and aren't plain hex:
     * NetNTLMv1/v2, MySQL5, and DES-Crypt. Checked before the generic
     * hex-length step because their shapes are specific enough to trust.
     */
    private function detectSpecial(string $text): ?HashCandidate
    {
        if ($this->isNetNtlmV1($text)) {
            return new HashCandidate('NetNTLMv1', 'high', 'special shape (LM+NT response, 16-hex challenge)');
        }

        if ($this->isNetNtlmV2($text)) {
            return new HashCandidate('NetNTLMv2', 'high', 'special shape (16-hex challenge, 32-hex HMAC, blob)');
        }

        if ($this->isMysql5($text)) {
            return new HashCandidate('MySQL5', 'high', 'special shape');
        }

        if ($this->isDesCrypt($text)) {
            return new HashCandidate('DES-Crypt', 'medium', 'special shape');
        }

        return null;
    }

    /**
     * Identify a raw hex hash by how many hex characters it has.
     *
     * The first algorithm listed for a length (the most common one) gets
     * "medium" confidence; the rest get "low".
     *
     * @return list<HashCandidate>
     */
    private function detectByHexLength(string $text): array
    {
        $hexRules = $this->rules->hexRules();
        $length = (string) strlen($text);

        if (! $this->isHex($text) || ! array_key_exists($length, $hexRules)) {
            return [];
        }

        $results = [];
        foreach (array_values($hexRules[$length]) as $i => $algorithm) {
            $results[] = new HashCandidate($algorithm, $i === 0 ? 'medium' : 'low', 'hex length match');
        }

        return $results;
    }

    /**
     * Recognize a PHC-style `$name$...` string we have no specific rule for.
     * Reported as generic "PHC" at low confidence — better than a silent miss.
     */
    private function detectGenericPhc(string $text): ?HashCandidate
    {
        if (str_starts_with($text, '$') && count(explode('$', $text)) >= 3) {
            return new HashCandidate('PHC', 'low', 'PHC-like format, unknown algorithm');
        }

        return null;
    }

    /**
     * Flag common non-hash inputs users paste by mistake: JWTs (start with
     * `eyJ`) and Base64 blobs. Both reported at low confidence.
     */
    private function detectShapeHint(string $text): ?HashCandidate
    {
        if (str_starts_with($text, 'eyJ')) {
            return new HashCandidate('JWT', 'low', 'looks like a JWT, not a hash');
        }

        if (strlen($text) % 4 === 0 && preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $text) === 1) {
            return new HashCandidate('Base64', 'low', 'looks like Base64, not a hash');
        }

        return null;
    }

    /** True if `$text` is a non-empty string of only hex digits (0-9a-fA-F). */
    private function isHex(string $text): bool
    {
        return preg_match('/^[0-9a-fA-F]+$/', $text) === 1;
    }

    /**
     * True if `$text` matches the MySQL5 format: a leading `*` followed by 40
     * UPPERCASE hex digits (41 chars total). The case check is intentional —
     * real MySQL5 output is uppercase, so a lowercase look-alike is rejected.
     */
    private function isMysql5(string $text): bool
    {
        return str_starts_with($text, '*')
            && strlen($text) === 41
            && preg_match('/^[0-9A-F]+$/', substr($text, 1)) === 1;
    }

    /**
     * Return the 6 colon-separated fields shared by both NetNTLM versions
     * (`user::domain:field3:field4:field5`), or null if the shape doesn't match.
     *
     * @return list<string>|null
     */
    private function netNtlmParts(string $text): ?array
    {
        $parts = explode(':', $text);
        if (count($parts) !== 6 || $parts[1] !== '') {
            return null;
        }

        return $parts;
    }

    /**
     * True for a NetNTLMv1 record: `user::domain:LM:NT:challenge` where LM and
     * NT are 48 hex chars each and the challenge is 16 hex chars.
     */
    private function isNetNtlmV1(string $text): bool
    {
        $parts = $this->netNtlmParts($text);
        if ($parts === null) {
            return false;
        }

        [$lm, $nt, $challenge] = [$parts[3], $parts[4], $parts[5]];

        return strlen($lm) === 48 && $this->isHex($lm)
            && strlen($nt) === 48 && $this->isHex($nt)
            && strlen($challenge) === 16 && $this->isHex($challenge);
    }

    /**
     * True for a NetNTLMv2 record: `user::domain:challenge:HMAC:blob` where the
     * challenge is 16 hex chars, the HMAC is exactly 32 hex chars, and the blob
     * is >= 40 hex chars. The 32-hex HMAC distinguishes v2 from v1.
     */
    private function isNetNtlmV2(string $text): bool
    {
        $parts = $this->netNtlmParts($text);
        if ($parts === null) {
            return false;
        }

        [$challenge, $hmac, $blob] = [$parts[3], $parts[4], $parts[5]];

        return strlen($challenge) === 16 && $this->isHex($challenge)
            && strlen($hmac) === 32 && $this->isHex($hmac)
            && strlen($blob) >= 40 && $this->isHex($blob);
    }

    /**
     * True if `$text` looks like a traditional 13-char DES-Crypt hash: exactly
     * 13 characters from the `./0-9A-Za-z` alphabet.
     */
    private function isDesCrypt(string $text): bool
    {
        return preg_match('#^[./0-9a-zA-Z]{13}$#', $text) === 1;
    }
}
