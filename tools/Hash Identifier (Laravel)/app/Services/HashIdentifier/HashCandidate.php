<?php

declare(strict_types=1);

namespace App\Services\HashIdentifier;

/**
 * One possible identification of a hash string.
 *
 * A `readonly class` makes every instance immutable — a detection result should
 * never be mutated after it is produced — mirroring the Python tool's
 * `@dataclass(frozen=True)` value object.
 */
final readonly class HashCandidate
{
    /**
     * @param  string  $algorithm  Human-readable algorithm name, e.g. "MD5" or "bcrypt".
     * @param  string  $confidence  How sure the detector is: "high" (definitive prefix or
     *                              shape), "medium" (most likely candidate for a length), or
     *                              "low" (plausible but ambiguous).
     * @param  string  $reason  Short explanation of why this candidate fired.
     */
    public function __construct(
        public string $algorithm,
        public string $confidence,
        public string $reason,
    ) {}
}
