<?php

declare(strict_types=1);

namespace App\Services\HashIdentifier;

use RuntimeException;

/**
 * Thrown when the detection rules file is missing, is not valid JSON, or fails
 * structural validation.
 *
 * The Python tool aborted the process with `SystemExit` on a malformed rules
 * file. In a framework we instead raise a typed exception so the caller (the
 * artisan command or the web layer) can decide how to surface it, while still
 * failing loudly with a clear message instead of a confusing error deep inside
 * detection.
 */
final class RuleValidationException extends RuntimeException {}
