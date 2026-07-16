<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\HashIdentifier\HashIdentifier;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Web front-end to the hash identifier.
 *
 * `index()` shows the form; `identify()` runs the shared detection engine over
 * one or more pasted hashes (one per line, matching the CLI's `--file` mode)
 * and renders the results as an HTML table. All detection logic lives in
 * {@see HashIdentifier}; this controller only marshals input and shapes the
 * results for the view.
 */
final class HashIdentifierController extends Controller
{
    public function index(): View
    {
        return view('hash-identifier', ['input' => '', 'groups' => null]);
    }

    public function identify(Request $request, HashIdentifier $identifier): View
    {
        $input = (string) $request->input('hashes', '');

        // One hash per non-blank line, whitespace stripped — the same rule the
        // CLI applies when reading a --file.
        $lines = preg_split('/\R/', $input) ?: [];
        $hashes = array_values(array_filter(array_map('trim', $lines), fn (string $l): bool => $l !== ''));

        $groups = array_map(function (string $hash) use ($identifier): array {
            $candidates = HashIdentifier::sortByConfidence($identifier->identify($hash));

            $rows = array_map(fn ($c): array => [
                'algorithm' => $c->algorithm,
                'confidence' => $c->confidence,
                'mode' => $identifier->hashcatModeFor($c->algorithm),
                'reason' => $c->reason,
            ], $candidates);

            return ['hash' => $hash, 'rows' => $rows];
        }, $hashes);

        return view('hash-identifier', ['input' => $input, 'groups' => $groups]);
    }
}
