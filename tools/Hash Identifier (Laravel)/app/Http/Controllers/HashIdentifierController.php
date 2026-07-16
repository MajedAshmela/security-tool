<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Requests\IdentifyHashesRequest;
use App\Services\HashIdentifier\HashIdentifier;
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

    public function identify(IdentifyHashesRequest $request, HashIdentifier $identifier): View
    {
        // Only the pasted text is echoed back into the textarea; an uploaded
        // file's lines are merged into $hashes but not redisplayed.
        $input = (string) $request->validated('hashes', '');
        $hashes = $request->allLines();

        $groups = array_map(function (string $hash) use ($identifier): array {
            $candidates = HashIdentifier::sortByConfidence($identifier->identify($hash));
            $rows = array_map($identifier->toRow(...), $candidates);

            return ['hash' => $hash, 'rows' => $rows];
        }, $hashes);

        $summary = ['high' => 0, 'medium' => 0, 'low' => 0, 'unmatched' => 0];
        foreach ($groups as $group) {
            $summary[$group['rows'][0]['confidence'] ?? 'unmatched']++;
        }

        return view('hash-identifier', ['input' => $input, 'groups' => $groups, 'summary' => $summary]);
    }
}
