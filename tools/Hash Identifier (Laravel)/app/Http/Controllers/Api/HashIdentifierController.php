<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\IdentifyHashesRequest;
use App\Services\HashIdentifier\HashIdentifier;
use Illuminate\Http\JsonResponse;

/**
 * JSON front-end to the hash identifier, for scripts and other tools to
 * integrate with instead of scraping the HTML form. Shares the same
 * {@see IdentifyHashesRequest} validation and {@see HashIdentifier} engine
 * as the web controller and the `hash:identify` Artisan command.
 */
final class HashIdentifierController extends Controller
{
    public function identify(IdentifyHashesRequest $request, HashIdentifier $identifier): JsonResponse
    {
        $groups = array_map(function (string $hash) use ($identifier): array {
            $candidates = HashIdentifier::sortByConfidence($identifier->identify($hash));

            return [
                'hash' => $hash,
                'candidates' => array_map($identifier->toRow(...), $candidates),
            ];
        }, $request->allLines());

        return response()->json(['results' => $groups]);
    }
}
