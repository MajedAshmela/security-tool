<?php

declare(strict_types=1);

use App\Http\Requests\IdentifyHashesRequest;

it('identifies a single hash and returns it as JSON', function () {
    $this->postJson('/api/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99'])
        ->assertOk()
        ->assertJson([
            'results' => [
                [
                    'hash' => '5f4dcc3b5aa765d61d8327deb882cf99',
                    'candidates' => [
                        ['algorithm' => 'MD5', 'confidence' => 'medium', 'mode' => '0', 'reason' => 'hex length match'],
                    ],
                ],
            ],
        ]);
});

it('identifies a batch of hashes, one per line', function () {
    $input = "5f4dcc3b5aa765d61d8327deb882cf99\n\$2b\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    $response = $this->postJson('/api/identify', ['hashes' => $input])->assertOk();

    expect($response->json('results'))->toHaveCount(2)
        ->and($response->json('results.0.candidates.0.algorithm'))->toBe('MD5')
        ->and($response->json('results.1.candidates.0.algorithm'))->toBe('bcrypt');
});

it('returns an empty result set for empty input', function () {
    $this->postJson('/api/identify', ['hashes' => ''])
        ->assertOk()
        ->assertExactJson(['results' => []]);
});

it('returns a validation error as JSON when input exceeds the maximum length', function () {
    $tooLong = str_repeat('a', IdentifyHashesRequest::MAX_INPUT_LENGTH + 1);

    $this->postJson('/api/identify', ['hashes' => $tooLong])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('hashes');
});

it('is not subject to CSRF protection', function () {
    // No @csrf token is sent; the API route group must not require one.
    $this->post('/api/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99'], ['Accept' => 'application/json'])
        ->assertOk();
});
