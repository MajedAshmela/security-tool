<?php

declare(strict_types=1);

use App\Http\Requests\IdentifyHashesRequest;
use Illuminate\Http\UploadedFile;

it('shows the form on the home page', function () {
    $this->get('/')
        ->assertOk()
        ->assertSee('Hash Identifier')
        ->assertSee('Identify');
});

it('identifies a single hash and renders its candidates', function () {
    $this->post('/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99'])
        ->assertOk()
        ->assertSee('MD5')
        ->assertSee('medium')   // confidence badge text
        ->assertSee('1000')     // NTLM hashcat mode, a lower-ranked candidate
        ->assertSee('5f4dcc3b5aa765d61d8327deb882cf99'); // hash echoed back
});

it('identifies a batch of hashes, one per line', function () {
    $input = "5f4dcc3b5aa765d61d8327deb882cf99\n\$2b\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";

    $this->post('/identify', ['hashes' => $input])
        ->assertOk()
        ->assertSee('MD5')
        ->assertSee('bcrypt');
});

it('shows an empty-state message when nothing is entered', function () {
    $this->post('/identify', ['hashes' => ''])
        ->assertOk()
        ->assertSee('No hashes entered');
});

it('shows a no-match row for unrecognizable input', function () {
    $this->post('/identify', ['hashes' => 'this-is-not-a-hash-at-all'])
        ->assertOk()
        ->assertSee('No hash type identified');
});

it('escapes hash input to prevent HTML injection', function () {
    $this->post('/identify', ['hashes' => '<script>alert(1)</script>'])
        ->assertOk()
        ->assertDontSee('<script>alert(1)</script>', escape: false)
        ->assertSee('&lt;script&gt;', escape: false);
});

it('rejects input longer than the maximum allowed size', function () {
    $tooLong = str_repeat('a', IdentifyHashesRequest::MAX_INPUT_LENGTH + 1);

    $this->post('/identify', ['hashes' => $tooLong])
        ->assertSessionHasErrors('hashes');
});

it('rejects a batch with more hashes than the maximum allowed', function () {
    $tooMany = implode("\n", array_fill(0, IdentifyHashesRequest::MAX_LINES + 1, '5f4dcc3b5aa765d61d8327deb882cf99'));

    $this->post('/identify', ['hashes' => $tooMany])
        ->assertSessionHasErrors('hashes');
});

it('accepts a batch right at the maximum line count', function () {
    $atLimit = implode("\n", array_fill(0, IdentifyHashesRequest::MAX_LINES, '5f4dcc3b5aa765d61d8327deb882cf99'));

    $this->post('/identify', ['hashes' => $atLimit])
        ->assertOk()
        ->assertSessionDoesntHaveErrors();
});

it('identifies hashes from an uploaded file', function () {
    $file = UploadedFile::fake()->createWithContent('hashes.txt', "5f4dcc3b5aa765d61d8327deb882cf99\n");

    $this->post('/identify', ['hashes' => '', 'file' => $file])
        ->assertOk()
        ->assertSee('MD5');
});

it('merges an uploaded file with pasted hashes', function () {
    $file = UploadedFile::fake()->createWithContent('hashes.txt', "\$2b\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW\n");

    $this->post('/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99', 'file' => $file])
        ->assertOk()
        ->assertSee('MD5')
        ->assertSee('bcrypt');
});

it('rejects an uploaded file combined with pasted hashes over the maximum line count', function () {
    $fileLines = implode("\n", array_fill(0, IdentifyHashesRequest::MAX_LINES, '5f4dcc3b5aa765d61d8327deb882cf99'));
    $file = UploadedFile::fake()->createWithContent('hashes.txt', $fileLines);

    $this->post('/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99', 'file' => $file])
        ->assertSessionHasErrors('hashes');
});

it('throttles repeated submissions from the same client', function () {
    for ($i = 0; $i < 30; $i++) {
        $this->post('/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99'])->assertOk();
    }

    $this->post('/identify', ['hashes' => '5f4dcc3b5aa765d61d8327deb882cf99'])
        ->assertStatus(429);
});
