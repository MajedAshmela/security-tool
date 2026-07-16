<?php

declare(strict_types=1);

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
