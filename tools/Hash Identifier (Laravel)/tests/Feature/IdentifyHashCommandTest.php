<?php

declare(strict_types=1);

it('prints a table identifying a single hash', function () {
    $this->artisan('hash:identify', ['hash' => '5f4dcc3b5aa765d61d8327deb882cf99', '--no-color' => true])
        ->expectsOutputToContain('MD5')
        ->expectsOutputToContain('Hashcat Mode')
        ->assertExitCode(0);
});

it('errors when neither a hash nor --file is given', function () {
    $this->artisan('hash:identify')
        ->expectsOutputToContain('provide a hash')
        ->assertExitCode(2);
});

it('errors when both a hash and --file are given', function () {
    $this->artisan('hash:identify', ['hash' => 'deadbeef', '--file' => 'whatever.txt'])
        ->expectsOutputToContain('not both')
        ->assertExitCode(2);
});

it('errors when the --file path does not exist', function () {
    $this->artisan('hash:identify', ['--file' => 'definitely-missing-file.txt'])
        ->expectsOutputToContain('file not found')
        ->assertExitCode(2);
});

it('writes result.txt next to the input file in --file mode and prints nothing', function () {
    $dir = sys_get_temp_dir().DIRECTORY_SEPARATOR.'hashid_'.uniqid();
    mkdir($dir);
    $input = $dir.DIRECTORY_SEPARATOR.'hashes.txt';
    file_put_contents($input, "5f4dcc3b5aa765d61d8327deb882cf99\n\$2b\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW\n");

    $this->artisan('hash:identify', ['--file' => $input])->assertExitCode(0);

    $result = $dir.DIRECTORY_SEPARATOR.'result.txt';
    expect(is_file($result))->toBeTrue();

    $contents = file_get_contents($result);
    expect($contents)->toContain('MD5')
        ->and($contents)->toContain('bcrypt')
        ->and($contents)->toContain('Hash Identification Results');

    // Clean up.
    @unlink($input);
    @unlink($result);
    @rmdir($dir);
});

it('honors --output to redirect a single hash to a file', function () {
    $out = sys_get_temp_dir().DIRECTORY_SEPARATOR.'out_'.uniqid().'.txt';

    $this->artisan('hash:identify', ['hash' => '5f4dcc3b5aa765d61d8327deb882cf99', '--output' => $out])
        ->assertExitCode(0);

    expect(is_file($out))->toBeTrue()
        ->and(file_get_contents($out))->toContain('MD5');

    @unlink($out);
});
