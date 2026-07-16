<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

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
        ->expectsOutputToContain('only one of')
        ->assertExitCode(2);
});

it('errors when a hash and --stdin are both given', function () {
    $this->artisan('hash:identify', ['hash' => 'deadbeef', '--stdin' => true])
        ->expectsOutputToContain('only one of')
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

it('prints JSON when --format=json is given', function () {
    // Uses Artisan::call() + Artisan::output() rather than $this->artisan(...)
    // ->expectsOutputToContain(...): that helper's mock only matches one
    // expectation per underlying doWrite() call, and the JSON is written as
    // a single multi-line call, so a second substring check would spuriously
    // fail even though it's genuinely present in the output.
    $exitCode = Artisan::call('hash:identify', ['hash' => '5f4dcc3b5aa765d61d8327deb882cf99', '--format' => 'json']);
    $output = Artisan::output();

    expect($exitCode)->toBe(0)
        ->and($output)->toContain('"algorithm": "MD5"')
        ->and($output)->toContain('"mode": "0"');
});

it('writes JSON to --output when --format=json is given', function () {
    $out = sys_get_temp_dir().DIRECTORY_SEPARATOR.'out_'.uniqid().'.json';

    $this->artisan('hash:identify', ['hash' => '5f4dcc3b5aa765d61d8327deb882cf99', '--format' => 'json', '--output' => $out])
        ->assertExitCode(0);

    $data = json_decode((string) file_get_contents($out), true);
    expect($data['results'][0]['hash'])->toBe('5f4dcc3b5aa765d61d8327deb882cf99')
        ->and($data['results'][0]['candidates'][0]['algorithm'])->toBe('MD5');

    @unlink($out);
});

it('errors on an invalid --format value', function () {
    $this->artisan('hash:identify', ['hash' => 'deadbeef', '--format' => 'xml'])
        ->expectsOutputToContain("invalid --format 'xml'")
        ->assertExitCode(2);
});

it('reads hashes from a real piped stdin when --stdin is given', function () {
    $result = Process::path(base_path())
        ->input("5f4dcc3b5aa765d61d8327deb882cf99\n\$2b\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW\n")
        ->run([PHP_BINARY, 'artisan', 'hash:identify', '--stdin', '--no-color']);

    expect($result->successful())->toBeTrue()
        ->and($result->output())->toContain('MD5')
        ->and($result->output())->toContain('bcrypt');
})->group('subprocess');
