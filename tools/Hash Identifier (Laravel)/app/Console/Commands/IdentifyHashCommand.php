<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\HashIdentifier\HashIdentifier;
use App\Services\HashIdentifier\RuleValidationException;
use App\Services\HashIdentifier\TableRenderer;
use Illuminate\Console\Command;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Console front-end to the hash identifier — the Laravel equivalent of the
 * Python tool's CLI. Accepts either a single positional hash or `--file`
 * (one hash per line), but not both and not neither.
 *
 * The two input modes default to different destinations, matching the original:
 *   - A single positional hash prints the table to the terminal (colored,
 *     unless `--no-color` or stdout isn't a TTY).
 *   - `--file` writes the table to `result.txt` next to the input file
 *     (uncolored, UTF-8) instead of printing.
 *
 * `--output` overrides the destination file path in either mode.
 */
final class IdentifyHashCommand extends Command
{
    protected $signature = 'hash:identify
        {hash? : A single hash to identify}
        {--file= : Path to a text file with one hash per line}
        {--output= : Write the results table to this file instead of the default destination}
        {--no-color : Disable colored output}';

    protected $description = 'Identify hash types from input text (structural detection).';

    public function handle(HashIdentifier $identifier, TableRenderer $renderer): int
    {
        $hash = $this->argument('hash');
        $file = $this->option('file');

        if ($hash === null && $file === null) {
            $this->error('provide a hash, or use --file to identify multiple hashes.');

            return self::INVALID;
        }

        if ($hash !== null && $file !== null) {
            $this->error('provide either a hash or --file, not both.');

            return self::INVALID;
        }

        try {
            $hashTexts = $this->readHashes($hash, $file);
        } catch (\RuntimeException $e) {
            $this->error($e->getMessage());

            return self::INVALID;
        }

        try {
            $groups = array_map(fn (string $h): array => [$h, $identifier->identify($h)], $hashTexts);

            $outputPath = $this->option('output') ?? ($file !== null ? $this->defaultOutputPath($file) : null);

            if ($outputPath !== null) {
                $lines = $renderer->render($groups, useColor: false, boxEncoding: 'utf-8');
                if (@file_put_contents($outputPath, implode("\n", $lines)."\n") === false) {
                    $this->error("could not write to {$outputPath}");

                    return self::FAILURE;
                }

                return self::SUCCESS;
            }

            $useColor = ! $this->option('no-color') && stream_isatty(STDOUT);
            $lines = $renderer->render($groups, useColor: $useColor);
            $this->getOutput()->writeln($lines, OutputInterface::OUTPUT_RAW);

            return self::SUCCESS;
        } catch (RuleValidationException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
    }

    /**
     * Collect the hash strings to identify.
     *
     * With `--file`, returns one entry per non-blank line (whitespace
     * stripped). Otherwise returns the single positional hash, stripped.
     *
     * @return list<string>
     *
     * @throws \RuntimeException if the `--file` path does not exist.
     */
    private function readHashes(?string $hash, ?string $file): array
    {
        if ($file !== null) {
            if (! is_file($file)) {
                throw new \RuntimeException("file not found: {$file}");
            }

            $lines = preg_split('/\R/', (string) file_get_contents($file)) ?: [];

            return array_values(array_filter(array_map('trim', $lines), fn (string $l): bool => $l !== ''));
        }

        return [trim((string) $hash)];
    }

    /** Auto-generated output path for `--file` mode: `result.txt` next to the input file. */
    private function defaultOutputPath(string $file): string
    {
        return dirname((string) realpath($file)).DIRECTORY_SEPARATOR.'result.txt';
    }
}
