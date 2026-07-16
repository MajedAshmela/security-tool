<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\HashIdentifier\HashCandidate;
use App\Services\HashIdentifier\HashIdentifier;
use App\Services\HashIdentifier\RuleValidationException;
use App\Services\HashIdentifier\TableRenderer;
use Illuminate\Console\Command;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Console front-end to the hash identifier — the Laravel equivalent of the
 * Python tool's CLI. Accepts a single positional hash, `--file` (one hash
 * per line), or `--stdin` (one hash per line on standard input), but never
 * more than one of the three.
 *
 * `--stdin` is opt-in rather than auto-detected: blindly reading standard
 * input whenever no hash/--file is given would block forever in a plain
 * interactive shell that isn't actually piping anything in.
 *
 * The input mode affects the default destination, matching the original:
 *   - A single positional hash or `--stdin` prints the table to the
 *     terminal (colored, unless `--no-color` or stdout isn't a TTY).
 *   - `--file` writes the table to `result.txt` next to the input file
 *     (uncolored, UTF-8) instead of printing.
 *
 * `--output` overrides the destination file path in either mode.
 * `--format=json` emits machine-readable JSON instead of the table, to
 * either destination.
 */
final class IdentifyHashCommand extends Command
{
    protected $signature = 'hash:identify
        {hash? : A single hash to identify}
        {--file= : Path to a text file with one hash per line}
        {--stdin : Read hashes (one per line) from standard input}
        {--output= : Write the results table to this file instead of the default destination}
        {--format=table : Output format: table or json}
        {--no-color : Disable colored output}';

    protected $description = 'Identify hash types from input text (structural detection).';

    public function handle(HashIdentifier $identifier, TableRenderer $renderer): int
    {
        $hash = $this->argument('hash');
        $file = $this->option('file');
        $stdin = $this->option('stdin');
        $format = $this->option('format');

        if (! in_array($format, ['table', 'json'], true)) {
            $this->error("invalid --format '{$format}': expected 'table' or 'json'.");

            return self::INVALID;
        }

        $sourcesGiven = count(array_filter([$hash !== null, $file !== null, $stdin]));
        if ($sourcesGiven > 1) {
            $this->error('provide only one of: a hash, --file, or --stdin.');

            return self::INVALID;
        }

        if ($sourcesGiven === 0) {
            $this->error('provide a hash, use --file to identify multiple hashes, or --stdin to read from standard input.');

            return self::INVALID;
        }

        try {
            $hashTexts = $this->readHashes($hash, $file, $stdin);
        } catch (\RuntimeException $e) {
            $this->error($e->getMessage());

            return self::INVALID;
        }

        try {
            $groups = array_map(fn (string $h): array => [$h, $identifier->identify($h)], $hashTexts);

            $outputPath = $this->option('output') ?? ($file !== null ? $this->defaultOutputPath($file) : null);
            $content = $format === 'json'
                ? $this->renderJson($groups, $identifier)
                : implode("\n", $renderer->render($groups, useColor: false, boxEncoding: 'utf-8'))."\n";

            if ($outputPath !== null) {
                if (@file_put_contents($outputPath, $content) === false) {
                    $this->error("could not write to {$outputPath}");

                    return self::FAILURE;
                }

                return self::SUCCESS;
            }

            if ($format === 'json') {
                $this->line($content);

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
     * Encode identification results as JSON: a list of
     * `{hash, candidates: [{algorithm, confidence, mode, reason}]}`.
     *
     * @param  list<array{0: string, 1: list<HashCandidate>}>  $groups
     */
    private function renderJson(array $groups, HashIdentifier $identifier): string
    {
        $results = array_map(function (array $group) use ($identifier): array {
            [$hash, $candidates] = $group;

            return [
                'hash' => $hash,
                'candidates' => array_map($identifier->toRow(...), HashIdentifier::sortByConfidence($candidates)),
            ];
        }, $groups);

        return json_encode(['results' => $results], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n";
    }

    /**
     * Collect the hash strings to identify: from `--file` (one per non-blank
     * line), the positional `hash` argument, or `--stdin` (one per non-blank
     * line read from standard input). Exactly one source is guaranteed to be
     * given by the caller.
     *
     * @return list<string>
     *
     * @throws \RuntimeException if the `--file` path does not exist.
     */
    private function readHashes(?string $hash, ?string $file, bool $stdin): array
    {
        if ($file !== null) {
            if (! is_file($file)) {
                throw new \RuntimeException("file not found: {$file}");
            }

            return $this->linesIn((string) file_get_contents($file));
        }

        if ($stdin) {
            return $this->linesIn((string) file_get_contents('php://stdin'));
        }

        return [trim((string) $hash)];
    }

    /** Non-blank, trimmed lines in `$text`. */
    private function linesIn(string $text): array
    {
        $lines = preg_split('/\R/', $text) ?: [];

        return array_values(array_filter(array_map('trim', $lines), fn (string $l): bool => $l !== ''));
    }

    /** Auto-generated output path for `--file` mode: `result.txt` next to the input file. */
    private function defaultOutputPath(string $file): string
    {
        return dirname((string) realpath($file)).DIRECTORY_SEPARATOR.'result.txt';
    }
}
