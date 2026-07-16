<?php

declare(strict_types=1);

namespace App\Services\HashIdentifier;

/**
 * Renders identification results into a single aligned, bordered table for the
 * console command and its saved report file. This is presentation only — it
 * contains no detection logic. It mirrors the Python tool's `_render_batch`.
 *
 * Column widths are computed across all rows so everything lines up, and the
 * box auto-widens if a hash string or title is longer than the columns. Widths
 * are measured in Unicode code points (not bytes) so the multibyte box-drawing
 * glyphs and em-dash align the same way Python's `len()` counted them.
 */
final class TableRenderer
{
    private const PAD = 2; // spaces of breathing room on each side of a cell

    // ANSI colors, one per confidence level plus the surrounding chrome.
    private const CONFIDENCE_COLOR = ['high' => "\e[1;92m", 'medium' => "\e[1;93m", 'low' => "\e[1;91m"];

    private const TITLE_COLOR = "\e[1;96m";

    private const HEADER_COLOR = "\e[1;97m";

    private const ALGO_COLOR = "\e[1;97m";

    private const REASON_COLOR = "\e[0;37m";

    private const BORDER_COLOR = "\e[0;90m";

    private const ERROR_COLOR = "\e[1;91m";

    private const RESET = "\e[0m";

    // Box-drawing glyphs: Unicode for capable terminals, ASCII as a fallback.
    private const UNICODE_BOX = [
        'tl' => '┌', 'tm' => '┬', 'tr' => '┐', 'ml' => '├', 'mm' => '┼', 'mr' => '┤',
        'bl' => '└', 'bm' => '┴', 'br' => '┘', 'v' => '│', 'h' => '─', 'dash' => '—',
    ];

    private const ASCII_BOX = [
        'tl' => '+', 'tm' => '+', 'tr' => '+', 'ml' => '+', 'mm' => '+', 'mr' => '+',
        'bl' => '+', 'bm' => '+', 'br' => '+', 'v' => '|', 'h' => '-', 'dash' => '-',
    ];

    public function __construct(private readonly HashIdentifier $identifier) {}

    /**
     * Render all results into a list of lines (no trailing newlines).
     *
     * @param  list<array{0: string, 1: list<HashCandidate>}>  $groups  (hash, candidates) pairs; candidates may be empty.
     * @param  bool  $useColor  Whether to emit ANSI color codes.
     * @param  string|null  $boxEncoding  Encoding to pick box glyphs for; null uses the live terminal.
     * @return list<string>
     */
    public function render(array $groups, bool $useColor, ?string $boxEncoding = null): array
    {
        $box = $this->boxCharset($boxEncoding);
        $headers = ['Algorithm', 'Confidence', 'Hashcat Mode', 'Reason'];
        $noMatchRow = ['-', '-', '-', 'No hash type identified'];

        // Build display rows for each hash, sorting candidates by confidence.
        $groupRows = [];
        foreach ($groups as [$hashText, $results]) {
            $results = HashIdentifier::sortByConfidence($results);
            $rows = [];
            foreach ($results as $r) {
                $rows[] = [$r->algorithm, strtoupper($r->confidence), $this->identifier->hashcatModeFor($r->algorithm), $r->reason];
            }
            $groupRows[] = [$hashText, $results, $rows ?: [$noMatchRow]];
        }

        // Column widths = widest cell (or header) in each column, across all hashes.
        $allRows = [];
        foreach ($groupRows as [, , $rows]) {
            array_push($allRows, ...$rows);
        }
        $widths = [];
        foreach ($headers as $i => $header) {
            $widths[$i] = max($this->width($header), ...array_map(fn (array $row): int => $this->width($row[$i]), $allRows));
        }
        $cellWidths = array_map(fn (int $w): int => $w + self::PAD * 2, $widths);
        $innerWidth = array_sum($cellWidths) + (count($widths) - 1);

        // The title and per-hash label rows span the full width; if any is
        // wider than the columns, grow the last column so the box stays square.
        $count = count($groups);
        $title = " Hash Identification Results {$box['dash']} {$count} hash".($count !== 1 ? 'es' : '').' ';
        $labels = array_map(fn (array $g): string => " Hash: {$g[0]} ", $groupRows);
        $widestLine = max($this->width($title), ...array_map(fn (string $l): int => $this->width($l), $labels ?: ['']));
        if ($widestLine > $innerWidth) {
            $deficit = $widestLine - $innerWidth;
            $last = count($widths) - 1;
            $widths[$last] += $deficit;
            $cellWidths[$last] += $deficit;
            $innerWidth += $deficit;
        }

        $border = function (string $left, string $mid, string $right, bool $fullWidth = false) use ($box, $cellWidths, $innerWidth, $useColor): string {
            $line = $fullWidth
                ? $left.str_repeat($box['h'], $innerWidth).$right
                : $left.implode($mid, array_map(fn (int $w): string => str_repeat($box['h'], $w), $cellWidths)).$right;

            return $this->colorize($line, self::BORDER_COLOR, $useColor);
        };

        $singleRow = function (string $text, string $color) use ($box, $innerWidth, $useColor): string {
            $v = $this->colorize($box['v'], self::BORDER_COLOR, $useColor);

            return $v.$this->colorize($this->pad($text, $innerWidth), $color, $useColor).$v;
        };

        $cellRow = function (array $cells, array $cellColors) use ($box, $widths, $useColor): string {
            $v = $this->colorize($box['v'], self::BORDER_COLOR, $useColor);
            $parts = [];
            foreach ($cells as $idx => $text) {
                $padded = $this->pad($text, $widths[$idx]);
                $color = $cellColors[$idx] ?? null;
                $styled = $color ? $this->colorize($padded, $color, $useColor) : $padded;
                $parts[] = str_repeat(' ', self::PAD).$styled.str_repeat(' ', self::PAD);
            }

            return $v.implode($v, $parts).$v;
        };

        $lines = [];
        $lines[] = $border($box['tl'], $box['tm'], $box['tr'], true);
        $lines[] = $singleRow($title, self::TITLE_COLOR);
        $lines[] = $border($box['ml'], $box['tm'], $box['mr']);
        $lines[] = $cellRow($headers, array_fill(0, count($headers), self::HEADER_COLOR));

        foreach ($groupRows as [$hashText, $results, $rows]) {
            // With multiple hashes, print a labeled sub-header before each block.
            if ($count > 1) {
                $lines[] = $border($box['ml'], $box['bm'], $box['mr']);
                $lines[] = $singleRow(" Hash: {$hashText} ", self::TITLE_COLOR);
                $lines[] = $border($box['ml'], $box['tm'], $box['mr']);
            } else {
                $lines[] = $border($box['ml'], $box['mm'], $box['mr']);
            }

            if ($results !== []) {
                foreach ($results as $idx => $r) {
                    $lines[] = $cellRow($rows[$idx], [self::ALGO_COLOR, self::CONFIDENCE_COLOR[$r->confidence], self::ALGO_COLOR, self::REASON_COLOR]);
                }
            } else {
                $lines[] = $cellRow($rows[0], array_fill(0, count($headers), self::ERROR_COLOR));
            }
        }

        $lines[] = $border($box['bl'], $box['bm'], $box['br'], true);

        return $lines;
    }

    /**
     * Return the Unicode box-drawing glyphs, or an ASCII fallback.
     *
     * File output passes an explicit encoding (always UTF-8 here) and gets the
     * Unicode glyphs. For live terminal output, a legacy Windows code page
     * (e.g. cp1252) can't render the glyphs, so ASCII is used there.
     *
     * @return array<string, string>
     */
    private function boxCharset(?string $encoding): array
    {
        if ($encoding !== null) {
            $normalized = strtolower(str_replace('-', '', $encoding));

            return in_array($normalized, ['utf8', 'utf16', 'utf32'], true) ? self::UNICODE_BOX : self::ASCII_BOX;
        }

        if (PHP_OS_FAMILY === 'Windows' && function_exists('sapi_windows_cp_get')) {
            return sapi_windows_cp_get() === 65001 ? self::UNICODE_BOX : self::ASCII_BOX;
        }

        return self::UNICODE_BOX;
    }

    /** Wrap `$text` in an ANSI color code when `$useColor` is on, else return it plain. */
    private function colorize(string $text, string $color, bool $useColor): string
    {
        return $useColor ? $color.$text.self::RESET : $text;
    }

    /** Code-point width of a string (so multibyte glyphs count as one column). */
    private function width(string $text): int
    {
        return mb_strlen($text, 'UTF-8');
    }

    /** Left-justify `$text` to `$width` code points (never truncates). */
    private function pad(string $text, int $width): string
    {
        return $text.str_repeat(' ', max(0, $width - $this->width($text)));
    }
}
