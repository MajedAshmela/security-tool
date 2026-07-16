<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Validates the pasted-hashes input (and optional uploaded file) for the web
 * form and the JSON API.
 *
 * The controller used to accept `hashes` with no size limit at all, so a
 * single POST could carry an arbitrarily large body and line count straight
 * into the detection loop. These caps keep a single request's detection work
 * bounded regardless of what a client sends, whether the hashes arrive
 * pasted, uploaded as a file, or both at once.
 */
final class IdentifyHashesRequest extends FormRequest
{
    /** Maximum raw size, in characters, of the pasted input. */
    public const MAX_INPUT_LENGTH = 50_000;

    /** Maximum number of non-blank lines (hashes) accepted per request, pasted + uploaded combined. */
    public const MAX_LINES = 500;

    /** Maximum size, in kilobytes, of an uploaded hash-list file. */
    public const MAX_FILE_KILOBYTES = 512;

    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'hashes' => [
                'nullable',
                'string',
                'max:'.self::MAX_INPUT_LENGTH,
                function (string $attribute, mixed $value, callable $fail): void {
                    $pastedLines = $this->linesIn((string) $value);
                    $fileLines = $this->hasFile('file')
                        ? $this->linesIn((string) file_get_contents($this->file('file')->getRealPath()))
                        : [];

                    $total = count($pastedLines) + count($fileLines);
                    if ($total > self::MAX_LINES) {
                        $fail('The pasted hashes and uploaded file combined must not contain more than '.self::MAX_LINES.' hashes.');
                    }
                },
            ],
            'file' => [
                'nullable',
                'file',
                'max:'.self::MAX_FILE_KILOBYTES,
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'hashes.max' => 'The pasted input must not exceed '.self::MAX_INPUT_LENGTH.' characters.',
            'file.max' => 'The uploaded file must not exceed '.self::MAX_FILE_KILOBYTES.' KB.',
        ];
    }

    /** Non-blank, trimmed lines in `$text`. */
    public function linesIn(string $text): array
    {
        $lines = preg_split('/\R/', $text) ?: [];

        return array_values(array_filter(array_map('trim', $lines), fn (string $l): bool => $l !== ''));
    }

    /**
     * All hashes submitted in this request: pasted text lines followed by
     * the uploaded file's lines (if any). Shared by the web and API
     * controllers so both read hashes the same way.
     *
     * @return list<string>
     */
    public function allLines(): array
    {
        $lines = $this->linesIn((string) $this->validated('hashes', ''));

        if ($this->hasFile('file')) {
            $fileContents = (string) file_get_contents($this->file('file')->getRealPath());
            $lines = array_merge($lines, $this->linesIn($fileContents));
        }

        return $lines;
    }
}
