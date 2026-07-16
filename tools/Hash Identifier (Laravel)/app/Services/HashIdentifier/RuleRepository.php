<?php

declare(strict_types=1);

namespace App\Services\HashIdentifier;

use JsonException;

/**
 * Loads, validates, and caches the detection rules from `rules.json`.
 *
 * The Python tool read the file once (memoized with `lru_cache`) and validated
 * its structure so a malformed rules file fails loudly with a clear message
 * instead of causing confusing errors deep in detection. This class mirrors
 * that: the file is read and validated lazily on first access, then cached on
 * the instance for the lifetime of the request/command.
 *
 * It is intentionally framework-agnostic (no Laravel helpers), so the detection
 * engine and its unit tests can use it without booting the application. The
 * default rules path is resolved relative to this file — the way the Python
 * tool resolved `rules.json` relative to the script, not the caller's CWD.
 */
final class RuleRepository
{
    /** Confidence values a prefix rule is allowed to declare. */
    private const VALID_CONFIDENCE = ['high', 'medium', 'low'];

    private readonly string $rulesPath;

    private bool $loaded = false;

    /** @var array<string, array{algorithm: string, confidence: string, min_length?: int}> */
    private array $prefixRules = [];

    /** @var array<int|string, list<string>> */
    private array $hexRules = [];

    /** @var array<string, string> */
    private array $hashcatModes = [];

    public function __construct(?string $rulesPath = null)
    {
        $this->rulesPath = $rulesPath
            ?? dirname(__DIR__, 3).DIRECTORY_SEPARATOR.'resources'.DIRECTORY_SEPARATOR.'rules.json';
    }

    /**
     * Prefix -> {algorithm, confidence, min_length?}, in file order.
     *
     * @return array<string, array{algorithm: string, confidence: string, min_length?: int}>
     */
    public function prefixRules(): array
    {
        $this->load();

        return $this->prefixRules;
    }

    /**
     * Hex length -> ordered list of algorithm names.
     *
     * @return array<int|string, list<string>>
     */
    public function hexRules(): array
    {
        $this->load();

        return $this->hexRules;
    }

    /** Return the hashcat `-m` mode for an algorithm, or "-" if none is mapped. */
    public function hashcatModeFor(string $algorithm): string
    {
        $this->load();

        return $this->hashcatModes[$algorithm] ?? '-';
    }

    /**
     * Read + validate the rules file once, caching the result on the instance.
     *
     * @throws RuleValidationException if the file is missing, is not valid JSON,
     *                                 lacks a required key, or contains an invalid
     *                                 confidence / missing algorithm / a non-object
     *                                 `hashcat_modes`.
     */
    private function load(): void
    {
        if ($this->loaded) {
            return;
        }

        if (! is_file($this->rulesPath)) {
            throw new RuleValidationException("rules file not found: {$this->rulesPath}");
        }

        try {
            $data = json_decode((string) file_get_contents($this->rulesPath), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuleValidationException("rules file is not valid JSON ({$this->rulesPath}): {$e->getMessage()}");
        }

        foreach (['prefix_rules', 'hex_rules'] as $key) {
            if (! is_array($data) || ! array_key_exists($key, $data)) {
                throw new RuleValidationException("rules file is missing required key '{$key}': {$this->rulesPath}");
            }
        }

        foreach ($data['prefix_rules'] as $prefix => $rule) {
            $confidence = $rule['confidence'] ?? null;
            if (! in_array($confidence, self::VALID_CONFIDENCE, true)) {
                throw new RuleValidationException(
                    "rules file has invalid confidence for prefix '{$prefix}': ".var_export($confidence, true)
                );
            }
            if (empty($rule['algorithm'])) {
                throw new RuleValidationException("rules file is missing algorithm for prefix '{$prefix}'");
            }
        }

        $hashcatModes = $data['hashcat_modes'] ?? [];
        // A JSON object decodes to an associative array; reject anything that
        // isn't one (a string/number, or a non-empty JSON array), matching the
        // Python `isinstance(hashcat_modes, dict)` check.
        if (! is_array($hashcatModes) || ($hashcatModes !== [] && array_is_list($hashcatModes))) {
            throw new RuleValidationException(
                "rules file has invalid 'hashcat_modes', expected an object: {$this->rulesPath}"
            );
        }

        $this->prefixRules = $data['prefix_rules'];
        $this->hexRules = $data['hex_rules'];
        $this->hashcatModes = $hashcatModes;
        $this->loaded = true;
    }
}
