<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Hash Identifier</title>
    <style>
        :root {
            --bg: #0f1419; --panel: #1a2029; --panel-2: #131820; --border: #2a3441;
            --text: #e6edf3; --muted: #8b98a5; --accent: #4da3ff;
            --high: #3fb950; --medium: #d29922; --low: #f85149; --mono: #d2a8ff;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0; background: var(--bg); color: var(--text);
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            line-height: 1.5;
        }
        .wrap { max-width: 960px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
        header h1 { margin: 0 0 .25rem; font-size: 1.7rem; letter-spacing: -.02em; }
        header p { margin: 0 0 1.75rem; color: var(--muted); max-width: 62ch; }
        code, .mono { font-family: ui-monospace, "SFMono-Regular", "Cascadia Code", Consolas, monospace; }
        form { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }
        label { display: block; font-weight: 600; margin-bottom: .5rem; }
        label .hint { font-weight: 400; color: var(--muted); font-size: .85rem; }
        textarea {
            width: 100%; min-height: 130px; resize: vertical; padding: .8rem .9rem;
            background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
            border-radius: 8px; font-family: ui-monospace, Consolas, monospace; font-size: .9rem;
        }
        textarea:focus { outline: none; border-color: var(--accent); }
        .actions { margin-top: .9rem; display: flex; gap: .75rem; align-items: center; }
        button {
            background: var(--accent); color: #04101f; border: 0; border-radius: 8px;
            padding: .6rem 1.4rem; font-weight: 700; font-size: .95rem; cursor: pointer;
        }
        button:hover { filter: brightness(1.08); }
        .results { margin-top: 2rem; }
        .group { margin-bottom: 1.5rem; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
        .group-head {
            background: var(--panel-2); padding: .7rem .95rem; border-bottom: 1px solid var(--border);
            font-size: .85rem; color: var(--muted); word-break: break-all;
        }
        .group-head .mono { color: var(--text); }
        .table-scroll { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: .9rem; }
        th, td { text-align: left; padding: .6rem .95rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
        tbody tr:last-child td { border-bottom: 0; }
        th { background: var(--panel); color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
        td.reason { white-space: normal; color: var(--muted); }
        td.mode { font-family: ui-monospace, Consolas, monospace; color: var(--mono); }
        td.algo { font-weight: 600; }
        .badge { display: inline-block; padding: .12rem .55rem; border-radius: 999px; font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }
        .badge.high   { background: rgba(63,185,80,.16);  color: var(--high);   border: 1px solid rgba(63,185,80,.4); }
        .badge.medium { background: rgba(210,153,34,.16); color: var(--medium); border: 1px solid rgba(210,153,34,.4); }
        .badge.low    { background: rgba(248,81,73,.16);  color: var(--low);    border: 1px solid rgba(248,81,73,.4); }
        .none td { color: var(--low); font-style: italic; }
        .empty { color: var(--muted); margin-top: 2rem; }
        footer { margin-top: 2.5rem; color: var(--muted); font-size: .82rem; }
        footer code { color: var(--mono); }
    </style>
</head>
<body>
    <div class="wrap">
        <header>
            <h1>🔎 Hash Identifier</h1>
            <p>
                Paste a hash to guess which algorithm produced it. Identification is purely
                <strong>structural</strong> (prefix, length, character set) &mdash; it never reverses or
                cracks the hash. Each guess shows a confidence level and the matching hashcat
                <code>-m</code> mode.
            </p>
        </header>

        <form method="POST" action="{{ route('hashes.identify') }}">
            @csrf
            <label for="hashes">
                Hash(es)
                <span class="hint">&mdash; one per line for a batch</span>
            </label>
            <textarea id="hashes" name="hashes" placeholder="5f4dcc3b5aa765d61d8327deb882cf99" autofocus>{{ $input }}</textarea>
            <div class="actions">
                <button type="submit">Identify</button>
            </div>
        </form>

        @if (! is_null($groups))
            @if (count($groups) === 0)
                <p class="empty">No hashes entered &mdash; paste at least one line above.</p>
            @else
                <section class="results">
                    @foreach ($groups as $group)
                        <div class="group">
                            <div class="group-head">Hash: <span class="mono">{{ $group['hash'] }}</span></div>
                            <div class="table-scroll">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Algorithm</th>
                                            <th>Confidence</th>
                                            <th>Hashcat Mode</th>
                                            <th>Reason</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @forelse ($group['rows'] as $row)
                                            <tr>
                                                <td class="algo">{{ $row['algorithm'] }}</td>
                                                <td><span class="badge {{ $row['confidence'] }}">{{ $row['confidence'] }}</span></td>
                                                <td class="mode">{{ $row['mode'] }}</td>
                                                <td class="reason">{{ $row['reason'] }}</td>
                                            </tr>
                                        @empty
                                            <tr class="none">
                                                <td colspan="4">No hash type identified</td>
                                            </tr>
                                        @endforelse
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    @endforeach
                </section>
            @endif
        @endif

        <footer>
            Also available on the command line:
            <code>php artisan hash:identify &lt;hash&gt;</code> or
            <code>php artisan hash:identify --file hashes.txt</code>.
        </footer>
    </div>
</body>
</html>
