<!DOCTYPE html>
<html>

<head>
    <title>echo</title>
    <link rel="stylesheet" href="/static/pico.classless.css">
</head>

<body>
    <header>
        <details>
            <summary><i>httpecho</i></summary>
            <p>A simple HTTP server that echoes back the request it receives. It is useful for debugging and
                testing HTTP clients.</p>
            <p>The order and case of the headers are preserved.</p>
        </details>
    </header>
    <main>
        <details open>
            <summary>Request echo</summary>
            <code>
<pre>
{{.dumpedRequest}}
</pre>
            </code>
        </details>
        <details>
            <summary>List of supported query parameters</summary>
            <li><code>sleep</code> - delay the response for the specified duration. Valid time units are " ns", "us"
                , "ms" , "s" , "m" , "h" . Example: `?sleep=5s`</li>
            <li><code>status</code> - set the HTTP status code of the response. Example: `?status=404`</li>
            <li><code>header</code> - add a custom header to the response (supports multiple). Example:
                `?header=Content-Type:application/json`</li>
            <li><code>size</code> - in addition to headers, add dummy data to make the response body match the
                specified
                size. Supported units are "KB", "MB", "GB". Example: `?size=200KB`</li>
            <li><code>verbose</code> - log the full request (headers and body) to stdout. Example:
                `?verbose=true`</li>
        </details>
    </main>
    <footer>
        <a href="https://github.com/jsnjack/httpecho">Report issues and share ideas on GitHub</a>
    </footer>
</body>

</html>
