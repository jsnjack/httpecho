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
        {{ range $el := .SortedRequests }}
        <details open>
            <summary>Request {{ index $el 0 }}</summary>
            <code>
<pre>
{{ index $el 1 }}
</pre>
            </code>
        </details>
        {{ end }}
    </main>
    <footer>
        <a href="https://github.com/jsnjack/httpecho">Report issues and share ideas on GitHub</a>
    </footer>
</body>

</html>
