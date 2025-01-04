<!DOCTYPE html>
<html>
<head>
    <title>echo</title>
    <link rel="stylesheet" href="/static/pico.classless.css">
</head>
<body>
    <main>
        <h1>echo</h1>
            {{range $element := .rawHeaders}}
                <p>{{$element}}</p>
            {{end}}
    </main>
</body>
</html>
