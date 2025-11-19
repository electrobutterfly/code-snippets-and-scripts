<?php
// Return 404 for any direct access to this directory
header("HTTP/1.0 404 Not Found");
echo '<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>';
exit;
?>
