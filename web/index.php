<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/x-icon" href="design/img/pandore.ico">
    <link rel="stylesheet" href="design/css/style.css">
    <script src="design/js/jquery-3.7.1.min.js"></script>
    <title>Pandore</title>
</head>

<body>

    <?php
    include_once 'helper/db.php';
    include_once 'helper/utils.php';
    include_once 'helper/user.php';
    include_once 'helper/payload.php';
    include_once 'helper/admin.php';

    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    $page = isset($_GET['page']) ? $_GET['page'] : 'main';
    $page_path = "pages/$page.php";

    if (file_exists($page_path)) {
        include($page_path);
    } else {
        include('pages/main.php');
    }
    ?>


<footer style="height:auto">
  <p>Made with ❤️ by <a style="color: var(--main-color); text-decoration: none;" href="https://github.com/notfell" target="_blank">fell</a></p>
</footer>
</body>

</html>
