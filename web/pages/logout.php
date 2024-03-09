<?php

if ($_SESSION['user_info'])
    unset($_SESSION['user_info']);

header("Location: ?page=main");
exit();

?>