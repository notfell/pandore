<?php 

redirect();

if ($_SERVER["REQUEST_METHOD"] == "POST")
{
    if (user_login($_POST['account_id']))
    {
        header("Location: ?page=main");
        exit();
    }
    else
    {
        $errorMessage = "Invalid account token !";
    }
}
?>

<div class="container">
        <div class="wrapper">
            <h3>Pandore</h3>
            <form action="" method="post">
                <?php if (!empty($errorMessage)): ?>
                    <div class="error-message"><?php echo $errorMessage; ?></div>
                <?php endif; ?>
                <div class="row">
                    <i class="fas fa-lock"></i>
                    <input type="password" name="account_id" placeholder="Account Token" required>
                </div>
                <div class="row button">
                    <input type="submit" name="login" value="Login">
                </div>
                <div class="signup-link">Not a member ? <a href="?page=register">Register now</a></div>
        </form>
    </div>
</div>