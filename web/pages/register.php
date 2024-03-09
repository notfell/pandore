<?php 

$errorMessage = '';

redirect();

if ($_SERVER["REQUEST_METHOD"] == "POST") 
{

    $username = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
    $invitation_key = filter_var($_POST['invitation_key'], FILTER_SANITIZE_STRING);
    
    user_create($username, $invitation_key, $errorMessage);
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
                    <i class="fas fa-user"></i>
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="row">
                    <i class="fas fa-key"></i>
                    <input type="password" name="invitation_key" placeholder="Invitation key" required>
                </div>
                <div class="row button">
                    <input type="submit" value="Register">
                </div>
                <div class="signup-link">Already a member ? <a href="?page=login">Log in now</a></div>
            </form>
    </div>
</div>