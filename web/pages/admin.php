<?php 

redirect();

if ($_SESSION['user_info']['admin'] != 1)
{
    header("Location: ?page=main");
    exit();
}

$users_array = get_all_users();

if ($_SERVER['REQUEST_METHOD'] === 'POST') 
{

    if (isset($_POST['reset_user'])) 
    {
        $user_id = $_POST['user_id'];
        user_reset_token($user_id);
    }

    if (isset($_POST['delete_user']))
    {
        $user_id = $_POST['user_id'];
        user_delete($user_id);
    }

    if (isset($_POST['create_invite']))
    {
        create_invite();
    }
    
    header("Refresh:0");
}

?>

<div class="container"> 
    <div class="wrapper dashboard-wrapper">
        <div class="dashboard-content">
        <div style="width: 50%; float: left; max-height: 400px; overflow-y: auto;">
                <strong>Users :</strong><br>
                <?php if (empty($users_array)) : ?>
                    <p style="color: #f84040;">⚠️ Users list failed or empty!</p>
                <?php else : ?>
                    <?php foreach ($users_array as $user) : ?>
                        <form method="post" action="?page=admin">
                            <div class="object-column">
                                <p>
                                    <?php echo $user['id'] . " | " . $user['username'] . " | admin : " . (($user['admin'] == 1) ? "yes" : "no"); ?>
                                    <span class="button-container">
                                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                        <button type="submit" name="reset_user" style="background-color: var(--main-color);">🔄</button>
                                        <button type="submit" name="delete_user" style="background-color: #f84040;">🗑️</button>
                                    </span>
                                </p>
                            </div>
                        </form>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <div style="float: right; width: 45%;">
                <strong>Actions :</strong><br>
                <form method="post" action="?page=admin">
                <div class="button">
                    <input type="submit" name="create_invite" value="Create Invite">
                </div>
                </form>
                <div class="button">
                    <input type="button" style="background-color: #f84040; border: #f84040; box-shadow: 0 0 5px #f84040;" value="Exit Admin Panel" onclick="window.location.href='?page=main';">
                </div>
            </div> 
        </div>
    </div>
</div>
