<?php 

function user_reset_token($user_id) 
{
    global $pdo;

    do 
    {
        $public_key = gen_rdn_str(4);
        $token = gen_rdn_str(8);

        $stmt = $pdo->prepare("SELECT * FROM users WHERE public = :public_key OR token = :token");
        $stmt->bindParam(':public_key', $public_key, PDO::PARAM_STR);
        $stmt->bindParam(':token', $token, PDO::PARAM_STR);
        $stmt->execute();
    } while ($stmt->rowCount() > 0);

    $hashed_token = password_hash($token, PASSWORD_ARGON2I);

    $sql = "UPDATE users SET token = :newToken, public = :newPublic WHERE id = :userId";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':newToken', $hashed_token, PDO::PARAM_STR);
    $stmt->bindParam(':newPublic', $public_key, PDO::PARAM_STR);
    $stmt->bindParam(':userId', $user_id, PDO::PARAM_INT);
    $stmt->execute();

    $final_token = $public_key . $token;

    echo '<script type="text/javascript">window.confirm("'."New Account Token : ". $final_token.'");</script>';
}

function user_delete($user_id)
{
    global $pdo;

    if ($_SESSION['user_info']['id'] != $user_id)
    {
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
        $stmt->bindParam(':id', $user_id, PDO::PARAM_INT);
        $stmt->execute();

        $stmt = $pdo->prepare("DELETE FROM payload WHERE created_by = :id");
        $stmt->bindParam(':id', $user_id, PDO::PARAM_INT);
        $stmt->execute();
    }
    else
    {
        echo '<script type="text/javascript">window.confirm("😹");</script>';

    }    
}



function get_all_users()
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users");
    $stmt->execute();

    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

    return $result;
}



function create_invite()
{
    global $pdo;

    do 
    {
        $invite_value = gen_rdn_str(16);

        $stmt = $pdo->prepare("SELECT * FROM invites WHERE value = :invite_key");
        $stmt->bindParam(':invite_key', $invite_value, PDO::PARAM_STR);
        $stmt->execute();
    } while ($stmt->rowCount() > 0);

    $stmt = $pdo->prepare("INSERT INTO invites (value) VALUES (:value)");
    $stmt->bindParam(':value', $invite_value, PDO::PARAM_STR);
    $stmt->execute();

    echo '<script type="text/javascript">window.confirm("'."New Invite : ". $invite_value.'");</script>';
}

?>