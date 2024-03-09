<?php 

include_once 'helper/db.php';

function user_login($token)
{
    global $pdo;

    $stmt = $pdo->prepare("SELECT * FROM users WHERE :account_id LIKE CONCAT('%', public, '%')");
    $stmt->bindParam(':account_id', $token, PDO::PARAM_STR);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $hashed_token = $user['token'];
        $public_key = $user['public'];
        $cleaned_token = str_replace($user['public'], "", $token);

        if (password_verify($cleaned_token, $hashed_token)) 
        {
            $_SESSION['user_info'] = array('id' => $user['id'], 'username' => $user['username'], 'admin' => $user['admin']);
            return true;
        } 
        else 
        {
            return false;
        }
    } 
    else 
        return false;
}

function user_create($username, $invitation_key, &$errorMessage)
{
    global $pdo;

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->execute();
    
    if ($stmt->rowCount() > 0)
    {
        $errorMessage = "Username already taken !";
    } 
    else 
    {
        $stmt = $pdo->prepare("SELECT * FROM invites WHERE value = :invitation_key AND used = 0");
        $stmt->bindParam(':invitation_key', $invitation_key, PDO::PARAM_STR);
        $stmt->execute();
    
        if ($stmt->rowCount() > 0) {
            $invite = $stmt->fetch(PDO::FETCH_ASSOC);
    
            do 
            {
                $public_key = gen_rdn_str(4);
                $token = gen_rdn_str(8);
    
                $stmt = $pdo->prepare("SELECT * FROM users WHERE public = :public_key OR token = :token");
                $stmt->bindParam(':public_key', $public_key, PDO::PARAM_STR);
                $stmt->bindParam(':token', $token, PDO::PARAM_STR);
                $stmt->execute();
            } while ($stmt->rowCount() > 0);
    
            if (ctype_alpha($username))
            {
                $stmt = $pdo->prepare("INSERT INTO users (token, public, username, admin) VALUES (:hashed_token, :public, :username, :admin)");
    
                $hashed_token = password_hash($token, PASSWORD_ARGON2I);
                
                $dummy = false;

                $stmt->bindParam(':hashed_token', $hashed_token, PDO::PARAM_STR);
                $stmt->bindParam(':public', $public_key, PDO::PARAM_STR);
                $stmt->bindParam(':username', $username, PDO::PARAM_STR);
                $stmt->bindParam(':admin', $dummy, PDO::PARAM_INT);
                $stmt->execute();

                $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
                $stmt->bindParam(':username', $username, PDO::PARAM_STR);
                $stmt->execute();
                
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                $_SESSION['user_info'] = array('id' => $user['id'], 'username' => $username, 'admin' => $user['admin']);
    
                $stmt = $pdo->prepare("UPDATE invites SET used = 1 WHERE value = :invite_content");
                $stmt->bindParam(':invite_content', $invite['value'], PDO::PARAM_STR);
                $stmt->execute();
                
                $_SESSION['token'] = $public_key . $token;

    
                header("Location: ?page=success");
                exit();
            } 
            else 
            {
                $errorMessage = "Please use only alphabetical characters !";
            }
        } else 
        {
            $errorMessage = "Invalid invitation key !";
        }
    }
}

function redirect()
{
    $currentPage = isset($_GET['page']) ? $_GET['page'] : '';

    if (!isset($_SESSION['user_info']))
    {
        if ($currentPage != 'login' && $currentPage != 'register')
        {
            header("Location: ?page=landing");
            exit();
        }
    }
    else
    {
        global $pdo;

        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->bindParam(':id', $_SESSION['user_info']['id'], PDO::PARAM_STR);
        $stmt->execute();

        if ($stmt->rowCount() > 0)
        {
            if ($currentPage == 'login' || $currentPage == 'register')
            {
                header("Location: ?page=dashboard");
                exit();
            }        
        }
        else
        {
            header("Location: ?page=logout");
            exit();
        }   
    }
}


?>