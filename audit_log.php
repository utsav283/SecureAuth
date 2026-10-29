<?php

function createAuditLog($conn, $user_id, $action, $description)
{
    $ip_address = $_SERVER["REMOTE_ADDR"] ?? "Unknown";

    $stmt = $conn->prepare(
        "INSERT INTO audit_logs
        (user_id, action, description, ip_address)
        VALUES (?, ?, ?, ?)"
    );

    $stmt->bind_param(
        "isss",
        $user_id,
        $action,
        $description,
        $ip_address
    );

    $stmt->execute();
    $stmt->close();
}

?>