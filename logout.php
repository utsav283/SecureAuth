<?php

session_start();

require_once "db.php";
require_once "audit_log.php";

// Record logout
if (isset($_SESSION["user_id"])) {

    createAuditLog(
        $conn,
        $_SESSION["user_id"],
        "LOGOUT",
        "User logged out"
    );
}

session_unset();
session_destroy();

header("Location: login.php");
exit;

?>