<?php

session_start();

require_once "db.php";

$message = "";
$message_type = "";

if (!isset($_SESSION["reset_email"])) {

    header("Location: forgot-password.php");
    exit;
}

$email = $_SESSION["reset_email"];


if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $reset_code =
        trim($_POST["reset_code"] ?? "");

    $new_password =
        $_POST["new_password"] ?? "";

    $confirm_password =
        $_POST["confirm_password"] ?? "";


    if (
        empty($reset_code) ||
        empty($new_password) ||
        empty($confirm_password)
    ) {

        $message =
            "Please complete all fields.";

        $message_type = "error";

    }

    elseif ($new_password !== $confirm_password) {

        $message =
            "Passwords do not match.";

        $message_type = "error";

    }

    elseif (
        strlen($new_password) < 8 ||
        !preg_match("/[A-Z]/", $new_password) ||
        !preg_match("/[a-z]/", $new_password) ||
        !preg_match("/[0-9]/", $new_password) ||
        !preg_match("/[^A-Za-z0-9]/", $new_password)
    ) {

        $message =
            "Password must contain at least 8 characters, uppercase, lowercase, number and special character.";

        $message_type = "error";

    }

    else {

        $stmt = $conn->prepare(
            "SELECT pr.id,
                    pr.user_id,
                    pr.reset_code,
                    pr.expires_at
             FROM password_resets pr
             WHERE pr.email = ?
               AND pr.used = 0
             ORDER BY pr.id DESC
             LIMIT 1"
        );

        $stmt->bind_param(
            "s",
            $email
        );

        $stmt->execute();

        $result =
            $stmt->get_result();


        if ($result->num_rows === 1) {

            $reset =
                $result->fetch_assoc();


            if (
                strtotime($reset["expires_at"]) < time()
            ) {

                $message =
                    "Reset code has expired.";

                $message_type = "error";

            }

            elseif (
                !password_verify(
                    $reset_code,
                    $reset["reset_code"]
                )
            ) {

                $message =
                    "Invalid reset code.";

                $message_type = "error";

            }

            else {

                $new_hash =
                    password_hash(
                        $new_password,
                        PASSWORD_DEFAULT
                    );


                // Update password
                $update = $conn->prepare(
                    "UPDATE users
                     SET password = ?
                     WHERE id = ?"
                );

                $update->bind_param(
                    "si",
                    $new_hash,
                    $reset["user_id"]
                );


                if ($update->execute()) {

                    // Mark reset code as used
                    $used = $conn->prepare(
                        "UPDATE password_resets
                         SET used = 1
                         WHERE id = ?"
                    );

                    $used->bind_param(
                        "i",
                        $reset["id"]
                    );

                    $used->execute();
                    $used->close();


                    unset(
                        $_SESSION["reset_email"]
                    );


                    header(
                        "Location: login.php?reset=1"
                    );

                    exit;

                } else {

                    $message =
                        "Unable to update password.";

                    $message_type = "error";
                }

                $update->close();
            }

        } else {

            $message =
                "No valid password reset request found.";

            $message_type = "error";
        }

        $stmt->close();
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Reset Password - SecureAuth</title>

    <link rel="stylesheet" href="reset-password.css">

</head>

<body>

<header class="navbar">

    <div class="nav-container">

        <a href="index.php" class="logo">
            <span>🛡</span>
            SecureAuth
        </a>

    </div>

</header>


<main class="reset-section">

    <div class="reset-card">

        <div class="reset-icon">
            🔐
        </div>

        <h1>Reset Password</h1>

        <p class="description">
            Enter the code sent to your email
            and choose a new secure password.
        </p>


        <?php if (!empty($message)): ?>

            <div class="form-message <?php echo $message_type; ?>">

                <?php echo htmlspecialchars($message); ?>

            </div>

        <?php endif; ?>


        <form
            action="reset-password.php"
            method="POST"
        >

            <div class="form-group">

                <label for="reset_code">
                    Reset Code
                </label>

                <input
                    type="text"
                    id="reset_code"
                    name="reset_code"
                    maxlength="6"
                    inputmode="numeric"
                    placeholder="Enter 6-digit code"
                    required
                >

            </div>


            <div class="form-group">

                <label for="new_password">
                    New Password
                </label>

                <input
                    type="password"
                    id="new_password"
                    name="new_password"
                    placeholder="Enter new password"
                    required
                >

            </div>


            <div class="form-group">

                <label for="confirm_password">
                    Confirm New Password
                </label>

                <input
                    type="password"
                    id="confirm_password"
                    name="confirm_password"
                    placeholder="Confirm new password"
                    required
                >

            </div>


            <button
                type="submit"
                class="reset-button"
            >
                Reset Password
            </button>

        </form>

    </div>

</main>

</body>

</html>