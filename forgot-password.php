<?php

session_start();

require_once "db.php";
require_once "vendor/autoload.php";
require_once "email-config.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$message = "";
$message_type = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $email = trim($_POST["email"] ?? "");

    if (empty($email)) {

        $message = "Please enter your email address.";
        $message_type = "error";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $message = "Please enter a valid email address.";
        $message_type = "error";

    } else {

        $stmt = $conn->prepare(
            "SELECT id, username, email
             FROM users
             WHERE email = ?"
        );

        $stmt->bind_param("s", $email);
        $stmt->execute();

        $result = $stmt->get_result();

        if ($result->num_rows === 1) {

            $user = $result->fetch_assoc();

            // Generate reset code
            $reset_code = (string) random_int(100000, 999999);

            // Hash reset code before storing
            $reset_code_hash = password_hash(
                $reset_code,
                PASSWORD_DEFAULT
            );

            // Expires in 10 minutes
            $expires_at = date(
                "Y-m-d H:i:s",
                time() + 600
            );

            // Invalidate old unused codes
            $invalidate = $conn->prepare(
                "UPDATE password_resets
                 SET used = 1
                 WHERE user_id = ? AND used = 0"
            );

            $invalidate->bind_param(
                "i",
                $user["id"]
            );

            $invalidate->execute();
            $invalidate->close();


            // Store new reset code
            $insert = $conn->prepare(
                "INSERT INTO password_resets
                (user_id, email, reset_code, expires_at)
                VALUES (?, ?, ?, ?)"
            );

            $insert->bind_param(
                "isss",
                $user["id"],
                $user["email"],
                $reset_code_hash,
                $expires_at
            );

            if ($insert->execute()) {

                $mail = new PHPMailer(true);

                try {

                    $mail->isSMTP();
                    $mail->Host = "smtp.gmail.com";
                    $mail->SMTPAuth = true;

                    $mail->Username = SMTP_USERNAME;
                    $mail->Password = SMTP_PASSWORD;

                    $mail->SMTPSecure =
                        PHPMailer::ENCRYPTION_STARTTLS;

                    $mail->Port = 587;

                    $mail->setFrom(
                        SMTP_USERNAME,
                        "SecureAuth"
                    );

                    $mail->addAddress(
                        $user["email"],
                        $user["username"]
                    );

                    $mail->isHTML(true);

                    $mail->Subject =
                        "SecureAuth - Password Reset Code";

                    $mail->Body = "
                        <h2>SecureAuth</h2>

                        <p>Your password reset code is:</p>

                        <h1>$reset_code</h1>

                        <p>This code expires in 10 minutes.</p>

                        <p>
                            If you did not request a password reset,
                            you can ignore this email.
                        </p>
                    ";

                    $mail->AltBody =
                        "Your SecureAuth password reset code is: $reset_code";

                    $mail->send();

                    $_SESSION["reset_email"] =
                        $user["email"];

                    header(
                        "Location: reset-password.php"
                    );

                    exit;

                } catch (Exception $e) {

                    $message =
                        "Unable to send the password reset email.";

                    $message_type = "error";

                }

            } else {

                $message =
                    "Unable to create password reset request.";

                $message_type = "error";
            }

            $insert->close();

        } else {

            /*
             * Generic response helps avoid revealing
             * whether an account exists.
             */
            $message =
                "If that email is registered, a reset code has been sent.";

            $message_type = "success";
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

    <title>Forgot Password - SecureAuth</title>

    <link rel="stylesheet" href="forgot-password.css">

</head>

<body>

<header class="navbar">

    <div class="nav-container">

        <a href="index.php" class="logo">
            <span>🛡</span>
            SecureAuth
        </a>

        <a href="login.php" class="back-link">
            ← Back to Login
        </a>

    </div>

</header>


<main class="reset-section">

    <div class="reset-card">

        <div class="reset-icon">
            🔑
        </div>

        <h1>Forgot Password?</h1>

        <p class="description">
            Enter your registered email address and
            we'll send you a password reset code.
        </p>


        <?php if (!empty($message)): ?>

            <div class="form-message <?php echo $message_type; ?>">

                <?php echo htmlspecialchars($message); ?>

            </div>

        <?php endif; ?>


        <form
            action="forgot-password.php"
            method="POST"
        >

            <div class="form-group">

                <label for="email">
                    Email Address
                </label>

                <input
                    type="email"
                    id="email"
                    name="email"
                    placeholder="Enter your registered email"
                    required
                >

            </div>


            <button
                type="submit"
                class="reset-button"
            >
                Send Reset Code
            </button>

        </form>


        <p class="login-link">
            Remember your password?
            <a href="login.php">Login</a>
        </p>

    </div>

</main>

</body>

</html>