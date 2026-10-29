<?php

session_start();

require_once "db.php";
require_once "vendor/autoload.php";
require_once "email-config.php";
require_once "audit_log.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$registered = isset($_GET["registered"]);
$reset = isset($_GET["reset"]);

$message = "";
$message_type = "";

$max_attempts = 5;
$lockout_minutes = 5;


if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";


    if (empty($email) || empty($password)) {

        $message = "Please enter your email and password.";
        $message_type = "error";

    } else {

        // Check recent failed login attempts
        $check_attempts = $conn->prepare(
            "SELECT COUNT(*) AS failed_attempts
             FROM login_attempts
             WHERE email = ?
             AND success = 0
             AND attempt_time >= DATE_SUB(NOW(), INTERVAL ? MINUTE)"
        );

        $check_attempts->bind_param(
            "si",
            $email,
            $lockout_minutes
        );

        $check_attempts->execute();

        $attempt_result = $check_attempts->get_result();
        $attempt_data = $attempt_result->fetch_assoc();

        $failed_attempts = (int)$attempt_data["failed_attempts"];

        $check_attempts->close();


        // Check whether user is temporarily blocked
        if ($failed_attempts >= $max_attempts) {

            $message =
                "Too many failed login attempts. Please try again in 5 minutes.";

            $message_type = "error";

        } else {

            // Find user
            $stmt = $conn->prepare(
                "SELECT id, username, email, password, two_factor_enabled
                 FROM users
                 WHERE email = ?"
            );

            $stmt->bind_param("s", $email);

            $stmt->execute();

            $result = $stmt->get_result();


            if ($result->num_rows === 1) {

                $user = $result->fetch_assoc();


                // Check password
                if (password_verify($password, $user["password"])) {

                    


                    // Store user information
                    $_SESSION["user_id"] = $user["id"];
                    $_SESSION["username"] = $user["username"];
                    $_SESSION["email"] = $user["email"];


                    // Generate 6-digit OTP
                    $otp = random_int(100000, 999999);

                    $_SESSION["otp"] = $otp;
                    $_SESSION["otp_time"] = time();


                    // Send OTP email
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


                        // Sender
                        $mail->setFrom(
                            SMTP_USERNAME,
                            "SecureAuth"
                        );


                        // Recipient
                        $mail->addAddress(
                            $user["email"],
                            $user["username"]
                        );


                        // Email
                        $mail->isHTML(true);

                        $mail->Subject =
                            "SecureAuth - Your Verification Code";


                        $mail->Body = "
                            <h2>SecureAuth</h2>

                            <p>Your two-factor authentication
                            verification code is:</p>

                            <h1>$otp</h1>

                            <p>This code will expire in
                            5 minutes.</p>

                            <p>If you did not attempt to log in,
                            please ignore this email.</p>
                        ";


                        $mail->AltBody =
                            "Your SecureAuth verification code is: $otp";


                        $mail->send();


                        // Email successfully sent
                        header("Location: 2fa-verify.php");
                        exit;


                    } catch (Exception $e) {

                        $message =
                            "Unable to send verification email.";

                        $message_type = "error";

                    }


                } else {

                    // Record failed password attempt
                    $log_failed = $conn->prepare(
                        "INSERT INTO login_attempts
                        (user_id, email, ip_address, success)
                        VALUES (?, ?, ?, 0)"
                    );

                    $user_id = $user["id"];
                    $ip_address = $_SERVER["REMOTE_ADDR"];

                    $log_failed->bind_param(
                        "iss",
                        $user_id,
                        $email,
                        $ip_address
                    );

                    $log_failed->execute();
                    createAuditLog(
                    $conn,
                    $user["id"],
                    "LOGIN_FAILED",
                    "Incorrect password entered"
                    );
                    
                    $log_failed->close();


                    $message =
                        "Invalid email or password.";

                    $message_type = "error";

                }


            } else {

                // Record failed attempt for unknown email
                $log_failed = $conn->prepare(
                    "INSERT INTO login_attempts
                    (user_id, email, ip_address, success)
                    VALUES (NULL, ?, ?, 0)"
                );

                $ip_address = $_SERVER["REMOTE_ADDR"];

                $log_failed->bind_param(
                    "ss",
                    $email,
                    $ip_address
                );

                $log_failed->execute();
                createAuditLog(
                $conn,
                null,
                "LOGIN_FAILED",
                "Login attempted with an unregistered email"
                );
                $log_failed->close();


                $message =
                    "Invalid email or password.";

                $message_type = "error";

            }

            $stmt->close();

        }

    }

}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login - SecureAuth</title>

    <link rel="stylesheet" href="login.css">
</head>

<body>

    <!-- Navigation -->
    <header class="navbar">

        <div class="nav-container">

            <a href="index.php" class="logo">
                <span class="logo-icon">🛡</span>
                SecureAuth
            </a>

            <a href="register.php" class="register-link">
                Don't have an account?
                <span>Create Account</span>
            </a>

        </div>

    </header>


    <!-- Login Section -->
    <main class="login-section">

        <div class="login-container">

            <!-- Login Card -->
            <div class="login-card">

                <!-- Header -->
                <div class="login-header">

                    <div class="login-icon">
                        🔐
                    </div>

                    <h1>Welcome Back</h1>

                    <p>
                        Login to access your secure account.
                    </p>

                </div>


                <!-- Security Notice -->
                <div class="security-notice">

                    <span class="notice-icon">🛡</span>

                    <div>
                        <strong>Secure Login</strong>

                        <p>
                            Your account is protected with
                            multi-step authentication.
                        </p>
                    </div>

                </div>
                
<?php if ($reset): ?>

    <div class="form-message success">
        Password reset successfully! You can now login with your new password.
    </div>

<?php endif; ?>


<?php if (!empty($message)): ?>

    <div class="form-message <?php echo $message_type; ?>">
        <?php echo htmlspecialchars($message); ?>
    </div>

<?php endif; ?>

                <!-- Login Form -->
                <form action="login.php" method="POST" id="loginForm">

                    <!-- Email -->
                    <div class="form-group">

                        <label for="email">
                            Email Address
                        </label>

                        <input
                            type="email"
                            id="email"
                            name="email"
                            placeholder="Enter your email"
                            autocomplete="username"
                            required
                        >

                    </div>


                    <!-- Password -->
                    <div class="form-group">

                        <div class="label-row">

                            <label for="password">
                                Password
                            </label>

                            <a href="forgot-password.php">
                                Forgot Password?
                            </a>

                        </div>


                        <div class="password-input">

                            <input
                                type="password"
                                id="password"
                                name="password"
                                placeholder="Enter your password"
                                autocomplete="current-password"
                                required
                            >

                            <button
                                type="button"
                                class="show-password"
                                onclick="togglePassword()"
                            >
                                Show
                            </button>

                        </div>

                    </div>


                    <!-- Remember Me -->
                    <div class="login-options">

                        <label class="remember-me">

                            <input
                                type="checkbox"
                                name="remember"
                            >

                            <span>
                                Remember me
                            </span>

                        </label>

                    </div>


                    <!-- Login Button -->
                    <button
                        type="submit"
                        class="login-button"
                    >
                        Login Securely
                    </button>

                </form>


                <!-- Divider -->
                <div class="divider">

                    <span>OR</span>

                </div>


                <!-- Password Checker -->
                <a
                    href="password-checker.php"
                    class="password-checker-link"
                >
                    🔐 Check your password strength
                </a>


                <!-- Register -->
                <p class="register-text">

                    Don't have an account?

                    <a href="register.php">
                        Create an account
                    </a>

                </p>

            </div>


            <!-- Right Information -->
            <div class="login-info">

                <div class="security-badge">
                    <span>●</span>
                    Protected Authentication
                </div>


                <h2>
                    Your security
                    <span>comes first.</span>
                </h2>


                <p>
                    SecureAuth uses multiple security controls
                    to help protect your account from
                    unauthorized access.
                </p>


                <!-- Security Features -->
                <div class="security-list">

                    <div class="security-item">

                        <div class="item-icon">
                            ✓
                        </div>

                        <div>
                            <h3>Secure Password Authentication</h3>

                            <p>
                                Passwords are securely protected
                                using modern hashing techniques.
                            </p>
                        </div>

                    </div>


                    <div class="security-item">

                        <div class="item-icon">
                            ✓
                        </div>

                        <div>
                            <h3>Two-Factor Verification</h3>

                            <p>
                                An additional verification code
                                helps protect your account.
                            </p>
                        </div>

                    </div>


                    <div class="security-item">

                        <div class="item-icon">
                            ✓
                        </div>

                        <div>
                            <h3>Login Activity Monitoring</h3>

                            <p>
                                Keep track of successful and
                                unsuccessful login attempts.
                            </p>
                        </div>

                    </div>

                </div>


                <!-- Security Score Card -->
                <div class="protection-card">

                    <div class="protection-icon">
                        🛡
                    </div>

                    <div>

                        <strong>
                            Account Protection
                        </strong>

                        <p>
                            Multi-layer security enabled
                        </p>

                    </div>

                    <span class="protected">
                        Protected
                    </span>

                </div>

            </div>

        </div>

    </main>


    <!-- Footer -->
    <footer class="footer">

        <p>
            © 2026 SecureAuth. Cybersecurity Project.
        </p>

    </footer>


    <!-- JavaScript -->
    <script>

        function togglePassword() {

            const password =
                document.getElementById("password");

            const button =
                document.querySelector(".show-password");

            if (password.type === "password") {

                password.type = "text";
                button.textContent = "Hide";

            } else {

                password.type = "password";
                button.textContent = "Show";

            }

        }

    </script>

</body>

</html>