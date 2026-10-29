<?php

require_once "db.php";
require_once "audit_log.php";

$message = "";
$message_type = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirm_password = $_POST["confirm_password"] ?? "";

    if (
        empty($username) ||
        empty($email) ||
        empty($password) ||
        empty($confirm_password)
    ) {

        $message = "Please fill in all fields.";
        $message_type = "error";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $message = "Please enter a valid email address.";
        $message_type = "error";

    } elseif ($password !== $confirm_password) {

        $message = "Passwords do not match.";
        $message_type = "error";

    } elseif (strlen($password) < 8) {

        $message = "Password must be at least 8 characters.";
        $message_type = "error";

    } else {

        $check = $conn->prepare(
            "SELECT id FROM users WHERE username = ? OR email = ?"
        );

        $check->bind_param("ss", $username, $email);
        $check->execute();

        $result = $check->get_result();

        if ($result->num_rows > 0) {

            $message = "Username or email already exists.";
            $message_type = "error";

        } else {

            $hashed_password = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            $stmt = $conn->prepare(
                "INSERT INTO users
                (username, email, password, two_factor_enabled)
                VALUES (?, ?, ?, 1)"
            );

            $stmt->bind_param(
                "sss",
                $username,
                $email,
                $hashed_password
            );

            if ($stmt->execute()) {
                createAuditLog(
                $conn,
                $conn->insert_id,
                "REGISTRATION",
                "New user account registered"
            );

                header("Location: login.php?registered=1");
                exit;

            } else {

                $message = "Database error: " . $stmt->error;
                $message_type = "error";

            }

            $stmt->close();
        }

        $check->close();
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Create Account - SecureAuth</title>

    <link rel="stylesheet" href="register.css">
</head>

<body>

    <!-- Navigation -->
    <header class="navbar">

        <div class="nav-container">

            <a href="index.php" class="logo">
                <span class="logo-icon">🛡</span>
                SecureAuth
            </a>

            <a href="login.php" class="login-link">
                Already have an account?
                <span>Login</span>
            </a>

        </div>

    </header>


    <!-- Registration Section -->
    <main class="register-section">

        <div class="register-container">

            <!-- Left Side -->
            <div class="register-info">

                <div class="security-badge">
                    <span>●</span>
                    Secure Registration
                </div>

                <h1>
                    Create your
                    <span>secure account.</span>
                </h1>

                <p>
                    Protect your account with a strong password
                    and additional authentication security.
                </p>


                <div class="security-features">

                    <div class="security-feature">

                        <div class="feature-icon">
                            🔐
                        </div>

                        <div>
                            <h3>Strong Password Protection</h3>
                            <p>
                                Create a strong password and
                                receive real-time security feedback.
                            </p>
                        </div>

                    </div>


                    <div class="security-feature">

                        <div class="feature-icon">
                            🛡
                        </div>

                        <div>
                            <h3>Two-Factor Authentication</h3>
                            <p>
                                Add another layer of protection
                                using verification codes.
                            </p>
                        </div>

                    </div>


                    <div class="security-feature">

                        <div class="feature-icon">
                            🔎
                        </div>

                        <div>
                            <h3>Account Security Monitoring</h3>
                            <p>
                                Monitor your login activity and
                                account security from your dashboard.
                            </p>
                        </div>

                    </div>

                </div>

            </div>


            <!-- Registration Form -->
            <div class="register-card">

                <div class="form-header">

                    <h2>Create Account</h2>

                    <p>
                        Enter your details to get started.
                    </p>

                </div>


                <form action="register.php" method="POST">

                    <!-- Username -->
                    <div class="form-group">

                        <label for="username">
                            Username
                        </label>

                        <input
                            type="text"
                            id="username"
                            name="username"
                            placeholder="Enter your username"
                            autocomplete="username"
                            required
                        >

                    </div>


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
                            autocomplete="email"
                            required
                        >

                    </div>


                    <!-- Password -->
                    <div class="form-group">

                        <label for="password">
                            Password
                        </label>

                        <div class="password-input">

                            <input
                                type="password"
                                id="password"
                                name="password"
                                placeholder="Create a strong password"
                                autocomplete="new-password"
                                required
                            >

                            <button
                                type="button"
                                class="show-password"
                                onclick="togglePassword('password', this)"
                            >
                                Show
                            </button>

                        </div>

                    </div>


                    <!-- Password Strength -->
                    <div class="strength-container">

                        <div class="strength-header">

                            <span>Password Strength</span>

                            <span id="strength-text">
                                Enter a password
                            </span>

                        </div>

                        <div class="strength-bar">

                            <div
                                id="strength-progress"
                                class="strength-progress"
                            ></div>

                        </div>

                        <div class="password-requirements">

                            <p id="length">
                                <span>○</span>
                                At least 8 characters
                            </p>

                            <p id="uppercase">
                                <span>○</span>
                                One uppercase letter
                            </p>

                            <p id="lowercase">
                                <span>○</span>
                                One lowercase letter
                            </p>

                            <p id="number">
                                <span>○</span>
                                One number
                            </p>

                            <p id="special">
                                <span>○</span>
                                One special character
                            </p>

                        </div>

                    </div>


                    <!-- Confirm Password -->
                    <div class="form-group">

                        <label for="confirm-password">
                            Confirm Password
                        </label>

                        <div class="password-input">

                            <input
                                type="password"
                                id="confirm-password"
                                name="confirm_password"
                                placeholder="Confirm your password"
                                autocomplete="new-password"
                                required
                            >

                            <button
                                type="button"
                                class="show-password"
                                onclick="togglePassword('confirm-password', this)"
                            >
                                Show
                            </button>

                        </div>

                        <small id="password-match"></small>

                    </div>


                    <!-- Terms -->
                    <div class="terms">

                        <label>

                            <input
                                type="checkbox"
                                id="terms"
                                name="terms"
                                required
                            >

                            <span>
                                I agree to the
                                <a href="#">Terms & Conditions</a>
                                and
                                <a href="#">Privacy Policy</a>.
                            </span>

                        </label>

                    </div>


                    <!-- Submit -->
                    <button
                        type="submit"
                        class="create-account-btn"
                    >
                        Create Secure Account
                    </button>


                    <!-- Login -->
                    <p class="login-text">

                        Already have an account?

                        <a href="login.php">
                            Login here
                        </a>

                    </p>

                </form>

            </div>

        </div>

    </main>


    <!-- JavaScript -->
    <script>

        // Show / Hide Password
        function togglePassword(inputId, button) {

            const input = document.getElementById(inputId);

            if (input.type === "password") {

                input.type = "text";
                button.textContent = "Hide";

            } else {

                input.type = "password";
                button.textContent = "Show";

            }

        }


        // Password Strength
        const password = document.getElementById("password");

        password.addEventListener("input", function () {

            const value = password.value;

            let score = 0;

            const length = document.getElementById("length");
            const uppercase = document.getElementById("uppercase");
            const lowercase = document.getElementById("lowercase");
            const number = document.getElementById("number");
            const special = document.getElementById("special");

            // Length
            if (value.length >= 8) {

                score++;
                length.classList.add("valid");
                length.querySelector("span").textContent = "✓";

            } else {

                length.classList.remove("valid");
                length.querySelector("span").textContent = "○";

            }


            // Uppercase
            if (/[A-Z]/.test(value)) {

                score++;
                uppercase.classList.add("valid");
                uppercase.querySelector("span").textContent = "✓";

            } else {

                uppercase.classList.remove("valid");
                uppercase.querySelector("span").textContent = "○";

            }


            // Lowercase
            if (/[a-z]/.test(value)) {

                score++;
                lowercase.classList.add("valid");
                lowercase.querySelector("span").textContent = "✓";

            } else {

                lowercase.classList.remove("valid");
                lowercase.querySelector("span").textContent = "○";

            }


            // Number
            if (/[0-9]/.test(value)) {

                score++;
                number.classList.add("valid");
                number.querySelector("span").textContent = "✓";

            } else {

                number.classList.remove("valid");
                number.querySelector("span").textContent = "○";

            }


            // Special Character
            if (/[^A-Za-z0-9]/.test(value)) {

                score++;
                special.classList.add("valid");
                special.querySelector("span").textContent = "✓";

            } else {

                special.classList.remove("valid");
                special.querySelector("span").textContent = "○";

            }


            // Strength display
            const progress = document.getElementById("strength-progress");
            const strengthText = document.getElementById("strength-text");

            if (value.length === 0) {

                progress.style.width = "0%";
                strengthText.textContent = "Enter a password";
                strengthText.className = "";

            } else if (score <= 2) {

                progress.style.width = "35%";
                strengthText.textContent = "Weak";
                strengthText.className = "weak";

            } else if (score === 3 || score === 4) {

                progress.style.width = "70%";
                strengthText.textContent = "Medium";
                strengthText.className = "medium";

            } else {

                progress.style.width = "100%";
                strengthText.textContent = "Strong";
                strengthText.className = "strong";

            }

        });


        // Confirm Password
        const confirmPassword =
            document.getElementById("confirm-password");

        confirmPassword.addEventListener("input", function () {

            const passwordValue =
                document.getElementById("password").value;

            const match =
                document.getElementById("password-match");

            if (confirmPassword.value === "") {

                match.textContent = "";

            } else if (confirmPassword.value === passwordValue) {

                match.textContent = "✓ Passwords match";
                match.className = "match-success";

            } else {

                match.textContent = "✕ Passwords do not match";
                match.className = "match-error";

            }

        });

    </script>

</body>
</html>