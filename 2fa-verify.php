<?php

session_start();

require_once "db.php";
require_once "audit_log.php";

$message = "";
$message_type = "";


// Make sure user has logged in
if (!isset($_SESSION["user_id"]) || !isset($_SESSION["otp"])) {

    header("Location: login.php");
    exit;

}


// Verify OTP
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $entered_otp = "";

    if (isset($_POST["otp"]) && is_array($_POST["otp"])) {

        $entered_otp = implode("", $_POST["otp"]);

    }


    // Check OTP
if ($entered_otp === (string)$_SESSION["otp"]) {

    // OTP is correct

    // Record successful login
    $log_success = $conn->prepare(
        "INSERT INTO login_attempts
        (user_id, email, ip_address, success)
        VALUES (?, ?, ?, 1)"
    );

    $ip_address = $_SERVER["REMOTE_ADDR"];
    $user_id = $_SESSION["user_id"];
    $email = $_SESSION["email"];

    $log_success->bind_param(
        "iss",
        $user_id,
        $email,
        $ip_address
    );

    $log_success->execute();
    $log_success->close();

    // Record successful login in audit log
    createAuditLog(
        $conn,
        $user_id,
        "LOGIN_SUCCESS",
        "User successfully logged in after OTP verification"
    );

    unset($_SESSION["otp"]);
    unset($_SESSION["otp_time"]);

    $_SESSION["authenticated"] = true;

    header("Location: dashboard.php");
    exit;

} else {

    $message = "Invalid verification code.";
    $message_type = "error";

}

}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Two-Factor Verification - SecureAuth</title>

    <link rel="stylesheet" href="2fa.css">
</head>

<body>

    <!-- Navigation -->
    <header class="navbar">

        <div class="nav-container">

            <a href="index.php" class="logo">
                <span class="logo-icon">🛡</span>
                SecureAuth
            </a>

            <a href="login.php" class="back-link">
                ← Back to Login
            </a>

        </div>

    </header>


    <!-- 2FA Section -->
    <main class="verification-section">

        <div class="verification-container">

            <!-- Verification Card -->
            <div class="verification-card">

                <!-- Icon -->
                <div class="verification-icon">
                    🔐
                </div>


                <!-- Header -->
                <div class="verification-header">

                    <h1>Two-Factor Verification</h1>

                    <p>
                        We've sent a 6-digit verification code
                        to your registered email address.
                    </p>

                </div>
                
          <?php if (!empty($message)): ?>

    <div class="form-message <?php echo $message_type; ?>">
        <?php echo htmlspecialchars($message); ?>
    </div>

<?php endif; ?>


                <!-- Email Information -->
                <div class="email-info">

                    <span class="email-icon">✉</span>

                    <div>
                        <span>Verification code sent to</span>
                        <strong>u***@example.com</strong>
                    </div>

                </div>


                <!-- OTP Form -->
                <form action="2fa-verify.php" method="POST" id="otpForm">

                    <label for="otp">
                        Enter Verification Code
                    </label>

                    <div class="otp-inputs">

    <input
        type="text"
        name="otp[]"
        maxlength="1"
        inputmode="numeric"
        class="otp-input"
        autofocus
    >

    <input
        type="text"
        name="otp[]"
        maxlength="1"
        inputmode="numeric"
        class="otp-input"
    >

    <input
        type="text"
        name="otp[]"
        maxlength="1"
        inputmode="numeric"
        class="otp-input"
    >

    <input
        type="text"
        name="otp[]"
        maxlength="1"
        inputmode="numeric"
        class="otp-input"
    >

    <input
        type="text"
        name="otp[]"
        maxlength="1"
        inputmode="numeric"
        class="otp-input"
    >

    <input
        type="text"
        name="otp[]"
        maxlength="1"
        inputmode="numeric"
        class="otp-input"
    >

</div>


                    <!-- Timer -->
                    <div class="timer">

                        <span>Code expires in</span>

                        <strong id="timer">
                            02:00
                        </strong>

                    </div>


                    <!-- Verify Button -->
                    <button
                        type="submit"
                        class="verify-button"
                    >
                        Verify & Continue
                    </button>

                </form>


                <!-- Resend -->
                <div class="resend-section">

                    <span>
                        Didn't receive the code?
                    </span>

                    <button
                        type="button"
                        id="resendButton"
                        disabled
                    >
                        Resend Code
                    </button>

                </div>


                <!-- Security Notice -->
                <div class="security-notice">

                    <span>🛡</span>

                    <p>
                        Never share your verification code with
                        anyone. SecureAuth will never ask you to
                        provide your code outside this website.
                    </p>

                </div>

            </div>


            <!-- Right Side -->
            <div class="verification-info">

                <div class="security-badge">
                    <span>●</span>
                    Additional Security Layer
                </div>


                <h2>
                    One more step to
                    <span>protect your account.</span>
                </h2>


                <p>
                    Two-factor authentication adds an additional
                    layer of security to your account. Even if
                    someone obtains your password, they still
                    need your verification code.
                </p>


                <!-- Security Steps -->
                <div class="security-steps">

                    <div class="security-step">

                        <div class="step-number">
                            01
                        </div>

                        <div>
                            <h3>Password Verification</h3>

                            <p>
                                Your password is checked first.
                            </p>
                        </div>

                    </div>


                    <div class="security-step active">

                        <div class="step-number">
                            02
                        </div>

                        <div>
                            <h3>Code Verification</h3>

                            <p>
                                Enter the one-time verification code.
                            </p>
                        </div>

                    </div>


                    <div class="security-step">

                        <div class="step-number">
                            03
                        </div>

                        <div>
                            <h3>Secure Access</h3>

                            <p>
                                Access your account dashboard.
                            </p>
                        </div>

                    </div>

                </div>


                <!-- Protection Card -->
                <div class="protection-card">

                    <div class="protection-icon">
                        ✓
                    </div>

                    <div>
                        <strong>
                            Multi-Factor Authentication
                        </strong>

                        <p>
                            Your account has an additional
                            security layer.
                        </p>
                    </div>

                </div>

            </div>

        </div>

    </main>


    <!-- JavaScript -->
    <script>

        /* ==========================
           OTP INPUTS
        ========================== */

        const otpInputs =
            document.querySelectorAll(".otp-input");


        otpInputs.forEach((input, index) => {

            input.addEventListener("input", function () {

                // Only allow numbers
                this.value =
                    this.value.replace(/[^0-9]/g, "");

                // Move to next input
                if (this.value.length === 1 &&
                    index < otpInputs.length - 1) {

                    otpInputs[index + 1].focus();

                }

            });


            input.addEventListener("keydown", function (event) {

                // Backspace moves to previous input
                if (
                    event.key === "Backspace" &&
                    this.value === "" &&
                    index > 0
                ) {

                    otpInputs[index - 1].focus();

                }

            });


            // Allow paste of complete OTP
            input.addEventListener("paste", function (event) {

                event.preventDefault();

                const pastedData =
                    event.clipboardData
                        .getData("text")
                        .replace(/[^0-9]/g, "")
                        .slice(0, 6);

                pastedData.split("").forEach((number, i) => {

                    if (otpInputs[i]) {
                        otpInputs[i].value = number;
                    }

                });

                if (pastedData.length === 6) {
                    otpInputs[5].focus();
                }

            });

        });


        /* ==========================
           COUNTDOWN TIMER
        ========================== */

        let timeLeft = 120;

        const timer =
            document.getElementById("timer");

        const resendButton =
            document.getElementById("resendButton");


        const countdown = setInterval(function () {

            const minutes =
                Math.floor(timeLeft / 60);

            const seconds =
                timeLeft % 60;


            timer.textContent =
                String(minutes).padStart(2, "0")
                + ":" +
                String(seconds).padStart(2, "0");


            if (timeLeft <= 0) {

                clearInterval(countdown);

                timer.textContent = "Expired";

                resendButton.disabled = false;

                resendButton.classList.add("active");

            }


            timeLeft--;

        }, 1000);


        /* ==========================
           RESEND CODE
        ========================== */

        resendButton.addEventListener("click", function () {

            if (resendButton.disabled) {
                return;
            }

            alert("A new verification code will be sent.");

            timeLeft = 120;

            resendButton.disabled = true;

            resendButton.classList.remove("active");

            timer.textContent = "02:00";

        });


        /* ==========================
           FORM VALIDATION
        ========================== */

        document
            .getElementById("otpForm")
            .addEventListener("submit", function (event) {

                let otp = "";

                otpInputs.forEach(function (input) {
                    otp += input.value;
                });


                if (otp.length !== 6) {

                    event.preventDefault();

                    alert(
                        "Please enter the complete 6-digit verification code."
                    );

                }

            });

    </script>

</body>

</html>