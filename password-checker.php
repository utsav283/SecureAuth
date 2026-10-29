<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Password Strength Checker - SecureAuth</title>

    <link rel="stylesheet" href="password-checker.css">

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


    <!-- Password Checker -->
    <main class="checker-section">

        <div class="checker-container">

            <!-- Checker Card -->
            <div class="checker-card">

                <div class="checker-icon">
                    🔐
                </div>

                <div class="checker-header">

                    <h1>Password Strength Checker</h1>

                    <p>
                        Check how strong your password is
                        before using it.
                    </p>

                </div>


                <!-- Password Input -->
                <div class="form-group">

                    <label for="password">
                        Enter Password
                    </label>

                    <div class="password-input">

                        <input
                            type="password"
                            id="password"
                            placeholder="Enter your password"
                            autocomplete="off"
                        >

                        <button
                            type="button"
                            id="togglePassword"
                            class="show-password"
                        >
                            Show
                        </button>

                    </div>

                </div>


                <!-- Strength -->
                <div class="strength-section">

                    <div class="strength-header">

                        <span>Password Strength</span>

                        <strong id="strengthText">
                            Not entered
                        </strong>

                    </div>


                    <div class="strength-bar">

                        <div id="strengthBar"></div>

                    </div>

                </div>


                <!-- Requirements -->
                <div class="requirements">

                    <h3>Password Requirements</h3>

                    <p id="length">
                        ✗ At least 8 characters
                    </p>

                    <p id="uppercase">
                        ✗ At least one uppercase letter
                    </p>

                    <p id="lowercase">
                        ✗ At least one lowercase letter
                    </p>

                    <p id="number">
                        ✗ At least one number
                    </p>

                    <p id="special">
                        ✗ At least one special character
                    </p>

                </div>


                <!-- Recommendation -->
                <div
                    class="recommendation"
                    id="recommendation"
                >

                    💡 Enter a password to check
                    its strength.

                </div>


                <!-- Security Notice -->
                <div class="security-notice">

                    <span>🛡</span>

                    <div>

                        <strong>Privacy Notice</strong>

                        <p>
                            Your password is checked locally
                            in your browser and is not sent
                            or stored by this page.
                        </p>

                    </div>

                </div>


                <!-- Buttons -->
                <div class="button-group">

                    <button
                        type="button"
                        id="clearButton"
                        class="clear-button"
                    >
                        Clear Password
                    </button>

                    <a
                        href="register.php"
                        class="register-button"
                    >
                        Create Account
                    </a>

                </div>

            </div>


            <!-- Information Section -->
            <div class="checker-info">

                <div class="security-badge">

                    <span>●</span>

                    Password Security

                </div>


                <h2>

                    Create a password that
                    <span>protects your account.</span>

                </h2>


                <p>

                    A strong password makes it harder
                    for attackers to gain unauthorized
                    access to your account.

                </p>


                <!-- Security Tips -->
                <div class="security-tips">

                    <div class="security-tip">

                        <div class="tip-icon">
                            ✓
                        </div>

                        <div>

                            <h3>Use 8+ Characters</h3>

                            <p>
                                Longer passwords are generally
                                harder to guess.
                            </p>

                        </div>

                    </div>


                    <div class="security-tip">

                        <div class="tip-icon">
                            ✓
                        </div>

                        <div>

                            <h3>Mix Character Types</h3>

                            <p>
                                Use uppercase, lowercase,
                                numbers and symbols.
                            </p>

                        </div>

                    </div>


                    <div class="security-tip">

                        <div class="tip-icon">
                            ✓
                        </div>

                        <div>

                            <h3>Avoid Common Passwords</h3>

                            <p>
                                Avoid passwords such as
                                password123 or your name.
                            </p>

                        </div>

                    </div>


                    <div class="security-tip">

                        <div class="tip-icon">
                            ✓
                        </div>

                        <div>

                            <h3>Don't Reuse Passwords</h3>

                            <p>
                                Use a different password
                                for each important account.
                            </p>

                        </div>

                    </div>

                </div>


                <!-- Security Card -->
                <div class="protection-card">

                    <div class="protection-icon">
                        🛡
                    </div>

                    <div>

                        <strong>
                            Secure Password Practices
                        </strong>

                        <p>
                            Strong passwords provide an
                            important layer of account security.
                        </p>

                    </div>

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

        const passwordInput =
            document.getElementById("password");

        const strengthBar =
            document.getElementById("strengthBar");

        const strengthText =
            document.getElementById("strengthText");

        const recommendation =
            document.getElementById("recommendation");

        const togglePassword =
            document.getElementById("togglePassword");

        const clearButton =
            document.getElementById("clearButton");


        /* ==========================
           PASSWORD VISIBILITY
        ========================== */

        togglePassword.addEventListener(
            "click",
            function () {

                if (passwordInput.type === "password") {

                    passwordInput.type = "text";

                    togglePassword.textContent = "Hide";

                } else {

                    passwordInput.type = "password";

                    togglePassword.textContent = "Show";

                }

            }
        );


        /* ==========================
           PASSWORD STRENGTH
        ========================== */

        passwordInput.addEventListener(
            "input",
            checkPassword
        );


        function checkPassword() {

            const password =
                passwordInput.value;


            /* Requirements */

            const hasLength =
                password.length >= 8;

            const hasUppercase =
                /[A-Z]/.test(password);

            const hasLowercase =
                /[a-z]/.test(password);

            const hasNumber =
                /[0-9]/.test(password);

            const hasSpecial =
                /[^A-Za-z0-9]/.test(password);


            /* Update requirement display */

            updateRequirement(
                "length",
                hasLength,
                "At least 8 characters"
            );

            updateRequirement(
                "uppercase",
                hasUppercase,
                "At least one uppercase letter"
            );

            updateRequirement(
                "lowercase",
                hasLowercase,
                "At least one lowercase letter"
            );

            updateRequirement(
                "number",
                hasNumber,
                "At least one number"
            );

            updateRequirement(
                "special",
                hasSpecial,
                "At least one special character"
            );


            /* Calculate score */

            let score = 0;

            if (hasLength) score++;
            if (hasUppercase) score++;
            if (hasLowercase) score++;
            if (hasNumber) score++;
            if (hasSpecial) score++;


            /* Empty password */

            if (password.length === 0) {

                strengthBar.style.width = "0%";

                strengthText.textContent =
                    "Not entered";

                recommendation.textContent =
                    "💡 Enter a password to check its strength.";

                return;

            }


            /* Remove previous strength classes */

strengthText.classList.remove(
    "strength-weak",
    "strength-good",
    "strength-strong"
);

strengthBar.classList.remove(
    "bar-weak",
    "bar-good",
    "bar-strong"
);


/* Weak */

if (score <= 2) {

    strengthBar.style.width = "30%";

    strengthText.textContent = "Weak";

    strengthText.classList.add("strength-weak");

    strengthBar.classList.add("bar-weak");

    recommendation.textContent =
        "⚠️ Your password is weak. Add more characters and different character types.";

}


/* Good */

else if (score <= 4) {

    strengthBar.style.width = "65%";

    strengthText.textContent = "Good";

    strengthText.classList.add("strength-good");

    strengthBar.classList.add("bar-good");

    recommendation.textContent =
        "💡 Your password is good. Add the missing requirements to make it stronger.";

}


/* Strong */

else {

    strengthBar.style.width = "100%";

    strengthText.textContent = "Strong";

    strengthText.classList.add("strength-strong");

    strengthBar.classList.add("bar-strong");

    recommendation.textContent =
        "✓ Strong password. This password meets all the basic security requirements.";

}

        }


        /* ==========================
           REQUIREMENT UPDATE
        ========================== */

        function updateRequirement(
            id,
            passed,
            text
        ) {

            const element =
                document.getElementById(id);


            if (passed) {

                element.textContent =
                    "✓ " + text;

                element.classList.add("passed");

            } else {

                element.textContent =
                    "✗ " + text;

                element.classList.remove("passed");

            }

        }


        /* ==========================
           CLEAR BUTTON
        ========================== */

        clearButton.addEventListener(
            "click",
            function () {

                passwordInput.value = "";

                passwordInput.type = "password";

                togglePassword.textContent =
                    "Show";

                strengthBar.style.width =
                    "0%";

                strengthText.textContent =
                    "Not entered";

                recommendation.textContent =
                    "💡 Enter a password to check its strength.";


                updateRequirement(
                    "length",
                    false,
                    "At least 8 characters"
                );

                updateRequirement(
                    "uppercase",
                    false,
                    "At least one uppercase letter"
                );

                updateRequirement(
                    "lowercase",
                    false,
                    "At least one lowercase letter"
                );

                updateRequirement(
                    "number",
                    false,
                    "At least one number"
                );

                updateRequirement(
                    "special",
                    false,
                    "At least one special character"
                );

                passwordInput.focus();

            }
        );

    </script>

</body>

</html>