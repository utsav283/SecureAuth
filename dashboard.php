<?php

session_start();

require_once "db.php";

// Only allow users who passed 2FA
if (
    !isset($_SESSION["authenticated"]) ||
    $_SESSION["authenticated"] !== true
) {

    header("Location: login.php");
    exit;

}

$username = $_SESSION["username"] ?? "User";
$email = $_SESSION["email"] ?? "";
$user_id = $_SESSION["user_id"] ?? 0;


// Get login history for the current user
$stmt = $conn->prepare(
    "SELECT email, ip_address, attempt_time, success
     FROM login_attempts
     WHERE user_id = ?
     ORDER BY attempt_time DESC
     LIMIT 10"
);
$audit_stmt = $conn->prepare(
    "SELECT action, description, ip_address, created_at
     FROM audit_logs
     WHERE user_id = ?
     ORDER BY created_at DESC
     LIMIT 10"
);

$audit_stmt->bind_param("i", $user_id);
$audit_stmt->execute();
$audit_logs = $audit_stmt->get_result();

$stmt->bind_param("i", $user_id);
$stmt->execute();
$login_history = $stmt->get_result();

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Dashboard - SecureAuth</title>

    <style>

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background: #f4f7fb;
            color: #1f2937;
        }

        .navbar {
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
            padding: 18px 40px;
        }

        .nav-container {
            max-width: 1100px;
            margin: auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            text-decoration: none;
            color: #111827;
            font-size: 22px;
            font-weight: bold;
        }

        .logo-icon {
            margin-right: 8px;
        }

        .logout-button {
            text-decoration: none;
            background: #111827;
            color: white;
            padding: 10px 18px;
            border-radius: 6px;
            font-size: 14px;
        }

        .dashboard {
            max-width: 1100px;
            margin: 60px auto;
            padding: 0 25px;
        }

        .welcome {
            margin-bottom: 35px;
        }

        .welcome h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }

        .welcome p {
            color: #6b7280;
        }

        .security-status {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
        }

        .security-status h2 {
            margin-bottom: 15px;
        }

        .status {
            display: inline-block;
            background: #ecfdf3;
            color: #15803d;
            border: 1px solid #bbf7d0;
            padding: 8px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: bold;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }

        .card {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 25px;
        }

        .card-icon {
            font-size: 28px;
            margin-bottom: 15px;
        }

        .card h3 {
            margin-bottom: 8px;
        }

        .card p {
            color: #6b7280;
            font-size: 14px;
            line-height: 1.6;
        }


        /* Login History */

        .login-history {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 25px;
            margin-top: 25px;
        }

        .login-history h2 {
            margin-bottom: 20px;
        }

        .table-container {
            overflow-x: auto;
        }

        .login-history table {
            width: 100%;
            border-collapse: collapse;
        }

        .login-history th,
        .login-history td {
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }

        .login-history th {
            background: #f9fafb;
            font-size: 14px;
        }

        .success-status {
            color: #15803d;
            font-weight: bold;
        }

        .failed-status {
            color: #dc2626;
            font-weight: bold;
        }

        .no-history {
            text-align: center;
            color: #6b7280;
            padding: 25px;
        }


        @media (max-width: 768px) {

            .cards {
                grid-template-columns: 1fr;
            }

            .navbar {
                padding: 18px 20px;
            }

            .dashboard {
                margin: 35px auto;
            }

        }

    </style>

</head>

<body>


    <!-- Navigation -->

    <header class="navbar">

        <div class="nav-container">

            <a href="dashboard.php" class="logo">

                <span class="logo-icon">🛡</span>

                SecureAuth

            </a>


            <a href="logout.php" class="logout-button">

                Logout

            </a>

        </div>

    </header>



    <!-- Dashboard -->

    <main class="dashboard">


        <!-- Welcome -->

        <div class="welcome">

            <h1>

                Welcome,
                <?php echo htmlspecialchars($username); ?>!

            </h1>

            <p>

                You have successfully authenticated using
                two-factor authentication.

            </p>

        </div>



        <!-- Security Status -->

        <div class="security-status">

            <h2>

                Account Security

            </h2>

            <span class="status">

                ✓ Two-Factor Authentication Enabled

            </span>

        </div>



        <!-- Dashboard Cards -->

        <div class="cards">


            <!-- Account -->

            <div class="card">

                <div class="card-icon">

                    👤

                </div>

                <h3>

                    Account

                </h3>

                <p>

                    Username:
                    <?php echo htmlspecialchars($username); ?>

                </p>

                <p>

                    Email:
                    <?php echo htmlspecialchars($email); ?>

                </p>

            </div>



            <!-- Password -->

            <div class="card">

                <div class="card-icon">

                    🔐

                </div>

                <h3>

                    Password

                </h3>

                <p>

                    Your password is securely stored
                    using password hashing.

                </p>

            </div>



            <!-- Two Factor -->

            <div class="card">

                <div class="card-icon">

                    🛡

                </div>

                <h3>

                    Two-Factor Authentication

                </h3>

                <p>

                    Additional verification is required
                    before accessing your account.

                </p>

            </div>

                        <!-- Network Scanner -->

            <div class="card">

                <div class="card-icon">

                    🔍

                </div>

                <h3>

                    Network Scanner

                </h3>

                <p>

                    Scan an authorized target and identify
                    accessible TCP ports and services.

                </p>

                <br>

                <a href="network-scanner.php"
                   style="
                       display: inline-block;
                       padding: 10px 16px;
                       background: #111827;
                       color: white;
                       text-decoration: none;
                       border-radius: 6px;
                       font-size: 14px;
                   ">

                    Open Network Scanner

                </a>

            </div>


        </div>

<!-- Packet Capture -->
<div class="card">
    <div class="card-icon">📡</div>
    <h3>Packet Capture</h3>
    <p>
        Capture and analyze real network traffic,
        including IP addresses, protocols and ports.
    </p>
    <br>
    <a href="packet-capture.php"
       style="
           display: inline-block;
           padding: 10px 16px;
           background: #111827;
           color: white;
           text-decoration: none;
           border-radius: 6px;
           font-size: 14px;
       ">
        Open Packet Capture
    </a>
</div>

        <!-- Login History -->

        <div class="login-history">

            <h2>

                🔐 Login History

            </h2>


            <div class="table-container">

                <table>

                    <thead>

                        <tr>

                            <th>Email</th>

                            <th>IP Address</th>

                            <th>Date & Time</th>

                            <th>Status</th>

                        </tr>

                    </thead>


                    <tbody>


                        <?php if ($login_history->num_rows > 0): ?>


                            <?php while ($row = $login_history->fetch_assoc()): ?>

                                <tr>


                                    <td>

                                        <?php
                                        echo htmlspecialchars(
                                            $row["email"]
                                        );
                                        ?>

                                    </td>


                                    <td>

                                        <?php
                                        echo htmlspecialchars(
                                            $row["ip_address"]
                                        );
                                        ?>

                                    </td>


                                    <td>

                                        <?php
                                        echo htmlspecialchars(
                                            $row["attempt_time"]
                                        );
                                        ?>

                                    </td>


                                    <td>


                                        <?php if ($row["success"] == 1): ?>

                                            <span class="success-status">

                                                ✓ Successful

                                            </span>


                                        <?php else: ?>

                                            <span class="failed-status">

                                                ✕ Failed

                                            </span>

                                        <?php endif; ?>


                                    </td>


                                </tr>

                            <?php endwhile; ?>


                        <?php else: ?>


                            <tr>

                                <td
                                    colspan="4"
                                    class="no-history"
                                >

                                    No login history available.

                                </td>

                            </tr>


                        <?php endif; ?>


                    </tbody>

                </table>

            </div>

        </div>
        
        <!-- Audit Logs -->
<div class="login-history">
    <h2>📋 Audit Logs</h2>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Action</th>
                    <th>Description</th>
                    <th>IP Address</th>
                    <th>Date & Time</th>
                </tr>
            </thead>

            <tbody>

                <?php if ($audit_logs->num_rows > 0): ?>

                    <?php while ($row = $audit_logs->fetch_assoc()): ?>

                        <tr>
                            <td>
                                <?php echo htmlspecialchars($row["action"]); ?>
                            </td>

                            <td>
                                <?php echo htmlspecialchars($row["description"]); ?>
                            </td>

                            <td>
                                <?php echo htmlspecialchars($row["ip_address"]); ?>
                            </td>

                            <td>
                                <?php echo htmlspecialchars($row["created_at"]); ?>
                            </td>
                        </tr>

                    <?php endwhile; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="4" class="no-history">
                            No audit logs available.
                        </td>
                    </tr>

                <?php endif; ?>

            </tbody>
        </table>
    </div>
</div>


    </main>


</body>

</html>

<?php

$stmt->close();
$audit_stmt->close();

?>