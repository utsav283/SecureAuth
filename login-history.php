<?php

session_start();

require_once "db.php";

// Make sure the user is logged in
if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION["user_id"];

// Get login history for current user
$stmt = $conn->prepare(
    "SELECT email, ip_address, attempt_time, success
     FROM login_attempts
     WHERE user_id = ?
     ORDER BY attempt_time DESC"
);

$stmt->bind_param("i", $user_id);

$stmt->execute();

$result = $stmt->get_result();

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login History - SecureAuth</title>

    <style>

        body {
            font-family: Arial, sans-serif;
            background: #f4f7fb;
            margin: 0;
            padding: 0;
        }

        .container {
            width: 90%;
            max-width: 1100px;
            margin: 50px auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }

        h1 {
            margin: 0;
        }

        .back-button {
            text-decoration: none;
            padding: 10px 16px;
            background: #333;
            color: white;
            border-radius: 6px;
        }

        .history-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th,
        td {
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background: #f1f3f6;
        }

        .success {
            color: green;
            font-weight: bold;
        }

        .failed {
            color: red;
            font-weight: bold;
        }

        .no-history {
            text-align: center;
            padding: 30px;
            color: #666;
        }

    </style>

</head>

<body>

<div class="container">

    <div class="header">

        <h1>🔐 Login History</h1>

        <a href="dashboard.php" class="back-button">
            Back to Dashboard
        </a>

    </div>


    <div class="history-card">

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

            <?php if ($result->num_rows > 0): ?>

                <?php while ($row = $result->fetch_assoc()): ?>

                    <tr>

                        <td>
                            <?php echo htmlspecialchars($row["email"]); ?>
                        </td>

                        <td>
                            <?php echo htmlspecialchars($row["ip_address"]); ?>
                        </td>

                        <td>
                            <?php echo htmlspecialchars($row["attempt_time"]); ?>
                        </td>

                        <td>

                            <?php if ($row["success"] == 1): ?>

                                <span class="success">
                                    ✓ Successful
                                </span>

                            <?php else: ?>

                                <span class="failed">
                                    ✕ Failed
                                </span>

                            <?php endif; ?>

                        </td>

                    </tr>

                <?php endwhile; ?>

            <?php else: ?>

                <tr>

                    <td colspan="4" class="no-history">
                        No login history available.
                    </td>

                </tr>

            <?php endif; ?>

            </tbody>

        </table>

    </div>

</div>

</body>

</html>

<?php

$stmt->close();

?>