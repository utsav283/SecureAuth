
<?php
session_start();

require_once "db.php";

// Only authenticated users can access the scanner
if (
    !isset($_SESSION["authenticated"]) ||
    $_SESSION["authenticated"] !== true
) {
    header("Location: login.php");
    exit;
}

$scan_message = "";
$scan_results = null;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $target = trim($_POST["target"] ?? "");
    $start_port = (int)($_POST["start_port"] ?? 0);
    $end_port = (int)($_POST["end_port"] ?? 0);

    // Validate IP address
    if (!filter_var($target, FILTER_VALIDATE_IP)) {
        $scan_message = "Invalid IP address.";
    }

    // Validate port range
    elseif (
        $start_port < 1 ||
        $start_port > 65535 ||
        $end_port < 1 ||
        $end_port > 65535 ||
        $start_port > $end_port
    ) {
        $scan_message = "Invalid port range.";
    }

    else {
        $python = "C:\\Users\\utsav\\AppData\\Local\\Programs\\Python\\Python314\\python.exe";
        $script = __DIR__ . DIRECTORY_SEPARATOR . "network_scanner.py";
        $results_file = __DIR__ . DIRECTORY_SEPARATOR . "scan_results.json";

        // Run the Python scanner
        $command =
            escapeshellarg($python) . " " .
            escapeshellarg($script) . " " .
            escapeshellarg($target) . " " .
            escapeshellarg((string)$start_port) . " " .
            escapeshellarg((string)$end_port);

        $output = shell_exec($command . " 2>&1");

        // Read the latest scan results
        if (is_file($results_file)) {
            $json = file_get_contents($results_file);
            $scan_results = json_decode($json, true);

            if (!is_array($scan_results)) {
                $scan_results = null;
                $scan_message = "Unable to read scan results.";
            }
        } else {
            $scan_message = "Scan completed, but no results file was created.";
        }
    }
}

$username = $_SESSION["username"] ?? "User";
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Network Scanner - SecureAuth</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            background: #f4f6f8;
            color: #1f2937;
        }

        /* Navigation */
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
            gap: 15px;
        }

        .logo {
            text-decoration: none;
            color: #111827;
            font-size: 22px;
            font-weight: bold;
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .nav-link {
            text-decoration: none;
            color: #374151;
            font-size: 14px;
            padding: 10px 12px;
            border-radius: 6px;
        }

        .nav-link:hover {
            background: #f3f4f6;
        }

        .logout-button {
            text-decoration: none;
            background: #111827;
            color: #ffffff;
            padding: 10px 18px;
            border-radius: 6px;
            font-size: 14px;
        }

        .logout-button:hover {
            background: #374151;
        }

        /* Main page */
        .scanner-container {
            width: 90%;
            max-width: 1100px;
            margin: 35px auto;
        }

        .scanner-card {
            background: #ffffff;
            padding: 30px;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.06);
        }

        h1 {
            margin: 0 0 12px;
            font-size: 28px;
            color: #111827;
        }

        h2 {
            margin: 0 0 18px;
            font-size: 21px;
            color: #111827;
        }

        .description {
            color: #6b7280;
            line-height: 1.6;
            margin-bottom: 28px;
        }

        /* Form */
        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 14px;
            color: #374151;
        }

        input {
            width: 100%;
            padding: 12px 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            background: #ffffff;
            color: #111827;
            font-size: 15px;
            outline: none;
        }

        input:focus {
            border-color: #6b7280;
            box-shadow: 0 0 0 3px rgba(107, 114, 128, 0.12);
        }

        .port-row {
            display: flex;
            gap: 20px;
        }

        .port-row .form-group {
            flex: 1;
            min-width: 0;
        }

        .scan-button {
            padding: 12px 22px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
            background: #111827;
            color: #ffffff;
        }

        .scan-button:hover {
            background: #374151;
        }

        /* Messages */
        .message {
            margin-top: 24px;
            padding: 14px 16px;
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
            border-radius: 6px;
            line-height: 1.5;
        }

        .success-message {
            background: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }

        /* Summary cards */
        .summary {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 15px;
            margin-top: 30px;
        }

        .summary-card {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            min-width: 0;
        }

        .summary-card h3 {
            margin: 0 0 10px;
            font-size: 14px;
            font-weight: 600;
            color: #6b7280;
        }

        .summary-card p {
            margin: 0;
            font-size: 24px;
            font-weight: bold;
            color: #111827;
            overflow-wrap: anywhere;
        }

        /* Scan information */
        .scan-info {
            margin-top: 25px;
            padding: 20px;
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }

        .scan-info p {
            margin: 10px 0;
            line-height: 1.5;
            overflow-wrap: anywhere;
        }

        .scan-info p:last-child {
            margin-bottom: 0;
        }

        /* Results table */
        .results {
            margin-top: 30px;
        }

        .table-container {
            width: 100%;
            overflow-x: auto;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            background: #ffffff;
        }

        .results table {
            width: 100%;
            min-width: 1000px;
            border-collapse: collapse;
        }

        .results th,
        .results td {
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
        }

        .results th {
            background: #f9fafb;
            color: #374151;
            font-size: 14px;
            font-weight: 600;
            white-space: nowrap;
        }

        .results td {
            font-size: 14px;
            line-height: 1.5;
        }

        .results tbody tr:last-child td {
            border-bottom: none;
        }

        .results tbody tr:hover {
            background: #f9fafb;
        }

        .product {
            font-weight: 600;
            min-width: 160px;
        }

        .version {
            min-width: 150px;
            font-weight: 500;
        }

        .details {
            min-width: 300px;
            max-width: 450px;
            overflow-wrap: anywhere;
            color: #4b5563;
            line-height: 1.6;
        }

        .status-open {
            color: #15803d;
            font-weight: bold;
            white-space: nowrap;
        }

        .no-results {
            padding: 20px;
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            color: #6b7280;
            line-height: 1.5;
        }

        /* Responsive layout */
        @media (max-width: 900px) {
            .summary {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .scanner-container {
                width: 94%;
            }

            .navbar {
                padding: 18px 24px;
            }
        }

        @media (max-width: 600px) {
            .navbar {
                padding: 16px 18px;
            }

            .nav-container {
                align-items: flex-start;
            }

            .nav-links {
                gap: 5px;
                flex-wrap: wrap;
                justify-content: flex-end;
            }

            .nav-link {
                padding: 8px;
            }

            .logo {
                font-size: 19px;
                white-space: nowrap;
            }

            .scanner-container {
                width: 94%;
                margin: 20px auto;
            }

            .scanner-card {
                padding: 20px;
            }

            h1 {
                font-size: 23px;
            }

            h2 {
                font-size: 19px;
            }

            .port-row {
                flex-direction: column;
                gap: 0;
            }

            .summary {
                grid-template-columns: 1fr 1fr;
                gap: 10px;
            }

            .summary-card {
                padding: 15px;
            }

            .summary-card p {
                font-size: 20px;
            }

            .scan-button {
                width: 100%;
            }
        }
    </style>
</head>

<body>

<header class="navbar">
    <div class="nav-container">
        <a href="dashboard.php" class="logo">
            🛡 SecureAuth
        </a>

        <nav class="nav-links">
            <a href="dashboard.php" class="nav-link">Dashboard</a>
            <a href="packet-capture.php" class="nav-link">Packet Capture</a>
            <a href="logout.php" class="logout-button">Logout</a>
        </nav>
    </div>
</header>

<main class="scanner-container">
    <div class="scanner-card">

        <h1>🔍 Network Security Scanner</h1>

        <p class="description">
            Scan an authorized target for accessible TCP ports,
            services, products, and version information.
        </p>

        <!-- Scanner form -->
        <form method="POST">
            <div class="form-group">
                <label for="target">Target IP Address</label>
                <input
                    type="text"
                    id="target"
                    name="target"
                    placeholder="Example: 127.0.0.1"
                    value="<?= htmlspecialchars($_POST["target"] ?? "", ENT_QUOTES, "UTF-8") ?>"
                    required
                >
            </div>

            <div class="port-row">
                <div class="form-group">
                    <label for="start_port">Starting Port</label>
                    <input
                        type="number"
                        id="start_port"
                        name="start_port"
                        value="<?= htmlspecialchars($_POST["start_port"] ?? "1", ENT_QUOTES, "UTF-8") ?>"
                        min="1"
                        max="65535"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="end_port">Ending Port</label>
                    <input
                        type="number"
                        id="end_port"
                        name="end_port"
                        value="<?= htmlspecialchars($_POST["end_port"] ?? "1024", ENT_QUOTES, "UTF-8") ?>"
                        min="1"
                        max="65535"
                        required
                    >
                </div>
            </div>

            <button type="submit" class="scan-button">
                🔍 Start Scan
            </button>
        </form>

        <!-- Error or status message -->
        <?php if ($scan_message !== ""): ?>
            <div class="message">
                <?= htmlspecialchars($scan_message, ENT_QUOTES, "UTF-8") ?>
            </div>
        <?php endif; ?>

        <?php if ($scan_results !== null): ?>

            <!-- Scan summary -->
            <div class="summary">
                <div class="summary-card">
                    <h3>Target</h3>
                    <p>
                        <?= htmlspecialchars((string)($scan_results["target"] ?? "Unknown"), ENT_QUOTES, "UTF-8") ?>
                    </p>
                </div>

                <div class="summary-card">
                    <h3>Ports Scanned</h3>
                    <p>
                        <?= htmlspecialchars((string)($scan_results["total_ports"] ?? 0), ENT_QUOTES, "UTF-8") ?>
                    </p>
                </div>

                <div class="summary-card">
                    <h3>Open Ports</h3>
                    <p>
                        <?= htmlspecialchars((string)($scan_results["open_count"] ?? 0), ENT_QUOTES, "UTF-8") ?>
                    </p>
                </div>

                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <p>
                        <?= htmlspecialchars((string)($scan_results["scan_duration"] ?? 0), ENT_QUOTES, "UTF-8") ?>
                        sec
                    </p>
                </div>
            </div>

            <!-- Scan information -->
            <div class="scan-info">
                <p>
                    <strong>Port Range:</strong>
                    <?= htmlspecialchars((string)($scan_results["start_port"] ?? 0), ENT_QUOTES, "UTF-8") ?>
                    -
                    <?= htmlspecialchars((string)($scan_results["end_port"] ?? 0), ENT_QUOTES, "UTF-8") ?>
                </p>

                <p>
                    <strong>Closed Ports:</strong>
                    <?= htmlspecialchars((string)($scan_results["closed_count"] ?? 0), ENT_QUOTES, "UTF-8") ?>
                </p>

                <p>
                    <strong>Scan Completed:</strong>
                    <?= htmlspecialchars((string)($scan_results["scan_time"] ?? "Unknown"), ENT_QUOTES, "UTF-8") ?>
                </p>
            </div>

            <!-- Open ports and detected services -->
            <div class="results">
                <h2>📋 Open Ports &amp; Service Detection</h2>

                <?php if (!empty($scan_results["open_ports"]) && is_array($scan_results["open_ports"])): ?>

                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Product</th>
                                    <th>Version</th>
                                    <th>Details</th>
                                    <th>Status</th>
                                </tr>
                            </thead>

                            <tbody>
                                <?php foreach ($scan_results["open_ports"] as $result): ?>
                                    <tr>
                                        <td>
                                            <?= htmlspecialchars((string)($result["port"] ?? "Unknown"), ENT_QUOTES, "UTF-8") ?>
                                        </td>

                                        <td>
                                            <?= htmlspecialchars((string)($result["service"] ?? "Unknown"), ENT_QUOTES, "UTF-8") ?>
                                        </td>

                                        <td class="product">
                                            <?= htmlspecialchars((string)($result["product"] ?? "Unknown"), ENT_QUOTES, "UTF-8") ?>
                                        </td>

                                        <td class="version">
                                            <?= htmlspecialchars((string)($result["version"] ?? "Not detected"), ENT_QUOTES, "UTF-8") ?>
                                        </td>

                                        <td class="details">
                                            <?= htmlspecialchars((string)($result["details"] ?? "No additional information."), ENT_QUOTES, "UTF-8") ?>
                                        </td>

                                        <td class="status-open">
                                            ✓
                                            <?= htmlspecialchars((string)($result["status"] ?? "OPEN"), ENT_QUOTES, "UTF-8") ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                <?php else: ?>

                    <div class="no-results">
                        No open TCP ports were found in the selected range.
                    </div>

                <?php endif; ?>
            </div>

        <?php endif; ?>

    </div>
</main>

</body>
</html>
