
<?php

session_start();

if (
    !isset($_SESSION["authenticated"]) ||
    $_SESSION["authenticated"] !== true
) {
    header("Location: login.php");
    exit;
}

set_time_limit(30);

$python = "C:\\Users\\utsav\\AppData\\Local\\Programs\\Python\\Python314\\python.exe";

$script = __DIR__ . DIRECTORY_SEPARATOR . "packet_capture.py";
$results_file = __DIR__ . DIRECTORY_SEPARATOR . "packet_results.json";
$pcap_file = __DIR__ . DIRECTORY_SEPARATOR . "packet_capture.pcap";

$message = "";
$message_type = "";
$command_output = "";
$scan_results = null;

// Start capture when the user submits the form.
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    if (!isset($_POST["start_capture"])) {
        $message = "Invalid capture request.";
        $message_type = "error";

    } elseif (!function_exists("shell_exec")) {
        $message = "PHP shell_exec() is disabled on this server.";
        $message_type = "error";

    } elseif (!is_file($python) || !is_file($script)) {
        $message = "Python executable or packet_capture.py was not found.";
        $message_type = "error";

    } else {

        // Remove the previous report so old results are not displayed
        // if the new capture fails.
        if (is_file($results_file)) {
            unlink($results_file);
        }

        $command =
            escapeshellarg($python) . " " .
            escapeshellarg($script);

        $command_output = shell_exec($command . " 2>&1");

        if (is_file($results_file)) {

            $json = file_get_contents($results_file);
            $scan_results = json_decode($json, true);

            if (
                is_array($scan_results) &&
                ($scan_results["status"] ?? "") === "success"
            ) {
                $message = "Packet capture completed successfully.";
                $message_type = "success";

            } else {
                $message = "Packet capture failed. Check the error details below.";
                $message_type = "error";
            }

        } else {
            $message = "No results file was created. Check Python and Npcap permissions.";
            $message_type = "error";
        }
    }
}


function e($value)
{
    return htmlspecialchars(
        (string)($value ?? ""),
        ENT_QUOTES,
        "UTF-8"
    );
}

$packet_count = (int)($scan_results["packet_count"] ?? 0);
$duration = $scan_results["duration"] ?? 0;
$protocol_counts = $scan_results["protocol_counts"] ?? [];
$packets = $scan_results["packets"] ?? [];

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Packet Capture | SecureAuth</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f3f4f6;
            color: #111827;
        }

        .navbar {
            background: #111827;
            color: white;
            padding: 18px 5%;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
        }

        .navbar h2 {
            margin: 0;
            font-size: 21px;
        }

        .navbar a {
            color: white;
            text-decoration: none;
            margin-left: 18px;
            font-size: 14px;
        }

        .container {
            width: 90%;
            max-width: 1250px;
            margin: 35px auto;
        }

        .intro {
            margin-bottom: 25px;
        }

        .intro h1 {
            margin-bottom: 10px;
        }

        .intro p {
            color: #6b7280;
            line-height: 1.6;
        }

        .panel {
            background: white;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 3px 12px rgba(0, 0, 0, 0.05);
        }

        .panel h2 {
            margin-top: 0;
            font-size: 20px;
        }

        .capture-button {
            background: #111827;
            color: white;
            border: none;
            padding: 13px 20px;
            border-radius: 7px;
            cursor: pointer;
            font-size: 15px;
        }

        .capture-button:hover {
            background: #374151;
        }

        .notice {
            padding: 14px 16px;
            border-radius: 7px;
            margin-bottom: 20px;
            line-height: 1.5;
        }

        .success {
            background: #dcfce7;
            color: #166534;
        }

        .error {
            background: #fee2e2;
            color: #991b1b;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 3px 12px rgba(0, 0, 0, 0.04);
        }

        .stat-card p {
            color: #6b7280;
            font-size: 13px;
            margin: 0 0 10px;
        }

        .stat-card h3 {
            margin: 0;
            font-size: 25px;
            overflow-wrap: anywhere;
        }

        .protocol-list {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .protocol-item {
            background: #f3f4f6;
            padding: 12px 15px;
            border-radius: 8px;
            font-size: 14px;
        }

        .table-wrap {
            overflow-x: auto;
            width: 100%;
        }

        table {
            width: 100%;
            min-width: 850px;
            border-collapse: collapse;
            font-size: 14px;
        }

        th, td {
            text-align: left;
            padding: 13px 12px;
            border-bottom: 1px solid #e5e7eb;
            white-space: nowrap;
        }

        th {
            background: #f9fafb;
            color: #374151;
        }

        .status {
            color: #166534;
            font-weight: bold;
        }

        .muted {
            color: #6b7280;
            line-height: 1.6;
        }

        details {
            margin-top: 18px;
        }

        pre {
            background: #111827;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        @media (max-width: 850px) {
            .stats {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .container {
                width: 94%;
            }
        }

        @media (max-width: 480px) {
            .stats {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>


<header class="navbar">
    
    <a href="dashboard.php" class="logo">
        🛡 SecureAuth
    </a>

    <nav>
        <a href="dashboard.php">Dashboard</a>
        <a href="network-scanner.php">Network Scanner</a>
        <a href="logout.php">Logout</a>
    </nav>
</header>


<main class="container">

    <section class="intro">
        <h1>Packet Capture &amp; Network Monitoring</h1>

        <p>
            Capture actual network traffic, inspect packet information,
            and review protocol statistics using Python and Scapy.
        </p>
    </section>

    <?php if ($message !== ""): ?>
        <div class="notice <?= e($message_type) ?>">
            <?= e($message) ?>
        </div>
    <?php endif; ?>

    <section class="panel">
        <h2>Start Packet Capture</h2>

        <p class="muted">
            Each capture runs for 10 seconds. Generate normal network
            activity during the capture to collect packets.
        </p>

        <form method="POST">
            <button
                type="submit"
                name="start_capture"
                value="1"
                class="capture-button"
            >
                Start 10-Second Capture
            </button>
        </form>
    </section>

    <?php if (is_array($scan_results)): ?>

        <?php if (($scan_results["status"] ?? "") === "success"): ?>

            <section class="stats">

                <div class="stat-card">
                    <p>Packets Captured</p>
                    <h3><?= $packet_count ?></h3>
                </div>

                <div class="stat-card">
                    <p>Capture Duration</p>
                    <h3><?= e($duration) ?> s</h3>
                </div>

                <div class="stat-card">
                    <p>Protocols Detected</p>
                    <h3><?= count($protocol_counts) ?></h3>
                </div>

                <div class="stat-card">
                    <p>Capture Status</p>
                    <h3 style="color: #16a34a;">Completed</h3>
                </div>

            </section>

            <section class="panel">
                <h2>Capture Information</h2>

                <p>
                    <strong>Started:</strong>
                    <?= e($scan_results["capture_start"] ?? "Unknown") ?>
                </p>

                <p>
                    <strong>Finished:</strong>
                    <?= e($scan_results["capture_end"] ?? "Unknown") ?>
                </p>

                <p>
                    <strong>Capture file:</strong>
                    packet_capture.pcap
                </p>
            </section>

            <section class="panel">
                <h2>Protocol Statistics</h2>

                <?php if (!empty($protocol_counts)): ?>

                    <div class="protocol-list">
                        <?php foreach ($protocol_counts as $protocol => $count): ?>
                            <div class="protocol-item">
                                <strong><?= e($protocol) ?></strong>:
                                <?= (int)$count ?> packets
                            </div>
                        <?php endforeach; ?>
                    </div>

                <?php else: ?>

                    <p class="muted">No packets were captured.</p>

                <?php endif; ?>
            </section>

            <section class="panel">
                <h2>Captured Packets</h2>

                <p class="muted">
                    Showing up to 500 packet records from the latest capture.
                </p>

                <?php if (!empty($packets)): ?>

                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Protocol</th>
                                    <th>Source Port</th>
                                    <th>Destination Port</th>
                                    <th>Length</th>
                                </tr>
                            </thead>

                            <tbody>
                                <?php foreach ($packets as $packet): ?>
                                    <tr>
                                        <td><?= e($packet["time"] ?? "—") ?></td>
                                        <td><?= e($packet["source_ip"] ?? "Unknown") ?></td>
                                        <td><?= e($packet["destination_ip"] ?? "Unknown") ?></td>
                                        <td><?= e($packet["protocol"] ?? "Other") ?></td>
                                        <td><?= e($packet["source_port"] ?? "—") ?></td>
                                        <td><?= e($packet["destination_port"] ?? "—") ?></td>
                                        <td><?= (int)($packet["length"] ?? 0) ?> bytes</td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                <?php else: ?>

                    <p class="muted">
                        No packets were captured during this session.
                    </p>

                <?php endif; ?>
            </section>

        <?php else: ?>

            <section class="panel">
                <h2>Capture Error</h2>
                <p><?= e($scan_results["message"] ?? "Unknown capture error.") ?></p>
            </section>

        <?php endif; ?>

    <?php else: ?>

        <section class="panel">
            <h2>Capture Results</h2>
            <p class="muted">
                No saved capture report is available yet.
                Start a capture to collect real network traffic.
            </p>
        </section>

    <?php endif; ?>

    <?php if ($command_output !== ""): ?>
        <details>
            <summary>Python execution output (troubleshooting)</summary>
            <pre><?= e($command_output) ?></pre>
        </details>
    <?php endif; ?>

</main>

</body>
</html>
