<?php
/**
 * Phishing Detection Tool - Web Interface
 * EDUCATIONAL / SCHOOL PROJECT USE ONLY
 *
 * Lets the user pick which sample pair to compare, runs the
 * PhishingDetector, and displays the verdict on screen.
 */

require_once __DIR__ . '/PhishingDetector.php';

$samplesDir = __DIR__ . '/../sample-sites';
$originalFile = $samplesDir . '/original_wiki.html';
$cloneFile    = $samplesDir . '/cloned_wiki.html';

$report = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run_check'])) {
    $originalHtml = file_get_contents($originalFile);
    $suspectHtml  = file_get_contents($cloneFile);

    $detector = new PhishingDetector($originalHtml, $suspectHtml);
    $report   = $detector->generateReport();
}

function verdictColor(string $verdict): string
{
    return match ($verdict) {
        'PHISHING SUSPECTED'        => '#c0392b',
        'SUSPICIOUS - REVIEW MANUALLY' => '#e67e22',
        default                     => '#27ae60',
    };
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phishing Detection Tool</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f6f8;
            margin: 0;
            padding: 40px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #1b3a57; font-size: 22px; }
        p.desc { color: #555; font-size: 14px; }
        button {
            padding: 10px 20px;
            background: #1b3a57;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .result {
            margin-top: 25px;
            padding: 20px;
            border-radius: 6px;
            color: white;
        }
        .result table {
            width: 100%;
            margin-top: 10px;
            color: white;
            font-size: 13px;
        }
        .result td {
            padding: 4px 0;
        }
        .verdict {
            font-size: 18px;
            font-weight: bold;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ Phishing Detection Tool</h1>
    <p class="desc">
        Checks a sample website against a known original to detect signs of phishing.
    </p>
    <?php if (!$report): ?>
   <form method="POST">
       <button type="submit" name="run_check">Run Detection Check</button>
   </form>
   <?php endif; ?>
    <?php if ($report): ?>
        <div class="result" style="background: <?= verdictColor($report['verdict']) ?>;">
            <div class="verdict"><?= htmlspecialchars($report['verdict']) ?></div>
            <table>
                <tr><td>Original domain:</td><td><?= htmlspecialchars($report['original_domain']) ?></td></tr>
                <tr><td>Suspect domain:</td><td><?= htmlspecialchars($report['suspect_domain']) ?></td></tr>
                <tr><td>Content similarity:</td><td><?= htmlspecialchars($report['content_similarity']) ?></td></tr>
                <tr><td>Domain match:</td><td><?= $report['domain_match'] ? 'Yes' : 'No' ?></td></tr>
                <tr><td>Lookalike domain detected:</td><td><?= $report['lookalike_domain'] ? 'Yes ⚠️' : 'No' ?></td></tr>
                <tr><td>Form submits to:</td><td><?= htmlspecialchars($report['suspect_form_action']) ?></td></tr>
                <tr><td>Suspicious form action:</td><td><?= $report['suspicious_form_action'] ? 'Yes ⚠️' : 'No' ?></td></tr>
                <tr><td>Risk score:</td><td><?= $report['risk_score'] ?> / 100</td></tr>
            </table>
        </table>
        </div>
        <p style="margin-top:15px;">
            <a href="index.php" style="color:#1b3a57;text-decoration:underline;font-size:14px;">↻ Check Again</a>
        </p>
    <?php endif; ?>
</body>
</html>
