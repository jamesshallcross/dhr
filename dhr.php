#!/usr/bin/env php
<?php

class ConsoleTable {
    private $headers = [];
    private $rows = [];
    private $columnWidths = [];
    
    public function setHeaders(array $headers) {
        $this->headers = $headers;
        $this->calculateColumnWidths();
    }
    
    public function addRow(array $row) {
        $this->rows[] = $row;
        $this->calculateColumnWidths();
    }
    
    private function stripAnsiCodes($text) {
        return preg_replace('/\033\[[0-9;]*m/', '', $text);
    }
    
    private function getDisplayWidth($text) {
        return mb_strlen($this->stripAnsiCodes($text));
    }
    
    private function calculateColumnWidths() {
        $this->columnWidths = [];
        
        // Check headers
        foreach ($this->headers as $i => $header) {
            $this->columnWidths[$i] = $this->getDisplayWidth($header);
        }
        
        // Check all rows
        foreach ($this->rows as $row) {
            foreach ($row as $i => $cell) {
                $width = $this->getDisplayWidth($cell);
                $this->columnWidths[$i] = max($this->columnWidths[$i] ?? 0, $width);
            }
        }
    }
    
    private function padCell($content, $width) {
        $displayWidth = $this->getDisplayWidth($content);
        $padding = max(0, $width - $displayWidth);
        return $content . str_repeat(' ', $padding);
    }
    
    public function render() {
        if (empty($this->headers)) {
            return '';
        }
        
        $output = '';
        
        // Render headers
        foreach ($this->headers as $i => $header) {
            $output .= $this->padCell($header, $this->columnWidths[$i] + 2);
        }
        $output = rtrim($output) . "\n";
        
        // Render separator
        $totalWidth = array_sum($this->columnWidths) + (count($this->columnWidths) * 2);
        $output .= str_repeat('─', $totalWidth) . "\n";
        
        // Render rows
        foreach ($this->rows as $row) {
            foreach ($row as $i => $cell) {
                $output .= $this->padCell($cell, $this->columnWidths[$i] + 2);
            }
            $output = rtrim($output) . "\n";
        }
        
        return $output;
    }
}

class DomainHealthReporter {
    private $domain;
    private $dnsServer;
    private $colors;
    private $maxWidth = 120;
    private $results = [];
    
    public function __construct($domain, $dnsServer = null) {
        $this->domain = $this->sanitizeDomain($domain);
        $this->dnsServer = $dnsServer;
        $this->initializeColors();
    }
    
    private function initializeColors() {
        $this->colors = [
            'reset' => "\033[0m",
            'bold' => "\033[1m",
            'dim' => "\033[2m",
            'red' => "\033[31m",
            'green' => "\033[32m",
            'yellow' => "\033[33m",
            'blue' => "\033[34m",
            'magenta' => "\033[35m",
            'cyan' => "\033[36m",
            'white' => "\033[37m",
            'bg_blue' => "\033[44m",
            'bg_green' => "\033[42m",
            'bg_red' => "\033[41m",
        ];
    }
    
    private function colorize($text, $color, $bold = false) {
        $prefix = $bold ? $this->colors['bold'] : '';
        return $prefix . $this->colors[$color] . $text . $this->colors['reset'];
    }
    
    private function sanitizeDomain($domain) {
        $domain = strtolower(trim($domain));
        $domain = preg_replace('#^https?://#', '', $domain);
        $domain = preg_replace('#^www\.#', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        return $domain;
    }
    
    private function printHeader() {
        $title = "DOMAIN HEALTH REPORTER";
        $subtitle = "Advanced Domain Analysis & Security Assessment";
        $border = str_repeat('═', $this->maxWidth);
        
        echo "\n";
        echo $this->colorize($border, 'cyan') . "\n";
        echo $this->colorize(str_pad($title, $this->maxWidth, ' ', STR_PAD_BOTH), 'white', true) . "\n";
        echo $this->colorize(str_pad($subtitle, $this->maxWidth, ' ', STR_PAD_BOTH), 'blue') . "\n";
        echo $this->colorize($border, 'cyan') . "\n\n";
        
        $dnsInfo = $this->dnsServer ? $this->dnsServer : $this->getSystemDns();
        
        // Analysis information in columns
        $col1Width = 30;
        $col2Width = 40;
        
        // Headers
        echo $this->colorize('ANALYSIS TARGET', 'blue', true) . 
             str_repeat(' ', $col1Width - strlen('ANALYSIS TARGET')) . 
             $this->colorize('DNS SERVER', 'blue', true) . 
             str_repeat(' ', $col2Width - strlen('DNS SERVER')) . 
             $this->colorize('TIMESTAMP', 'blue', true) . "\n";
        echo str_repeat('─', $this->maxWidth) . "\n";
        
        // Data row
        echo $this->colorize($this->domain, 'yellow', true) . 
             str_repeat(' ', $col1Width - strlen($this->domain)) . 
             $this->colorize($dnsInfo, 'green') . 
             str_repeat(' ', $col2Width - strlen($dnsInfo)) . 
             $this->colorize(date('Y-m-d H:i:s T'), 'white') . "\n";
        echo "\n";
    }
    
    private function getSystemDns() {
        $output = shell_exec('dig | grep SERVER 2>/dev/null');
        if ($output && preg_match('/SERVER: ([^#]+)/', $output, $matches)) {
            return trim($matches[1]);
        }
        return '8.8.8.8#53';
    }
    
    private function printSectionHeader($title, $icon = '📊') {
        $border = str_repeat('─', 60);
        echo $this->colorize($border, 'cyan') . "\n";
        echo $this->colorize("$icon $title", 'cyan', true) . "\n";
        echo $this->colorize($border, 'cyan') . "\n";
    }
    
    private function dnsLookup($domain, $type = 'A', $server = null) {
        $cmd = 'dig ';
        if ($server) {
            $cmd .= "@$server ";
        }
        $cmd .= "+short $type $domain 2>/dev/null";
        
        $output = shell_exec($cmd);
        return $output ? array_filter(explode("\n", trim($output))) : [];
    }
    
    private function whoisLookup($input) {
        $output = shell_exec("whois '$input' 2>/dev/null");
        return $output ?: '';
    }
    
    private function getOrgInfo($ip) {
        $whois = $this->whoisLookup($ip);
        // Try multiple organization field patterns
        $patterns = [
            '/Organization:\s*(.+?)\s*\(/i',  // Organization: WPEngine, Inc. (WPENG)
            '/OrgName:\s*(.+)/i',             // OrgName: Example Corp
            '/org-name:\s*(.+)/i',            // org-name: Example Corp
            '/descr:\s*(.+)/i'                // descr: Example Description
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whois, $matches)) {
                return trim($matches[1]);
            }
        }
        return 'Unknown';
    }
    
    private function analyzeHostInfo() {
        $this->printSectionHeader('HOST INFORMATION ANALYSIS', '🖥️');
        
        // Use external column command for perfect alignment
        $data = [];
        $hosts = [
            $this->domain,
            "www.{$this->domain}"
        ];
        
        foreach ($hosts as $host) {
            $records = $this->dnsLookup($host, 'A', $this->dnsServer);
            
            if (empty($records)) {
                $data[] = [
                    $host,
                    'No A record',
                    'N/A',
                    'NO_RECORD'
                ];
                continue;
            }
            
            $record = $records[0];
            
            if (filter_var($record, FILTER_VALIDATE_IP)) {
                $org = $this->getOrgInfo($record);
                $data[] = [
                    $host,
                    $record,
                    $org,
                    'RESOLVED'
                ];
            } else {
                // CNAME record
                $data[] = [
                    $host,
                    $record,
                    '',
                    'CNAME'
                ];
                
                // Resolve CNAME to final IP
                $finalIp = $this->resolveCnameChain($record);
                if ($finalIp) {
                    $org = $this->getOrgInfo($finalIp);
                    $data[] = [
                        "  └─ $record",
                        $finalIp,
                        $org,
                        'RESOLVED'
                    ];
                }
            }
        }
        
        // Create pipe-delimited data
        $output = "HOSTNAME|IP/CNAME|ORGANIZATION|STATUS\n";
        foreach ($data as $row) {
            $output .= implode('|', $row) . "\n";
        }
        
        // Use column command for perfect alignment
        $formatted = shell_exec("echo " . escapeshellarg($output) . " | column -t -s '|'");
        
        // Apply colors to the formatted output
        $lines = explode("\n", trim($formatted));
        foreach ($lines as $i => $line) {
            if ($i === 0) {
                // Header line
                echo $this->colorize($line, 'white', true) . "\n";
                echo str_repeat('─', strlen($line)) . "\n";
            } else if (!empty($line)) {
                // Data line - apply colors based on content
                $coloredLine = $line;
                // Apply status colors first (most specific)
                $coloredLine = preg_replace('/\bRESOLVED\b/', $this->colorize('✓ RESOLVED', 'green'), $coloredLine);
                $coloredLine = preg_replace('/\bCNAME\b/', $this->colorize('↳ CNAME', 'yellow'), $coloredLine);
                $coloredLine = preg_replace('/\bNO_RECORD\b/', $this->colorize('❌ NO_RECORD', 'red'), $coloredLine);
                // Apply IP addresses
                $coloredLine = preg_replace('/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/', $this->colorize('$0', 'green'), $coloredLine);
                // Apply organization names
                $coloredLine = preg_replace('/\bWPEngine[^|]*/', $this->colorize('$0', 'magenta'), $coloredLine);
                // Apply CNAME hostnames (but not if already colored)
                $coloredLine = preg_replace('/(?<!\033\[)\b[a-zA-Z0-9.-]+\.(?:com|net|org|co\.uk)\.?\b(?!\033)/', $this->colorize('$0', 'yellow'), $coloredLine);
                echo $coloredLine . "\n";
            }
        }
        echo "\n";
    }
    
    private function resolveCnameChain($hostname, $depth = 0) {
        if ($depth > 10) return null;
        
        $records = $this->dnsLookup($hostname, 'A', $this->dnsServer);
        if (empty($records)) return null;
        
        $record = $records[0];
        if (filter_var($record, FILTER_VALIDATE_IP)) {
            return $record;
        }
        
        return $this->resolveCnameChain($record, $depth + 1);
    }
    
    private function analyzeRedirects() {
        $this->printSectionHeader('HTTP/HTTPS REDIRECT ANALYSIS', '🔄');
        
        printf("%-35s %-8s %-8s %-35s %s\n",
            $this->colorize('TEST URL', 'white', true),
            $this->colorize('CODE', 'white', true),
            $this->colorize('TIME', 'white', true),
            $this->colorize('FINAL URL', 'white', true),
            $this->colorize('STATUS', 'white', true)
        );
        echo str_repeat('─', $this->maxWidth) . "\n";
        
        $urls = [
            "http://{$this->domain}",
            "http://www.{$this->domain}",
            "https://{$this->domain}",
            "https://www.{$this->domain}"
        ];
        
        foreach ($urls as $url) {
            $result = $this->testRedirect($url);
            
            $statusColor = 'red';
            $statusText = '❌ FAIL';
            
            if ($result['code'] >= 200 && $result['code'] < 300) {
                $statusColor = 'green';
                $statusText = '✓ OK';
            } elseif ($result['code'] >= 300 && $result['code'] < 400) {
                $statusColor = 'yellow';
                $statusText = '↳ REDIRECT';
            }
            
            printf("%-35s %-8s %-8s %-35s %s\n",
                $url,
                $this->colorize($result['code'], $result['code'] < 400 ? 'green' : 'red'),
                $this->colorize(number_format($result['time'], 2) . 's', 'blue'),
                $this->colorize($result['final_url'], 'cyan'),
                $this->colorize($statusText, $statusColor)
            );
        }
        echo "\n";
    }
    
    private function testRedirect($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Domain Health Reporter/2.0'
        ]);
        
        $start = microtime(true);
        curl_exec($ch);
        $time = microtime(true) - $start;
        
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        
        curl_close($ch);
        
        return [
            'code' => $code,
            'time' => $time,
            'final_url' => $finalUrl ?: $url
        ];
    }
    
    private function analyzeDnsRecords() {
        $recordTypes = [
            'A' => ['icon' => '🅰️', 'desc' => 'IPv4 Address Records'],
            'AAAA' => ['icon' => '🅰️', 'desc' => 'IPv6 Address Records'],
            'CNAME' => ['icon' => '🔗', 'desc' => 'Canonical Name Records'],
            'MX' => ['icon' => '📧', 'desc' => 'Mail Exchange Records'],
            'NS' => ['icon' => '🌐', 'desc' => 'Name Server Records'],
            'TXT' => ['icon' => '📝', 'desc' => 'Text Records'],
        ];
        
        foreach ($recordTypes as $type => $info) {
            $this->printSectionHeader("{$info['desc']} ($type)", $info['icon']);
            
            $records = $this->dnsLookup($this->domain, $type, $this->dnsServer);
            
            if (empty($records)) {
                echo $this->colorize("No $type records found", 'dim') . "\n\n";
                continue;
            }
            
            if ($type === 'MX') {
                printf("%-15s %s\n", 
                    $this->colorize('PRIORITY', 'white', true),
                    $this->colorize('MAIL SERVER', 'white', true)
                );
                echo str_repeat('─', 60) . "\n";
                foreach ($records as $record) {
                    $parts = explode(' ', $record, 2);
                    $priority = $parts[0] ?? '';
                    $server = $parts[1] ?? $record;
                    printf("%-15s %s\n",
                        $this->colorize($priority, 'yellow'),
                        $this->colorize($server, 'green')
                    );
                }
            } elseif ($type === 'TXT') {
                printf("%-50s %s\n", 
                    $this->colorize('RECORD TYPE', 'white', true),
                    $this->colorize('VALUE', 'white', true)
                );
                echo str_repeat('─', 100) . "\n";
                foreach ($records as $record) {
                    $recordType = 'TXT';
                    if (strpos($record, 'v=spf1') !== false) $recordType = 'SPF';
                    elseif (strpos($record, 'v=DMARC1') !== false) $recordType = 'DMARC';
                    elseif (strpos($record, 'google-site-verification') !== false) $recordType = 'Google Verify';
                    elseif (strpos($record, '_globalsign-domain-verification') !== false) $recordType = 'GlobalSign';
                    elseif (strpos($record, 'mandrill_verify') !== false) $recordType = 'Mandrill';
                    
                    printf("%-50s %s\n",
                        $this->colorize($recordType, 'cyan'),
                        $this->colorize($record, 'green')
                    );
                }
            } else {
                printf("%-40s %s\n", 
                    $this->colorize('RECORD', 'white', true),
                    $this->colorize('STATUS', 'white', true)
                );
                echo str_repeat('─', 60) . "\n";
                foreach ($records as $record) {
                    printf("%-40s %s\n",
                        $this->colorize($record, 'green'),
                        $this->colorize('✓ Active', 'green')
                    );
                }
            }
            echo "\n";
        }
    }
    
    private function analyzeEmailSecurity() {
        $this->printSectionHeader('EMAIL SECURITY ANALYSIS', '🛡️');
        
        echo $this->colorize("DMARC Policy:", 'blue', true) . "\n";
        $dmarc = $this->dnsLookup("_dmarc.{$this->domain}", 'TXT', $this->dnsServer);
        if (empty($dmarc)) {
            echo $this->colorize("❌ No DMARC record found - Email spoofing vulnerable", 'red') . "\n";
        } else {
            echo $this->colorize("✓ DMARC configured:", 'green') . " " . $dmarc[0] . "\n";
        }
        echo "\n";
        
        echo $this->colorize("SPF Policy:", 'blue', true) . "\n";
        $spf = array_filter($this->dnsLookup($this->domain, 'TXT', $this->dnsServer), 
                           fn($r) => strpos($r, 'v=spf1') !== false);
        if (empty($spf)) {
            echo $this->colorize("❌ No SPF record found - Email spoofing vulnerable", 'red') . "\n";
        } else {
            $spfRecord = array_values($spf)[0];
            echo $this->colorize("✓ SPF configured:", 'green') . " " . $spfRecord . "\n";
        }
        echo "\n";
    }
    
    private function analyzeDomainInfo() {
        $this->printSectionHeader('DOMAIN REGISTRATION INFO', '📄');
        
        $whois = $this->whoisLookup($this->domain);
        
        if (preg_match('/Registrar:\s*(.+)/i', $whois, $matches)) {
            echo $this->colorize("Registrar: ", 'blue', true) . $this->colorize(trim($matches[1]), 'green') . "\n";
        }
        
        if (preg_match('/Registry Expiry Date:\s*(.+)/i', $whois, $matches)) {
            $expiry = trim($matches[1]);
            $expiryTime = strtotime($expiry);
            $daysUntilExpiry = ($expiryTime - time()) / (24 * 3600);
            
            $color = $daysUntilExpiry < 30 ? 'red' : ($daysUntilExpiry < 90 ? 'yellow' : 'green');
            $status = $daysUntilExpiry < 30 ? '⚠️ CRITICAL' : ($daysUntilExpiry < 90 ? '⚠️ WARNING' : '✓ OK');
            
            echo $this->colorize("Expiry: ", 'blue', true) . 
                 $this->colorize($expiry, $color) . 
                 $this->colorize(" (" . round($daysUntilExpiry) . " days) ", 'dim') .
                 $this->colorize($status, $color) . "\n";
        }
        echo "\n";
    }
    
    private function generateSummary() {
        $this->printSectionHeader('SECURITY & HEALTH SUMMARY', '📊');
        
        $issues = [];
        $warnings = [];
        $passes = [];
        
        $aRecords = $this->dnsLookup($this->domain, 'A', $this->dnsServer);
        if (empty($aRecords)) {
            $issues[] = "No A record found for root domain";
        } else {
            $passes[] = "A record configured correctly";
        }
        
        $dmarc = $this->dnsLookup("_dmarc.{$this->domain}", 'TXT', $this->dnsServer);
        if (empty($dmarc)) {
            $issues[] = "DMARC policy not configured - vulnerable to email spoofing";
        } else {
            $passes[] = "DMARC policy configured";
        }
        
        $spf = array_filter($this->dnsLookup($this->domain, 'TXT', $this->dnsServer), 
                           fn($r) => strpos($r, 'v=spf1') !== false);
        if (empty($spf)) {
            $issues[] = "SPF record not configured - vulnerable to email spoofing";
        } else {
            $passes[] = "SPF policy configured";
        }
        
        if (!empty($issues)) {
            echo $this->colorize("🚨 CRITICAL ISSUES:", 'red', true) . "\n";
            foreach ($issues as $issue) {
                echo "  " . $this->colorize("❌ $issue", 'red') . "\n";
            }
            echo "\n";
        }
        
        if (!empty($warnings)) {
            echo $this->colorize("⚠️ WARNINGS:", 'yellow', true) . "\n";
            foreach ($warnings as $warning) {
                echo "  " . $this->colorize("⚠️ $warning", 'yellow') . "\n";
            }
            echo "\n";
        }
        
        if (!empty($passes)) {
            echo $this->colorize("✅ HEALTH CHECKS PASSED:", 'green', true) . "\n";
            foreach ($passes as $pass) {
                echo "  " . $this->colorize("✓ $pass", 'green') . "\n";
            }
            echo "\n";
        }
        
        $totalChecks = count($issues) + count($warnings) + count($passes);
        $healthScore = round((count($passes) / $totalChecks) * 100);
        
        $scoreColor = $healthScore >= 80 ? 'green' : ($healthScore >= 60 ? 'yellow' : 'red');
        echo $this->colorize("🎯 OVERALL HEALTH SCORE: ", 'blue', true) . 
             $this->colorize("$healthScore%", $scoreColor, true) . "\n\n";
    }
    
    public function analyze() {
        $this->printHeader();
        $this->analyzeHostInfo();
        $this->analyzeRedirects();
        $this->analyzeDnsRecords();
        $this->analyzeEmailSecurity();
        $this->analyzeDomainInfo();
        $this->generateSummary();
        
        echo $this->colorize(str_repeat('═', $this->maxWidth), 'cyan') . "\n";
        echo $this->colorize("Analysis complete! Report generated by Domain Health Reporter v2.0", 'blue', true) . "\n";
        echo $this->colorize(str_repeat('═', $this->maxWidth), 'cyan') . "\n\n";
    }
}

function showUsage($scriptName) {
    echo "\n";
    echo "🔍 Domain Health Reporter v2.0 - Advanced PHP Edition\n";
    echo "───────────────────────────────────────────────────\n\n";
    echo "Usage: php $scriptName [-ns dns_server] <domain>\n\n";
    echo "Examples:\n";
    echo "  php $scriptName example.com\n";
    echo "  php $scriptName -ns 1.1.1.1 example.com\n";
    echo "  php $scriptName -ns 8.8.8.8 https://www.example.com/path\n\n";
    exit(1);
}

if ($argc < 2) {
    showUsage($argv[0]);
}

$dnsServer = null;
$domain = null;

for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] === '-ns' && isset($argv[$i + 1])) {
        $dnsServer = $argv[$i + 1];
        $i++;
    } else {
        $domain = $argv[$i];
    }
}

if (!$domain) {
    showUsage($argv[0]);
}

try {
    $reporter = new DomainHealthReporter($domain, $dnsServer);
    $reporter->analyze();
} catch (Exception $e) {
    echo "\n❌ Error: " . $e->getMessage() . "\n\n";
    exit(1);
}

?>