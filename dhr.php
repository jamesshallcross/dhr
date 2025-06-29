#!/usr/bin/env php
<?php

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
        echo $this->colorize("🔍 Analysis Target: ", 'blue', true) . $this->colorize($this->domain, 'yellow', true) . "\n";
        echo $this->colorize("🌐 DNS Server: ", 'blue', true) . $this->colorize($dnsInfo, 'green') . "\n";
        echo $this->colorize("⏰ Timestamp: ", 'blue', true) . $this->colorize(date('Y-m-d H:i:s T'), 'white') . "\n\n";
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
        if (preg_match('/(?:OrgName|org-name|descr):\s*(.+)/i', $whois, $matches)) {
            return trim($matches[1]);
        }
        return 'Unknown';
    }
    
    private function analyzeHostInfo() {
        $this->printSectionHeader('HOST INFORMATION ANALYSIS', '🖥️');
        
        printf("%-40s %-25s %-30s %s\n", 
            $this->colorize('HOSTNAME', 'white', true),
            $this->colorize('IP/CNAME', 'white', true),
            $this->colorize('ORGANIZATION', 'white', true),
            $this->colorize('STATUS', 'white', true)
        );
        echo str_repeat('─', $this->maxWidth) . "\n";
        
        $hosts = [
            $this->domain,
            "www.{$this->domain}"
        ];
        
        foreach ($hosts as $host) {
            $records = $this->dnsLookup($host, 'A', $this->dnsServer);
            
            if (empty($records)) {
                printf("%-40s %-25s %-30s %s\n",
                    $host,
                    $this->colorize('No A record', 'red'),
                    $this->colorize('N/A', 'dim'),
                    $this->colorize('❌ FAIL', 'red')
                );
                continue;
            }
            
            $record = $records[0];
            
            if (filter_var($record, FILTER_VALIDATE_IP)) {
                $org = $this->getOrgInfo($record);
                printf("%-40s %-25s %-30s %s\n",
                    $host,
                    $this->colorize($record, 'green'),
                    $this->colorize($org, 'magenta'),
                    $this->colorize('✓ OK', 'green')
                );
            } else {
                printf("%-40s %-25s %-30s %s\n",
                    $host,
                    $this->colorize($record, 'yellow'),
                    $this->colorize('(CNAME)', 'yellow'),
                    $this->colorize('↳ CNAME', 'yellow')
                );
                
                $finalIp = $this->resolveCnameChain($record);
                if ($finalIp) {
                    $org = $this->getOrgInfo($finalIp);
                    printf("%-40s %-25s %-30s %s\n",
                        "  └─ $record",
                        $this->colorize($finalIp, 'green'),
                        $this->colorize($org, 'magenta'),
                        $this->colorize('✓ OK', 'green')
                    );
                }
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
            
            foreach ($records as $record) {
                if ($type === 'MX') {
                    $parts = explode(' ', $record, 2);
                    $priority = $parts[0] ?? '';
                    $server = $parts[1] ?? $record;
                    echo $this->colorize("Priority: $priority", 'yellow') . " → " . 
                         $this->colorize($server, 'green') . "\n";
                } else {
                    echo $this->colorize($record, 'green') . "\n";
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
            echo $this->colorize("✓ SPF configured:", 'green') . " " . $spf[0] . "\n";
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