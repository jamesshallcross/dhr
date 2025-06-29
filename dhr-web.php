<?php
class DomainHealthReporter {
    private $domain;
    private $dnsServer;
    private $results = [];
    
    public function __construct($domain, $dnsServer = null) {
        $this->domain = $this->sanitizeDomain($domain);
        $this->dnsServer = $dnsServer;
    }
    
    private function sanitizeDomain($domain) {
        $domain = strtolower(trim($domain));
        $domain = preg_replace('#^https?://#', '', $domain);
        $domain = preg_replace('#^www\.#', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        return $domain;
    }
    
    private function printHeader() {
        $dnsInfo = $this->dnsServer ? $this->dnsServer : $this->getSystemDns();
        $timestamp = date('Y-m-d H:i:s T');
        
        echo "<div class='header-section'>";
        echo "<div class='info-grid'>";
        echo "<div class='info-item'><strong>Target:</strong> <span class='domain'>{$this->domain}</span></div>";
        echo "<div class='info-item'><strong>DNS:</strong> {$dnsInfo}</div>";
        echo "<div class='info-item'><strong>Time:</strong> {$timestamp}</div>";
        echo "</div>";
        echo "</div>";
    }
    
    private function getSystemDns() {
        $output = shell_exec('dig | grep SERVER 2>/dev/null');
        if ($output && preg_match('/SERVER: ([^#]+)/', $output, $matches)) {
            return trim($matches[1]);
        }
        return '8.8.8.8#53';
    }
    
    private function printSectionHeader($title) {
        echo "<h4>{$title}</h4>";
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
        $patterns = [
            '/Organization:\s*(.+?)\s*\(/i',
            '/OrgName:\s*(.+)/i',
            '/org-name:\s*(.+)/i',
            '/descr:\s*(.+)/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whois, $matches)) {
                return trim($matches[1]);
            }
        }
        return 'Unknown';
    }
    
    private function analyzeHostInfo() {
        $this->printSectionHeader('Host Information');
        
        $hosts = [
            $this->domain,
            "www.{$this->domain}"
        ];
        
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>Host</th><th>IP/CNAME</th><th>Organization</th><th>Status</th></tr></thead>";
        echo "<tbody>";
        
        foreach ($hosts as $host) {
            $records = $this->dnsLookup($host, 'A', $this->dnsServer);
            
            if (empty($records)) {
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td class='no-record'>No A record</td>";
                echo "<td>N/A</td>";
                echo "<td class='status-error'>NO_RECORD</td>";
                echo "</tr>";
                continue;
            }
            
            $record = $records[0];
            
            if (filter_var($record, FILTER_VALIDATE_IP)) {
                $org = $this->getOrgInfo($record);
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td class='ip'>{$record}</td>";
                echo "<td class='org'>{$org}</td>";
                echo "<td class='status-success'>RESOLVED</td>";
                echo "</tr>";
            } else {
                // CNAME record
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td class='cname'>{$record}</td>";
                echo "<td></td>";
                echo "<td class='status-cname'>CNAME</td>";
                echo "</tr>";
                
                // Resolve CNAME to final IP
                $finalIp = $this->resolveCnameChain($record);
                if ($finalIp) {
                    $org = $this->getOrgInfo($finalIp);
                    echo "<tr class='cname-resolution'>";
                    echo "<td>&nbsp;&nbsp;└─ {$record}</td>";
                    echo "<td class='ip'>{$finalIp}</td>";
                    echo "<td class='org'>{$org}</td>";
                    echo "<td class='status-success'>RESOLVED</td>";
                    echo "</tr>";
                }
            }
        }
        
        echo "</tbody></table>";
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
        $this->printSectionHeader('HTTP/HTTPS Redirect Results');
        
        $urls = [
            "http://{$this->domain}",
            "http://www.{$this->domain}",
            "https://{$this->domain}",
            "https://www.{$this->domain}"
        ];
        
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>URL</th><th>Code</th><th>Time</th><th>Redirect</th></tr></thead>";
        echo "<tbody>";
        
        foreach ($urls as $url) {
            $result = $this->testRedirect($url);
            $codeClass = '';
            if ($result['code'] >= 200 && $result['code'] < 300) $codeClass = 'status-success';
            elseif ($result['code'] >= 300 && $result['code'] < 400) $codeClass = 'status-redirect';
            else $codeClass = 'status-error';
            
            echo "<tr>";
            echo "<td class='url'>{$url}</td>";
            echo "<td class='{$codeClass}'>{$result['code']}</td>";
            echo "<td class='time'>" . number_format($result['time'], 2) . "s</td>";
            echo "<td class='redirect-url'>{$result['final_url']}</td>";
            echo "</tr>";
        }
        
        echo "</tbody></table>";
    }
    
    private function testRedirect($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Domain Health Reporter/2.0'
        ]);
        
        $start = microtime(true);
        $response = curl_exec($ch);
        $time = microtime(true) - $start;
        
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        $redirectUrl = '';
        if ($code >= 300 && $code < 400 && $response) {
            if (preg_match('/Location:\s*(.+)/i', $response, $matches)) {
                $redirectUrl = trim($matches[1]);
                if (strpos($redirectUrl, 'http') !== 0) {
                    $parsedUrl = parse_url($url);
                    $redirectUrl = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $redirectUrl;
                }
            }
        } elseif ($code >= 200 && $code < 300) {
            $redirectUrl = '';
        } else {
            $redirectUrl = 'Error';
        }
        
        return [
            'code' => $code,
            'time' => $time,
            'final_url' => $redirectUrl
        ];
    }
    
    private function analyzeDnsRecords() {
        // MX RECORDS
        $this->printSectionHeader('MX Records');
        $records = $this->dnsLookup($this->domain, 'MX', $this->dnsServer);
        if (empty($records)) {
            echo "<p class='no-records'>No MX records found</p>";
        } else {
            echo "<ul class='dns-list'>";
            foreach ($records as $record) {
                $parts = explode(' ', $record, 2);
                $priority = $parts[0] ?? '';
                $server = $parts[1] ?? $record;
                echo "<li><span class='priority'>{$priority}</span> <span class='server'>{$server}</span></li>";
            }
            echo "</ul>";
        }
        
        // NS RECORDS
        $this->printSectionHeader('NS Records');
        $records = $this->dnsLookup($this->domain, 'NS', $this->dnsServer);
        if (empty($records)) {
            echo "<p class='no-records'>No NS records found</p>";
        } else {
            echo "<ul class='dns-list'>";
            foreach ($records as $record) {
                echo "<li class='server'>{$record}</li>";
            }
            echo "</ul>";
        }
    }
    
    private function analyzeEmailSecurity() {
        $this->printSectionHeader('DMARC Record');
        $dmarc = $this->dnsLookup("_dmarc.{$this->domain}", 'TXT', $this->dnsServer);
        if (empty($dmarc)) {
            echo "<p class='no-records'>No DMARC record found</p>";
        } else {
            echo "<div class='dmarc-record'>{$dmarc[0]}</div>";
        }
    }
    
    private function analyzeDomainInfo() {
        $this->printSectionHeader('Registrar Information');
        $whois = $this->whoisLookup($this->domain);
        
        if (preg_match('/Registrar:\s*(.+)/i', $whois, $matches)) {
            echo "<p class='registrar'>" . trim($matches[1]) . "</p>";
        } else {
            echo "<p class='no-records'>Registrar information not found</p>";
        }
        
        $this->printSectionHeader('Domain Expiration');
        if (preg_match('/Registry Expiry Date:\s*(.+)/i', $whois, $matches)) {
            echo "<p class='expiry'>" . trim($matches[1]) . "</p>";
        } else {
            echo "<p class='no-records'>Expiration date not found</p>";
        }
    }
    
    public function analyze() {
        echo "
        <style>
            .header-section { margin-bottom: 15px; padding: 12px; background: #f8f9fa; border-radius: 3px; }
            .info-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }
            .info-item { font-size: 13px; }
            .domain { color: #e74c3c; font-weight: bold; }
            .compact-table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13px; }
            .compact-table th, .compact-table td { padding: 4px 8px; text-align: left; border-bottom: 1px solid #ddd; }
            .compact-table th { background-color: #f5f5f5; font-weight: bold; font-size: 12px; }
            .compact-table tr:hover { background-color: #f9f9f9; }
            .ip { color: #27ae60; font-family: monospace; font-size: 12px; }
            .cname { color: #f39c12; font-family: monospace; font-size: 12px; }
            .org { color: #8e44ad; font-size: 12px; }
            .url { color: #3498db; font-family: monospace; font-size: 12px; }
            .time { color: #3498db; font-family: monospace; font-size: 12px; }
            .redirect-url { color: #3498db; font-family: monospace; font-size: 12px; }
            .status-success { color: #27ae60; font-weight: bold; font-size: 11px; }
            .status-cname { color: #f39c12; font-weight: bold; font-size: 11px; }
            .status-redirect { color: #f39c12; font-weight: bold; font-size: 11px; }
            .status-error { color: #e74c3c; font-weight: bold; font-size: 11px; }
            .no-record { color: #e74c3c; font-style: italic; font-size: 12px; }
            .cname-resolution { background-color: #f9f9f9; }
            .dns-list { list-style: none; padding: 0; margin: 5px 0; }
            .dns-list li { padding: 2px 0; border-bottom: 1px solid #eee; font-size: 13px; }
            .priority { color: #f39c12; font-weight: bold; }
            .server { color: #27ae60; font-family: monospace; font-size: 12px; }
            .dmarc-record { background: #f8f9fa; padding: 8px; border-radius: 3px; font-family: monospace; word-break: break-all; font-size: 12px; }
            .registrar, .expiry { color: #27ae60; font-weight: bold; font-size: 13px; }
            .no-records { color: #666; font-style: italic; font-size: 12px; margin: 5px 0; }
            h4 { color: #2c3e50; border-bottom: 1px solid #3498db; padding-bottom: 2px; margin: 15px 0 8px 0; font-size: 16px; }
            h4:first-child { margin-top: 0; }
        </style>
        ";
        
        $this->printHeader();
        $this->analyzeHostInfo();
        $this->analyzeRedirects();
        $this->analyzeDnsRecords();
        $this->analyzeEmailSecurity();
        $this->analyzeDomainInfo();
    }
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $domain = trim($_POST['domain'] ?? '');
    $dnsServer = trim($_POST['dns_server'] ?? '');
    
    if (empty($domain)) {
        echo "<div class='error'>Please provide a domain name.</div>";
        exit;
    }
    
    try {
        $reporter = new DomainHealthReporter($domain, $dnsServer ?: null);
        $reporter->analyze();
    } catch (Exception $e) {
        echo "<div class='error'>Error analyzing domain: " . htmlspecialchars($e->getMessage()) . "</div>";
    }
} else {
    echo "<div class='error'>Invalid request method.</div>";
}
?>