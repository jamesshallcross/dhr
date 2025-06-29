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
        $timestamp = date('Y.m.d H:i');
        
        echo "<div class='header-section'>";
        echo "<div class='info-grid'>";
        echo "<div class='info-item'><strong>Target:</strong> <span class='domain'>{$this->domain}</span></div>";
        echo "<div class='info-item'><strong>Time:</strong> {$timestamp}</div>";
        echo "<div class='info-item'><strong>Using <span class='dns-server'>{$dnsInfo}</span> for DNS lookups</strong></div>";
        echo "</div>";
        echo "</div>";
    }
    
    private function getSystemDns() {
        return '1.1.1.1#53';
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
                echo "<td><span class='no-record'>No A record</span></td>";
                echo "<td>N/A</td>";
                echo "<td><span class='status-error'>NO_RECORD</span></td>";
                echo "</tr>";
                continue;
            }
            
            $record = $records[0];
            
            if (filter_var($record, FILTER_VALIDATE_IP)) {
                $org = $this->getOrgInfo($record);
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td><span class='ip'>{$record}</span></td>";
                echo "<td><span class='org'>{$org}</span></td>";
                echo "<td><span class='status-success'>RESOLVED</span></td>";
                echo "</tr>";
            } else {
                // CNAME record
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td><span class='cname'>{$record}</span></td>";
                echo "<td></td>";
                echo "<td><span class='status-cname'>CNAME</span></td>";
                echo "</tr>";
                
                // Resolve CNAME to final IP
                $finalIp = $this->resolveCnameChain($record);
                if ($finalIp) {
                    $org = $this->getOrgInfo($finalIp);
                    echo "<tr class='cname-resolution'>";
                    echo "<td>&nbsp;&nbsp;└─ {$record}</td>";
                    echo "<td><span class='ip'>{$finalIp}</span></td>";
                    echo "<td><span class='org'>{$org}</span></td>";
                    echo "<td><span class='status-success'>RESOLVED</span></td>";
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
        echo "<thead><tr><th>URL</th><th>Code</th><th>Redirect</th><th>Time</th></tr></thead>";
        echo "<tbody>";
        
        foreach ($urls as $url) {
            $result = $this->testRedirect($url);
            $codeClass = '';
            if ($result['code'] >= 200 && $result['code'] < 300) $codeClass = 'status-success';
            elseif ($result['code'] >= 300 && $result['code'] < 400) $codeClass = 'status-redirect';
            else $codeClass = 'status-error';
            
            echo "<tr>";
            echo "<td><span class='url'>{$url}</span></td>";
            echo "<td><span class='{$codeClass}'>{$result['code']}</span></td>";
            echo "<td><span class='redirect-url'>{$result['final_url']}</span></td>";
            echo "<td><span class='time'>" . number_format($result['time'], 2) . "s</span></td>";
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
            CURLOPT_TIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Domain Health Reporter/2.0'
        ]);
        
        $start = microtime(true);
        $response = curl_exec($ch);
        $time = microtime(true) - $start;
        
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        // Handle timeout specifically
        if ($curlError && strpos($curlError, 'timeout') !== false) {
            return [
                'code' => 0,
                'time' => $time,
                'final_url' => 'Timeout'
            ];
        }
        
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
            $redirectUrl = $code > 0 ? 'Error' : 'Timeout';
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
                echo "<li><span class='server'>{$record}</span></li>";
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
            .header-section { margin-bottom: 10px; padding: 8px; border-radius: 3px; transition: background-color 0.3s; }
            .dark .header-section { background: #3d3d3d; }
            .light .header-section { background: #f8f9fa; }
            .info-grid { display: flex; justify-content: space-between; align-items: center; }
            .info-item { font-size: 13px; transition: color 0.3s; white-space: nowrap; }
            .info-item:first-child { flex: 0 0 auto; }
            .info-item:nth-child(2) { flex: 0 0 auto; text-align: center; }
            .info-item:last-child { flex: 0 0 auto; text-align: right; }
            .dark .info-item { color: #e0e0e0; }
            .light .info-item { color: #333; }
            .domain { font-weight: bold; }
            .dark .domain { color: #ff6b6b; }
            .light .domain { color: #e74c3c; }
            .dns-server { font-weight: bold; font-family: monospace; }
            .dark .dns-server { color: #4ade80; }
            .light .dns-server { color: #27ae60; }
            .compact-table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13px; transition: all 0.3s; }
            .dark .compact-table { background: #2d2d2d; }
            .light .compact-table { background: white; }
            .compact-table th, .compact-table td { padding: 4px 8px; text-align: left; transition: all 0.3s; }
            .dark .compact-table th, .dark .compact-table td { border-bottom: 1px solid #555; color: #e0e0e0; }
            .light .compact-table th, .light .compact-table td { border-bottom: 1px solid #ddd; color: #333; }
            .compact-table th { font-weight: bold; font-size: 12px; }
            .dark .compact-table th { background-color: #3d3d3d; }
            .light .compact-table th { background-color: #f5f5f5; }
            .compact-table tr:hover { transition: background-color 0.2s; }
            .dark .compact-table tr:hover { background-color: #3d3d3d; }
            .light .compact-table tr:hover { background-color: #f9f9f9; }
            .compact-table .ip { font-family: monospace; font-size: 12px; }
            .dark .compact-table .ip { color: #4ade80 !important; }
            .light .compact-table .ip { color: #27ae60 !important; }
            .compact-table .cname { font-family: monospace; font-size: 12px; }
            .dark .compact-table .cname { color: #fbbf24 !important; }
            .light .compact-table .cname { color: #f39c12 !important; }
            .compact-table .org { font-size: 12px; }
            .dark .compact-table .org { color: #a78bfa !important; }
            .light .compact-table .org { color: #8e44ad !important; }
            .compact-table .url { font-family: monospace; font-size: 12px; }
            .dark .compact-table .url { color: #60a5fa !important; }
            .light .compact-table .url { color: #3498db !important; }
            .compact-table .time { font-family: monospace; font-size: 12px; }
            .dark .compact-table .time { color: #60a5fa !important; }
            .light .compact-table .time { color: #3498db !important; }
            .compact-table .redirect-url { font-family: monospace; font-size: 12px; }
            .dark .compact-table .redirect-url { color: #60a5fa !important; }
            .light .compact-table .redirect-url { color: #3498db !important; }
            .compact-table .status-success { font-weight: bold; font-size: 11px; }
            .dark .compact-table .status-success { color: #4ade80 !important; }
            .light .compact-table .status-success { color: #27ae60 !important; }
            .compact-table .status-cname { font-weight: bold; font-size: 11px; }
            .dark .compact-table .status-cname { color: #fbbf24 !important; }
            .light .compact-table .status-cname { color: #f39c12 !important; }
            .compact-table .status-redirect { font-weight: bold; font-size: 11px; }
            .dark .compact-table .status-redirect { color: #fbbf24 !important; }
            .light .compact-table .status-redirect { color: #f39c12 !important; }
            .compact-table .status-error { font-weight: bold; font-size: 11px; }
            .dark .compact-table .status-error { color: #f87171 !important; }
            .light .compact-table .status-error { color: #e74c3c !important; }
            .compact-table .no-record { font-style: italic; font-size: 12px; }
            .dark .compact-table .no-record { color: #f87171 !important; }
            .light .compact-table .no-record { color: #e74c3c !important; }
            .cname-resolution { transition: background-color 0.3s; }
            .dark .cname-resolution { background-color: #3d3d3d; }
            .light .cname-resolution { background-color: #f9f9f9; }
            .dns-list { list-style: none; padding: 0; margin: 5px 0; }
            .dns-list li { padding: 2px 0; font-size: 13px; transition: all 0.3s; }
            .dark .dns-list li { border-bottom: 1px solid #555; color: #e0e0e0; }
            .light .dns-list li { border-bottom: 1px solid #eee; color: #333; }
            .priority { font-weight: bold; }
            .dark .priority { color: #fbbf24; }
            .light .priority { color: #f39c12; }
            .server { font-family: monospace; font-size: 12px; }
            .dark .server { color: #4ade80; }
            .light .server { color: #27ae60; }
            .dmarc-record { padding: 8px; border-radius: 3px; font-family: monospace; word-break: break-all; font-size: 12px; transition: all 0.3s; }
            .dark .dmarc-record { background: #3d3d3d; color: #e0e0e0; }
            .light .dmarc-record { background: #f8f9fa; color: #333; }
            .registrar, .expiry { font-weight: bold; font-size: 13px; }
            .dark .registrar, .dark .expiry { color: #4ade80; }
            .light .registrar, .light .expiry { color: #27ae60; }
            .no-records { font-style: italic; font-size: 12px; margin: 5px 0; }
            .dark .no-records { color: #9ca3af; }
            .light .no-records { color: #666; }
            h4 { padding-bottom: 2px; margin: 15px 0 8px 0; font-size: 16px; transition: all 0.3s; }
            .dark h4 { color: #60a5fa; border-bottom: 1px solid #60a5fa; }
            .light h4 { color: #2c3e50; border-bottom: 1px solid #3498db; }
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