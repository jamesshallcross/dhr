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
        // Set UK timezone for proper BST/GMT display
        $originalTimezone = date_default_timezone_get();
        date_default_timezone_set('Europe/London');
        $timestamp = date('Y.m.d H:i T');
        date_default_timezone_set($originalTimezone);
        
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
        
        // Desktop table
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>Host</th><th>IP/CNAME</th><th>Organization</th><th>Status</th><th>CF-DC</th></tr></thead>";
        echo "<tbody>";
        
        $hostData = [];
        
        foreach ($hosts as $host) {
            $records = $this->dnsLookup($host, 'A', $this->dnsServer);
            
            if (empty($records)) {
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td><span class='no-record'>No A record</span></td>";
                echo "<td>N/A</td>";
                echo "<td><span class='status-error'>NO_RECORD</span></td>";
                echo "</tr>";
                
                $hostData[] = [
                    'host' => $host,
                    'ip_cname' => "<span class='no-record'>No A record</span>",
                    'org' => 'N/A',
                    'status' => "<span class='status-error'>NO_RECORD</span>"
                ];
                continue;
            }
            
            $record = $records[0];
            
            if (filter_var($record, FILTER_VALIDATE_IP)) {
                $org = $this->getOrgInfo($record);
                $dc = $this->getDataCenter($host, $org);
                
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td><span class='ip'>{$record}</span></td>";
                echo "<td><span class='org'>{$org}</span></td>";
                echo "<td><span class='status-success'>RESOLVED</span></td>";
                echo "<td><span class='datacenter'>{$dc}</span></td>";
                echo "</tr>";
                
                $hostData[] = [
                    'host' => $host,
                    'ip_cname' => "<span class='ip'>{$record}</span>",
                    'org' => "<span class='org'>{$org}</span>",
                    'status' => "<span class='status-success'>RESOLVED</span>",
                    'dc' => "<span class='datacenter'>{$dc}</span>"
                ];
            } else {
                // CNAME record
                echo "<tr>";
                echo "<td>{$host}</td>";
                echo "<td><span class='cname'>{$record}</span></td>";
                echo "<td>CNAME</td>";
                echo "<td><span class='status-cname'>CNAME</span></td>";
                echo "<td></td>";
                echo "</tr>";
                
                $hostData[] = [
                    'host' => $host,
                    'ip_cname' => "<span class='cname'>{$record}</span>",
                    'org' => 'CNAME',
                    'status' => "<span class='status-cname'>CNAME</span>",
                    'dc' => ''
                ];
                
                // Resolve CNAME to final IP
                $finalIp = $this->resolveCnameChain($record);
                if ($finalIp) {
                    $org = $this->getOrgInfo($finalIp);
                    $dc = $this->getDataCenter($record, $org);
                    
                    echo "<tr>";
                    echo "<td>&nbsp;&nbsp;└─ {$record}</td>";
                    echo "<td><span class='ip'>{$finalIp}</span></td>";
                    echo "<td><span class='org'>{$org}</span></td>";
                    echo "<td><span class='status-success'>RESOLVED</span></td>";
                    echo "<td><span class='datacenter'>{$dc}</span></td>";
                    echo "</tr>";
                    
                    $hostData[] = [
                        'host' => "&nbsp;&nbsp;└─ {$record}",
                        'ip_cname' => "<span class='ip'>{$finalIp}</span>",
                        'org' => "<span class='org'>{$org}</span>",
                        'status' => "<span class='status-success'>RESOLVED</span>",
                        'dc' => "<span class='datacenter'>{$dc}</span>"
                    ];
                }
            }
        }
        
        echo "</tbody></table>";
        
        // Mobile cards
        echo "<div class='host-info-mobile'>";
        foreach ($hostData as $data) {
            echo "<div class='host-card'>";
            echo "<div class='host-name'>{$data['host']}</div>";
            echo "<div class='host-detail'><strong>IP/CNAME:</strong> {$data['ip_cname']}</div>";
            if (!empty($data['org'])) {
                echo "<div class='host-detail'><strong>Org:</strong> {$data['org']}</div>";
            }
            echo "<div class='host-detail'><strong>Status:</strong> {$data['status']}</div>";
            if (!empty($data['dc'])) {
                echo "<div class='host-detail'><strong>CF-DC:</strong> {$data['dc']}</div>";
            }
            echo "</div>";
        }
        echo "</div>";
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
        
        // Desktop table
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>URL</th><th>Code</th><th>Redirect</th><th>Time</th></tr></thead>";
        echo "<tbody>";
        
        $redirectData = [];
        
        foreach ($urls as $url) {
            $result = $this->testRedirect($url);
            $codeClass = '';
            if ($result['code'] >= 200 && $result['code'] < 300) $codeClass = 'status-success';
            elseif ($result['code'] >= 300 && $result['code'] < 400) $codeClass = 'status-redirect';
            else $codeClass = 'status-error';
            
            // Make URL bold if code is 200
            $urlClass = ($result['code'] == 200) ? 'url url-bold' : 'url';
            $rowClass = ($result['code'] == 200) ? 'final-destination' : '';
            
            echo "<tr class='{$rowClass}'>";
            echo "<td><span class='{$urlClass}'>{$url}</span></td>";
            echo "<td><span class='{$codeClass}'>{$result['code']}</span></td>";
            echo "<td><span class='redirect-url'>{$result['final_url']}</span></td>";
            echo "<td><span class='time'>" . number_format($result['time'], 2) . "s</span></td>";
            echo "</tr>";
            
            $redirectData[] = [
                'url' => "<span class='{$urlClass}'>{$url}</span>",
                'code' => "<span class='{$codeClass}'>{$result['code']}</span>",
                'redirect' => "<span class='redirect-url'>{$result['final_url']}</span>",
                'time' => "<span class='time'>" . number_format($result['time'], 2) . "s</span>"
            ];
        }
        
        echo "</tbody></table>";
        
        // Mobile cards
        echo "<div class='redirect-info-mobile'>";
        foreach ($redirectData as $i => $data) {
            $cardClass = (strpos($data['code'], '200') !== false) ? 'redirect-card final-destination-card' : 'redirect-card';
            echo "<div class='{$cardClass}'>";
            echo "<div class='redirect-url-header'>{$data['url']}</div>";
            echo "<div class='redirect-detail'><strong>Code:</strong> {$data['code']}</div>";
            if (!empty($data['redirect']) && strip_tags($data['redirect']) !== '') {
                echo "<div class='redirect-detail'><strong>Redirect:</strong> {$data['redirect']}</div>";
            }
            echo "<div class='redirect-detail'><strong>Time:</strong> {$data['time']}</div>";
            echo "</div>";
        }
        echo "</div>";
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
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
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
    
    private function analyzeSSLCertificate() {
        $this->printSectionHeader('SSL Certificate');
        
        $hosts = [
            $this->domain,
            "www.{$this->domain}"
        ];
        
        // Desktop table
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>Host</th><th>Provider</th><th>Valid Until</th><th>Days Left</th><th>SSL Status</th><th>HSTS</th></tr></thead>";
        echo "<tbody>";
        
        $sslData = [];
        
        foreach ($hosts as $host) {
            $sslInfo = $this->getSSLInfo($host);
            $hstsInfo = $this->getHSTSInfo($host);
            $sslInfo = array_merge($sslInfo, $hstsInfo);
            
            echo "<tr>";
            echo "<td>{$host}</td>";
            echo "<td><span class='ssl-provider'>{$sslInfo['provider']}</span></td>";
            echo "<td><span class='ssl-expiry'>{$sslInfo['valid_until']}</span></td>";
            echo "<td><span class='{$sslInfo['days_class']}'>{$sslInfo['days_left']}</span></td>";
            echo "<td><span class='{$sslInfo['status_class']}'>{$sslInfo['status']}</span></td>";
            echo "<td><span class='{$sslInfo['hsts_class']}'>{$sslInfo['hsts']}</span></td>";
            echo "</tr>";
            
            $sslData[] = [
                'host' => $host,
                'provider' => "<span class='ssl-provider'>{$sslInfo['provider']}</span>",
                'valid_until' => "<span class='ssl-expiry'>{$sslInfo['valid_until']}</span>",
                'days_left' => "<span class='{$sslInfo['days_class']}'>{$sslInfo['days_left']}</span>",
                'status' => "<span class='{$sslInfo['status_class']}'>{$sslInfo['status']}</span>",
                'hsts' => "<span class='{$sslInfo['hsts_class']}'>{$sslInfo['hsts']}</span>"
            ];
        }
        
        echo "</tbody></table>";
        
        // Mobile cards
        echo "<div class='ssl-info-mobile'>";
        foreach ($sslData as $data) {
            echo "<div class='ssl-card'>";
            echo "<div class='ssl-host-header'>{$data['host']}</div>";
            echo "<div class='ssl-detail'><strong>Provider:</strong> {$data['provider']}</div>";
            echo "<div class='ssl-detail'><strong>Valid Until:</strong> {$data['valid_until']}</div>";
            echo "<div class='ssl-detail'><strong>Days Left:</strong> {$data['days_left']}</div>";
            echo "<div class='ssl-detail'><strong>SSL Status:</strong> {$data['status']}</div>";
            echo "<div class='ssl-detail'><strong>HSTS:</strong> {$data['hsts']}</div>";
            echo "</div>";
        }
        echo "</div>";
    }
    
    private function getSSLInfo($host) {
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false,
            ],
        ]);
        
        $socket = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
        
        if (!$socket) {
            return [
                'provider' => 'N/A',
                'valid_until' => 'N/A',
                'days_left' => 'No SSL',
                'days_class' => 'ssl-error',
                'status' => 'No SSL',
                'status_class' => 'status-error'
            ];
        }
        
        $cert = stream_context_get_params($socket);
        fclose($socket);
        
        if (!isset($cert['options']['ssl']['peer_certificate'])) {
            return [
                'provider' => 'N/A',
                'valid_until' => 'N/A',
                'days_left' => 'No SSL',
                'days_class' => 'ssl-error',
                'status' => 'No SSL',
                'status_class' => 'status-error'
            ];
        }
        
        $certInfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
        
        // Get provider/issuer
        $provider = 'Unknown';
        if (isset($certInfo['issuer']['O'])) {
            $provider = $certInfo['issuer']['O'];
        } elseif (isset($certInfo['issuer']['CN'])) {
            $provider = $certInfo['issuer']['CN'];
        }
        
        // Simplify common provider names
        if (strpos($provider, 'Let\'s Encrypt') !== false) {
            $provider = 'Let\'s Encrypt';
        } elseif (strpos($provider, 'DigiCert') !== false) {
            $provider = 'DigiCert';
        } elseif (strpos($provider, 'Cloudflare') !== false) {
            $provider = 'Cloudflare';
        } elseif (strpos($provider, 'Amazon') !== false) {
            $provider = 'Amazon';
        }
        
        // Calculate expiry
        $validUntil = date('Y.m.d', $certInfo['validTo_time_t']);
        $daysLeft = floor(($certInfo['validTo_time_t'] - time()) / 86400);
        
        // Determine status and classes
        if ($daysLeft > 30) {
            $status = 'Valid';
            $statusClass = 'status-success';
            $daysClass = 'ssl-good';
        } elseif ($daysLeft > 7) {
            $status = 'Expires Soon';
            $statusClass = 'status-cname';
            $daysClass = 'ssl-warning';
        } elseif ($daysLeft > 0) {
            $status = 'Expires Very Soon';
            $statusClass = 'status-error';
            $daysClass = 'ssl-error';
        } else {
            $status = 'Expired';
            $statusClass = 'status-error';
            $daysClass = 'ssl-error';
            $daysLeft = 'Expired';
        }
        
        return [
            'provider' => $provider,
            'valid_until' => $validUntil,
            'days_left' => is_numeric($daysLeft) ? $daysLeft . ' days' : $daysLeft,
            'days_class' => $daysClass,
            'status' => $status,
            'status_class' => $statusClass
        ];
    }
    
    private function getHSTSInfo($host) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "https://{$host}",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => false,  // Don't follow redirects
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        ]);
        
        $response = curl_exec($ch);
        $curlError = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($curlError || !$response) {
            return [
                'hsts' => 'None',
                'hsts_class' => 'ssl-error'
            ];
        }
        
        // Check for HSTS header (case-insensitive)
        if (preg_match('/^strict-transport-security:\s*(.+)$/im', $response, $matches)) {
            $hstsHeader = trim($matches[1]);
            
            // Extract max-age value
            if (preg_match('/max-age=([0-9]+)/i', $hstsHeader, $maxAgeMatches)) {
                $maxAgeSeconds = (int)$maxAgeMatches[1];
                $hstsFormatted = $this->formatHSTSMaxAge($maxAgeSeconds);
                
                return [
                    'hsts' => $hstsFormatted,
                    'hsts_class' => 'ssl-good'
                ];
            }
        }
        
        return [
            'hsts' => 'None',
            'hsts_class' => 'ssl-error'
        ];
    }
    
    private function formatHSTSMaxAge($seconds) {
        if ($seconds >= 31536000) { // 1 year
            $years = floor($seconds / 31536000);
            $remaining = $seconds % 31536000;
            if ($remaining >= 2592000) { // At least 1 month remaining
                $months = floor($remaining / 2592000);
                return $years . 'y ' . $months . 'm';
            }
            return $years . ' year' . ($years > 1 ? 's' : '');
        } elseif ($seconds >= 2592000) { // 1 month
            $months = floor($seconds / 2592000);
            $remaining = $seconds % 2592000;
            if ($remaining >= 86400) { // At least 1 day remaining
                $days = floor($remaining / 86400);
                return $months . 'm ' . $days . 'd';
            }
            return $months . ' month' . ($months > 1 ? 's' : '');
        } elseif ($seconds >= 86400) { // 1 day
            $days = floor($seconds / 86400);
            return $days . ' day' . ($days > 1 ? 's' : '');
        } elseif ($seconds >= 3600) { // 1 hour
            $hours = floor($seconds / 3600);
            return $hours . ' hour' . ($hours > 1 ? 's' : '');
        } else {
            return $seconds . ' seconds';
        }
    }
    
    private function analyzeDnsRecords() {
        // MX RECORDS
        $this->printSectionHeader('MX Records');
        $records = $this->dnsLookup($this->domain, 'MX', $this->dnsServer);
        
        // Detect email provider
        $emailProvider = $this->detectEmailProvider($records);
        if ($emailProvider) {
            echo "<div class='email-provider-info'>{$emailProvider}</div>";
        }
        
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
        
        // Detect DNS provider
        $dnsProvider = $this->detectDnsProvider($records);
        if ($dnsProvider) {
            echo "<div class='dns-provider-info'>{$dnsProvider}</div>";
        }
        
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
        $expiryInfo = $this->parseExpiryDate($whois);
        if ($expiryInfo) {
            echo "<p class='expiry'>";
            echo "<span class='expiry-date'>{$expiryInfo['formatted_date']}</span> ";
            echo "(<span class='{$expiryInfo['days_class']}'>{$expiryInfo['days_text']}</span>)";
            echo "</p>";
        } else {
            echo "<p class='no-records'>Expiration date not found</p>";
        }
    }
    
    private function detectEmailProvider($mxRecords) {
        if (empty($mxRecords)) {
            return null;
        }
        
        // Check for Google Workspace pattern
        $googleMxPattern = [
            'aspmx.l.google.com.',
            'alt1.aspmx.l.google.com.',
            'alt2.aspmx.l.google.com.',
            'alt3.aspmx.l.google.com.',
            'alt4.aspmx.l.google.com.'
        ];
        
        $foundGoogleMx = [];
        foreach ($mxRecords as $record) {
            // Extract hostname from "priority hostname" format
            $parts = explode(' ', trim($record), 2);
            if (count($parts) >= 2) {
                $hostname = trim($parts[1]);
                if (in_array($hostname, $googleMxPattern)) {
                    $foundGoogleMx[] = $hostname;
                }
            }
        }
        
        // If we found multiple Google MX records, it's likely Google Workspace
        if (count($foundGoogleMx) >= 3) {
            return "Email by <span class='email-provider-name'>Google Workspace</span>";
        }
        
        // Check for Microsoft 365 pattern
        foreach ($mxRecords as $record) {
            $parts = explode(' ', trim($record), 2);
            if (count($parts) >= 2) {
                $hostname = trim($parts[1]);
                if (preg_match('/\.mail\.protection\.outlook\.com\.?$/', $hostname)) {
                    return "Email by <span class='email-provider-name'>Microsoft 365</span>";
                }
            }
        }
        
        // Check for Stackmail/20i pattern
        foreach ($mxRecords as $record) {
            $parts = explode(' ', trim($record), 2);
            if (count($parts) >= 2) {
                $hostname = trim($parts[1]);
                if ($hostname === 'mx.stackmail.com.' || $hostname === 'mx.stackmail.com') {
                    return "Email by <span class='email-provider-name'>Stackmail/20i</span>";
                }
            }
        }
        
        return null;
    }
    
    private function getDataCenter($host, $org) {
        // Only check for data center if organization suggests Cloudflare/Shopify/WPEngine
        if (!preg_match('/cloudflare|shopify|wpengine/i', $org)) {
            return '';
        }
        
        // Make HTTP request to get Cf-Ray header
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "https://{$host}",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        ]);
        
        $response = curl_exec($ch);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($curlError || !$response) {
            return '';
        }
        
        // Look for Cf-Ray header
        if (preg_match('/^cf-ray:\s*([a-f0-9]+)-([a-z]{3})/im', $response, $matches)) {
            $dcCode = strtoupper($matches[2]);
            return $dcCode;
        }
        
        return '';
    }
    
    private function parseExpiryDate($whois) {
        // Multiple patterns for different whois formats
        $patterns = [
            '/Registry Expiry Date:\s*(.+)/i',    // Standard format
            '/Expiry date:\s*(.+)/i',             // UK domains
            '/Expiration Date:\s*(.+)/i',         // Alternative format
            '/Domain expires:\s*(.+)/i',          // Another format
            '/Expires on:\s*(.+)/i'               // Yet another format
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $whois, $matches)) {
                $dateString = trim($matches[1]);
                
                // Try to parse various date formats
                $timestamp = $this->parseVariousDateFormats($dateString);
                
                if ($timestamp) {
                    $formattedDate = date('Y.m.d', $timestamp);
                    $daysLeft = floor(($timestamp - time()) / 86400);
                    
                    // Determine status and styling
                    if ($daysLeft > 90) {
                        $daysClass = 'ssl-good';
                        $daysText = $daysLeft . ' days';
                    } elseif ($daysLeft > 30) {
                        $daysClass = 'ssl-warning';
                        $daysText = $daysLeft . ' days';
                    } elseif ($daysLeft > 0) {
                        $daysClass = 'ssl-error';
                        $daysText = $daysLeft . ' days';
                    } else {
                        $daysClass = 'ssl-error';
                        $daysText = 'Expired';
                    }
                    
                    return [
                        'formatted_date' => $formattedDate,
                        'days_left' => $daysLeft,
                        'days_text' => $daysText,
                        'days_class' => $daysClass
                    ];
                }
            }
        }
        
        return null;
    }
    
    private function parseVariousDateFormats($dateString) {
        // Remove common suffixes and clean up
        $dateString = preg_replace('/\s*\(.*\)$/', '', $dateString); // Remove (timezone) info
        $dateString = trim($dateString);
        
        // Try various date formats
        $formats = [
            'Y-m-d\TH:i:s\Z',          // ISO format with Z
            'Y-m-d\TH:i:s.u\Z',        // ISO format with microseconds
            'Y-m-d H:i:s',             // Standard datetime
            'Y-m-d',                   // Just date
            'd-M-Y',                   // 07-Mar-2026 format
            'd/m/Y',                   // DD/MM/YYYY
            'm/d/Y',                   // MM/DD/YYYY
            'j M Y',                   // 7 Mar 2026
            'M j, Y',                  // Mar 7, 2026
            'd.m.Y',                   // DD.MM.YYYY
        ];
        
        foreach ($formats as $format) {
            $timestamp = strtotime($dateString);
            if ($timestamp !== false) {
                return $timestamp;
            }
            
            $date = DateTime::createFromFormat($format, $dateString);
            if ($date !== false) {
                return $date->getTimestamp();
            }
        }
        
        return false;
    }
    
    private function detectDnsProvider($nsRecords) {
        if (empty($nsRecords)) {
            return null;
        }
        
        // Check each NS record for provider patterns
        foreach ($nsRecords as $record) {
            $hostname = trim($record);
            
            // Check for Cloudflare
            if (preg_match('/\.cloudflare\.com\.?$/i', $hostname)) {
                return "DNS on <span class='dns-provider-name'>Cloudflare</span>";
            }
            
            // Check for GoDaddy
            if (preg_match('/\.domaincontrol\.com\.?$/i', $hostname)) {
                return "DNS on <span class='dns-provider-name'>GoDaddy</span>";
            }
            
            // Check for Stack/20i
            if (preg_match('/\.stackdns\.com\.?$/i', $hostname)) {
                return "DNS on <span class='dns-provider-name'>Stack/20i</span>";
            }
            
            // Check for Amazon Route 53
            if (preg_match('/awsdns/i', $hostname)) {
                return "DNS on <span class='dns-provider-name'>Amazon Route 53</span>";
            }
        }
        
        return null;
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
            @media (max-width: 768px) {
                .header-section { padding: 6px; }
                .info-grid { flex-direction: column; gap: 5px; text-align: center; }
                .info-item { white-space: normal; text-align: center !important; font-size: 12px; }
            }
            .domain { font-weight: bold; }
            .dark .domain { color: #ff6b6b; }
            .light .domain { color: #e74c3c; }
            .dns-server { font-weight: bold; font-family: monospace; }
            .dark .dns-server { color: #4ade80; }
            .light .dns-server { color: #27ae60; }
            .compact-table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 13px; transition: all 0.3s; }
            @media (max-width: 768px) {
                .compact-table { font-size: 11px; }
                .compact-table th, .compact-table td { padding: 3px 4px; }
                .compact-table .ip, .compact-table .cname, .compact-table .url, 
                .compact-table .time, .compact-table .redirect-url { font-size: 10px; }
                .compact-table .status-success, .compact-table .status-cname, 
                .compact-table .status-redirect, .compact-table .status-error { font-size: 9px; }
                
                /* Mobile card layout for Host Information */
                .host-info-mobile { display: block; }
                .host-info-mobile .compact-table { display: none; }
                .compact-table { display: none; }
                .host-card { border-radius: 5px; margin: 8px 0; padding: 10px; transition: background-color 0.3s; }
                .dark .host-card { background: #3d3d3d; border: 1px solid #555; }
                .light .host-card { background: #f9f9f9; border: 1px solid #ddd; }
                .host-card .host-name { font-weight: bold; font-size: 13px; margin-bottom: 5px; }
                .host-card .host-detail { font-size: 11px; margin: 3px 0; }
                .host-card .host-detail strong { min-width: 60px; display: inline-block; }
                
                /* Color coding for mobile cards */
                .dark .host-card .ip { color: #4ade80 !important; }
                .light .host-card .ip { color: #27ae60 !important; }
                .dark .host-card .cname { color: #fbbf24 !important; }
                .light .host-card .cname { color: #f39c12 !important; }
                .dark .host-card .org { color: #a78bfa !important; }
                .light .host-card .org { color: #8e44ad !important; }
                .dark .host-card .status-success { color: #4ade80 !important; }
                .light .host-card .status-success { color: #27ae60 !important; }
                .dark .host-card .status-cname { color: #fbbf24 !important; }
                .light .host-card .status-cname { color: #f39c12 !important; }
                .dark .host-card .status-error { color: #f87171 !important; }
                .light .host-card .status-error { color: #e74c3c !important; }
                .dark .host-card .no-record { color: #f87171 !important; }
                .light .host-card .no-record { color: #e74c3c !important; }
                
                /* Mobile card layout for Redirect Results */
                .redirect-info-mobile { display: block; }
                .redirect-card { border-radius: 5px; margin: 8px 0; padding: 10px; transition: background-color 0.3s; }
                .dark .redirect-card { background: #3d3d3d; border: 1px solid #555; }
                .light .redirect-card { background: #f9f9f9; border: 1px solid #ddd; }
                .redirect-card .redirect-url-header { font-weight: bold; font-size: 13px; margin-bottom: 5px; }
                .redirect-card .redirect-detail { font-size: 11px; margin: 3px 0; }
                .redirect-card .redirect-detail strong { min-width: 60px; display: inline-block; }
                
                /* Color coding for mobile redirect cards */
                .dark .redirect-card .url { color: #60a5fa !important; }
                .light .redirect-card .url { color: #3498db !important; }
                .dark .redirect-card .time { color: #60a5fa !important; }
                .light .redirect-card .time { color: #3498db !important; }
                .dark .redirect-card .redirect-url { color: #60a5fa !important; }
                .light .redirect-card .redirect-url { color: #3498db !important; }
                .dark .redirect-card .status-success { color: #4ade80 !important; }
                .light .redirect-card .status-success { color: #27ae60 !important; }
                .dark .redirect-card .status-redirect { color: #fbbf24 !important; }
                .light .redirect-card .status-redirect { color: #f39c12 !important; }
                .dark .redirect-card .status-error { color: #f87171 !important; }
                .light .redirect-card .status-error { color: #e74c3c !important; }
                
                /* Mobile card layout for SSL Certificate */
                .ssl-info-mobile { display: block; }
                .ssl-card { border-radius: 5px; margin: 8px 0; padding: 10px; transition: background-color 0.3s; }
                .dark .ssl-card { background: #3d3d3d; border: 1px solid #555; }
                .light .ssl-card { background: #f9f9f9; border: 1px solid #ddd; }
                .ssl-card .ssl-host-header { font-weight: bold; font-size: 13px; margin-bottom: 5px; }
                .ssl-card .ssl-detail { font-size: 11px; margin: 3px 0; }
                .ssl-card .ssl-detail strong { min-width: 80px; display: inline-block; }
                
                /* Color coding for mobile SSL cards */
                .dark .ssl-card .ssl-provider { color: #a78bfa !important; }
                .light .ssl-card .ssl-provider { color: #8e44ad !important; }
                .dark .ssl-card .ssl-expiry { color: #60a5fa !important; }
                .light .ssl-card .ssl-expiry { color: #3498db !important; }
                .dark .ssl-card .ssl-good { color: #4ade80 !important; }
                .light .ssl-card .ssl-good { color: #27ae60 !important; }
                .dark .ssl-card .ssl-warning { color: #fbbf24 !important; }
                .light .ssl-card .ssl-warning { color: #f39c12 !important; }
                .dark .ssl-card .ssl-error { color: #f87171 !important; }
                .light .ssl-card .ssl-error { color: #e74c3c !important; }
            }
            @media (min-width: 769px) {
                .host-info-mobile { display: none; }
                .redirect-info-mobile { display: none; }
                .ssl-info-mobile { display: none; }
            }
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
            @media (max-width: 768px) {
                h4 { font-size: 14px; margin: 10px 0 6px 0; }
            }
        </style>
        ";
        
        $this->printHeader();
        $this->analyzeHostInfo();
        $this->analyzeRedirects();
        $this->analyzeSSLCertificate();
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