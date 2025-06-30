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
        
        $hostData = [];
        
        foreach ($hosts as $host) {
            $records = $this->dnsLookup($host, 'A', $this->dnsServer);
            
            if (empty($records)) {
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
                
                $hostData[] = [
                    'host' => $host,
                    'ip_cname' => "<span class='ip'>{$record}</span>",
                    'org' => "<span class='org'>{$org}</span>",
                    'status' => "<span class='status-success'>RESOLVED</span>",
                    'dc' => "<span class='datacenter'>{$dc}</span>"
                ];
            } else {
                // CNAME record
                $hostData[] = [
                    'host' => $host,
                    'ip_cname' => "<span class='cname'>{$record}</span>",
                    'org' => '',
                    'status' => "<span class='status-cname'>CNAME</span>",
                    'dc' => ''
                ];
                
                // Resolve CNAME to final IP
                $finalIp = $this->resolveCnameChain($record);
                if ($finalIp) {
                    $org = $this->getOrgInfo($finalIp);
                    $dc = $this->getDataCenter($record, $org);
                    
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
        
        // Detect hosting provider from collected organization data and display above table
        $hostingProvider = $this->detectHostingProvider($hostData);
        if ($hostingProvider) {
            echo "<div class='hosting-provider-info'>{$hostingProvider}</div>";
        }
        
        // Desktop table
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>Host</th><th>IP/CNAME</th><th>Organization</th><th>Status</th><th>CF-DC</th></tr></thead>";
        echo "<tbody>";
        
        // Output the collected host data to the table
        foreach ($hostData as $data) {
            echo "<tr>";
            echo "<td>{$data['host']}</td>";
            echo "<td>{$data['ip_cname']}</td>";
            echo "<td>" . (isset($data['org']) ? $data['org'] : '') . "</td>";
            echo "<td>{$data['status']}</td>";
            echo "<td>" . (isset($data['dc']) ? $data['dc'] : '') . "</td>";
            echo "</tr>";
        }
        
        echo "</tbody></table>";
        
        // Mobile cards
        echo "<div class='host-info-mobile'>";
        
        // Show hosting provider info above mobile cards too
        if ($hostingProvider) {
            echo "<div class='hosting-provider-info'>{$hostingProvider}</div>";
        }
        
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
    
    private function detectHostingProvider($hostData) {
        // Collect all organization information
        $organizations = [];
        foreach ($hostData as $data) {
            if (isset($data['org']) && $data['org'] !== 'N/A' && !empty($data['org'])) {
                // Extract plain text organization (remove HTML)
                $org = strip_tags($data['org']);
                $organizations[] = $org;
            }
        }
        
        if (empty($organizations)) {
            return null;
        }
        
        // Check for hosting providers in order of priority
        foreach ($organizations as $org) {
            // WPEngine detection
            if (stripos($org, 'WPEngine') !== false) {
                return "Hosting on <span class='hosting-provider-name'>WPEngine</span>";
            }
            
            // Shopify detection
            if (stripos($org, 'Shopify') !== false) {
                return "Hosting on <span class='hosting-provider-name'>Shopify</span>";
            }
            
            // Stack/20i detection (Anycast CDN Subnet)
            if (stripos($org, 'Anycast CDN Subnet') !== false) {
                return "Hosting on <span class='hosting-provider-name'>Stack/20i</span>";
            }
            
            // Cloudflare detection (special case - orange color)
            if (stripos($org, 'Cloudflare') !== false) {
                return "Hosting behind <span class='hosting-provider-cloudflare'>Cloudflare</span>";
            }
        }
        
        return null;
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
            echo "<td><a href='{$url}' target='_blank' class='{$urlClass} redirect-link'>{$url}</a></td>";
            echo "<td><span class='{$codeClass}'>{$result['code']}</span></td>";
            echo "<td><span class='redirect-url'>{$result['final_url']}</span></td>";
            echo "<td><span class='time'>" . number_format($result['time'], 2) . "s</span></td>";
            echo "</tr>";
            
            $redirectData[] = [
                'url' => "<a href='{$url}' target='_blank' class='{$urlClass} redirect-link'>{$url}</a>",
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
            
            $sslLabsUrl = "https://www.ssllabs.com/ssltest/analyze.html?d=" . urlencode($host) . "&hideResults=on&latest";
            
            echo "<tr>";
            echo "<td><a href='{$sslLabsUrl}' target='_blank' class='ssl-labs-link'>{$host}</a></td>";
            echo "<td><span class='ssl-provider'>{$sslInfo['provider']}</span></td>";
            echo "<td><span class='ssl-expiry'>{$sslInfo['valid_until']}</span></td>";
            echo "<td><span class='{$sslInfo['days_class']}'>{$sslInfo['days_left']}</span></td>";
            echo "<td><span class='{$sslInfo['status_class']}'>{$sslInfo['status']}</span></td>";
            echo "<td><span class='{$sslInfo['hsts_class']}'>{$sslInfo['hsts']}</span></td>";
            echo "</tr>";
            
            $sslData[] = [
                'host' => "<a href='{$sslLabsUrl}' target='_blank' class='ssl-labs-link'>{$host}</a>",
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
        // Desktop two-column layout
        echo "<div class='dns-records-desktop'>";
        echo "<div class='dns-column'>";
        
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
        
        echo "</div>"; // End left column
        echo "<div class='dns-column'>";
        
        // NS RECORDS
        $this->printSectionHeader('NS Records');
        $records = $this->dnsLookup($this->domain, 'NS', $this->dnsServer);
        
        // Sort NS records alphabetically
        if (!empty($records)) {
            sort($records);
        }
        
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
        
        echo "</div>"; // End right column
        echo "</div>"; // End desktop layout
        
        // Mobile single-column layout
        echo "<div class='dns-records-mobile'>";
        
        // MX RECORDS (mobile)
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
        
        // NS RECORDS (mobile)
        $this->printSectionHeader('NS Records');
        $records = $this->dnsLookup($this->domain, 'NS', $this->dnsServer);
        
        // Sort NS records alphabetically
        if (!empty($records)) {
            sort($records);
        }
        
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
        
        echo "</div>"; // End mobile layout
    }
    
    private function analyzeGtmAnalytics() {
        $this->printSectionHeader('GTM / Analytics (work in progress / alpha)');
        
        // Get page content for analysis
        $url = "https://www.{$this->domain}";
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        ]);
        
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200 || !$content) {
            echo "<p class='no-records'>Unable to analyze page content for analytics detection</p>";
            return;
        }
        
        $foundAnalytics = [];
        
        // Google Tag Manager detection (both inline script and direct src)
        if (preg_match('/googletagmanager\.com\/gtm\.js\?id=(GTM-[A-Z0-9]+)/i', $content, $matches) ||
            preg_match('/[\'\"](GTM-[A-Z0-9]+)[\'\"]\s*\)[^<]*<\/script>/i', $content, $matches)) {
            $gtmId = $matches[1];
            $foundAnalytics[] = [
                'type' => 'Google Tag Manager',
                'id' => "<strong>{$gtmId}</strong>",
                'method' => 'snippet in &lt;head&gt;'
            ];
        }
        
        // Google Analytics 4 detection
        if (preg_match('/googletagmanager\.com\/gtag\/js\?id=(G-[A-Z0-9]+)/i', $content, $matches)) {
            $ga4Id = $matches[1];
            
            // Check if loaded via GTM
            $loadMethod = 'snippet in &lt;head&gt;';
            if (preg_match('/gtag\(["\']config["\'],\s*["\']' . preg_quote($ga4Id, '/') . '["\']/', $content)) {
                // Check if there's also GTM on the page
                if (preg_match('/GTM-[A-Z0-9]+/', $content)) {
                    $loadMethod = 'via GTM';
                }
            }
            
            $foundAnalytics[] = [
                'type' => 'Google Analytics 4',
                'id' => "<strong>{$ga4Id}</strong>",
                'method' => $loadMethod
            ];
        }
        
        // Bozboz Plausible Analytics detection
        if (preg_match('/plausible\.bozboz\.co\.uk\/js\/script\.js/i', $content)) {
            $loadMethod = 'snippet in &lt;head&gt;';
            
            // Check if loaded via GTM (look for GTM container loading plausible)
            if (preg_match('/GTM-[A-Z0-9]+/', $content) && 
                !preg_match('/<script[^>]*src[^>]*plausible\.bozboz\.co\.uk/i', $content)) {
                $loadMethod = 'via GTM';
            }
            
            $foundAnalytics[] = [
                'type' => 'Bozboz Plausible Analytics',
                'id' => '',
                'method' => $loadMethod
            ];
        }
        
        // CookieYes detection
        if (preg_match('/cdn-cookieyes\.com\/client_data\/([a-f0-9]+)\/script\.js/i', $content, $matches)) {
            $cookieYesId = $matches[1];
            $loadMethod = 'snippet in &lt;head&gt;';
            
            // Check if loaded via GTM
            if (preg_match('/GTM-[A-Z0-9]+/', $content) && 
                !preg_match('/<script[^>]*src[^>]*cdn-cookieyes\.com/i', $content)) {
                $loadMethod = 'via GTM';
            }
            
            $foundAnalytics[] = [
                'type' => 'CookieYes',
                'id' => "<strong>{$cookieYesId}</strong>",
                'method' => $loadMethod
            ];
        }
        
        // Meta Pixel detection (Facebook Pixel)
        if (preg_match('/connect\.facebook\.net\/[^\/]+\/fbevents\.js/i', $content) || 
            preg_match('/fbq\(["\']init["\'],\s*["\'](\d+)["\']/', $content, $pixelMatches)) {
            
            $pixelId = isset($pixelMatches[1]) ? $pixelMatches[1] : '';
            $loadMethod = 'snippet in &lt;head&gt;';
            
            // Check if loaded via GTM
            if (preg_match('/GTM-[A-Z0-9]+/', $content) && 
                !preg_match('/<script[^>]*src[^>]*connect\.facebook\.net/i', $content)) {
                $loadMethod = 'via GTM';
            }
            
            $foundAnalytics[] = [
                'type' => 'Meta Pixel',
                'id' => $pixelId ? "<strong>{$pixelId}</strong>" : '',
                'method' => $loadMethod
            ];
        }
        
        // Display results
        if (empty($foundAnalytics)) {
            echo "<p class='no-records'>No analytics tools detected</p>";
        } else {
            foreach ($foundAnalytics as $analytics) {
                echo "<div class='dmarc-record'>";
                echo "<strong>{$analytics['type']}</strong> detected";
                
                if (!empty($analytics['id'])) {
                    // Determine the ID label based on the type
                    if (strpos($analytics['type'], 'Google Tag Manager') !== false) {
                        echo " - Container ID: {$analytics['id']}";
                    } elseif (strpos($analytics['type'], 'Google Analytics') !== false) {
                        echo " - Data Stream ID: {$analytics['id']}";
                    } elseif (strpos($analytics['type'], 'CookieYes') !== false) {
                        echo " - CookieYes ID: {$analytics['id']}";
                    } elseif (strpos($analytics['type'], 'Meta Pixel') !== false) {
                        echo " - Pixel ID: {$analytics['id']}";
                    }
                }
                
                echo " <em>({$analytics['method']})</em>";
                echo "</div>";
            }
        }
    }
    
    private function analyzeEmailSecurity() {
        // DMARC Record
        $this->printSectionHeader('DMARC Record');
        $dmarc = $this->dnsLookup("_dmarc.{$this->domain}", 'TXT', $this->dnsServer);
        if (empty($dmarc)) {
            echo "<p class='no-records'>No DMARC record found</p>";
        } else {
            echo "<div class='dmarc-record'>{$dmarc[0]}</div>";
        }
        
        // SPF Record  
        $this->printSectionHeader('SPF Record');
        $txtRecords = $this->dnsLookup($this->domain, 'TXT', $this->dnsServer);
        $spfRecord = null;
        if (!empty($txtRecords)) {
            foreach ($txtRecords as $record) {
                // Remove quotes and check for SPF
                $cleanRecord = trim($record, '"');
                if (stripos($cleanRecord, 'v=spf1') === 0) {
                    $spfRecord = $cleanRecord;
                    break;
                }
            }
        }
        if ($spfRecord) {
            // Split SPF record on spaces for easier reading
            $spfParts = explode(' ', $spfRecord);
            
            // Separate parts into categories for sorting
            $versionParts = [];
            $ip4Parts = [];
            $includeParts = [];
            $otherParts = [];
            
            foreach ($spfParts as $part) {
                $trimmedPart = trim($part);
                if (stripos($trimmedPart, 'v=spf') === 0) {
                    $versionParts[] = $trimmedPart;
                } elseif (stripos($trimmedPart, 'ip4:') === 0) {
                    $ip4Parts[] = $trimmedPart;
                } elseif (stripos($trimmedPart, 'include:') === 0) {
                    $includeParts[] = $trimmedPart;
                } else {
                    $otherParts[] = $trimmedPart;
                }
            }
            
            // Sort ip4 parts by IP address numerically
            usort($ip4Parts, function($a, $b) {
                // Extract IP from ip4:x.x.x.x or ip4:x.x.x.x/x format
                $ipA = preg_replace('/^ip4:/', '', $a);
                $ipB = preg_replace('/^ip4:/', '', $b);
                
                // Remove CIDR notation for comparison
                $ipA = explode('/', $ipA)[0];
                $ipB = explode('/', $ipB)[0];
                
                // Convert to comparable format
                return ip2long($ipA) <=> ip2long($ipB);
            });
            
            // Sort include parts alphabetically
            sort($includeParts, SORT_STRING | SORT_FLAG_CASE);
            
            // Combine in order: version, ip4 (sorted), include (sorted), others
            $sortedParts = array_merge($versionParts, $ip4Parts, $includeParts, $otherParts);
            
            echo "<div class='dmarc-record'>";
            foreach ($sortedParts as $index => $part) {
                if ($index > 0) {
                    echo "<br>";
                }
                echo htmlspecialchars($part);
            }
            echo "</div>";
        } else {
            echo "<p class='no-records'>No SPF record found</p>";
        }
        
        // DKIM Records
        $this->printSectionHeader('DKIM Records');
        $dkimSelectors = ['bozmail', 'boz', 's1', 's2', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'default', 'mail', 'dk', 'dkim1', 'dkim2'];
        $foundDkim = [];
        
        foreach ($dkimSelectors as $selector) {
            $dkimRecords = $this->dnsLookup("{$selector}._domainkey.{$this->domain}", 'TXT', $this->dnsServer);
            if (!empty($dkimRecords)) {
                // Remove quotes from DKIM record
                $cleanRecord = trim($dkimRecords[0], '"');
                $foundDkim[$selector] = $cleanRecord;
            }
        }
        
        if (!empty($foundDkim)) {
            foreach ($foundDkim as $selector => $record) {
                echo "<div class='dmarc-record'><strong>{$selector}:</strong> {$record}</div>";
            }
        } else {
            echo "<p class='no-records'>No DKIM records found (checked common selectors)</p>";
        }
        
        // TXT Records (root domain only) - exclude SPF record
        $this->printSectionHeader('TXT Records');
        if (empty($txtRecords)) {
            echo "<p class='no-records'>No TXT records found</p>";
        } else {
            $nonSpfRecords = [];
            foreach ($txtRecords as $record) {
                $cleanRecord = trim($record, '"');
                // Exclude SPF records
                if (stripos($cleanRecord, 'v=spf1') !== 0) {
                    $nonSpfRecords[] = $cleanRecord;
                }
            }
            
            if (empty($nonSpfRecords)) {
                echo "<p class='no-records'>No non-SPF TXT records found</p>";
            } else {
                echo "<div class='dmarc-record'>";
                foreach ($nonSpfRecords as $index => $record) {
                    if ($index > 0) {
                        echo "<br>";
                    }
                    echo htmlspecialchars($record);
                }
                echo "</div>";
            }
        }
    }
    
    private function analyzeDomainInfo() {
        // Desktop two-column layout
        echo "<div class='domain-info-desktop'>";
        echo "<div class='domain-column'>";
        
        $this->printSectionHeader('Registrar Information');
        $whois = $this->whoisLookup($this->domain);
        
        if (preg_match('/Registrar:\s*(.+)/i', $whois, $matches)) {
            $registrarRaw = trim($matches[1]);
            $registrarFriendly = $this->detectRegistrarProvider($registrarRaw);
            
            if ($registrarFriendly) {
                echo "<div class='registrar-provider-info'>Domain Registered with <span class='registrar-provider-name'>{$registrarFriendly}</span></div>";
            }
            
            echo "<p class='registrar'>" . $registrarRaw . "</p>";
        } else {
            echo "<p class='no-records'>Registrar information not found</p>";
        }
        
        echo "</div>"; // End left column
        echo "<div class='domain-column'>";
        
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
        
        echo "</div>"; // End right column
        echo "</div>"; // End desktop layout
        
        // Mobile single-column layout
        echo "<div class='domain-info-mobile'>";
        
        $this->printSectionHeader('Registrar Information');
        if (preg_match('/Registrar:\s*(.+)/i', $whois, $matches)) {
            $registrarRaw = trim($matches[1]);
            $registrarFriendly = $this->detectRegistrarProvider($registrarRaw);
            
            if ($registrarFriendly) {
                echo "<div class='registrar-provider-info'>Domain Registered with <span class='registrar-provider-name'>{$registrarFriendly}</span></div>";
            }
            
            echo "<p class='registrar'>" . $registrarRaw . "</p>";
        } else {
            echo "<p class='no-records'>Registrar information not found</p>";
        }
        
        $this->printSectionHeader('Domain Expiration');
        if ($expiryInfo) {
            echo "<p class='expiry'>";
            echo "<span class='expiry-date'>{$expiryInfo['formatted_date']}</span> ";
            echo "(<span class='{$expiryInfo['days_class']}'>{$expiryInfo['days_text']}</span>)";
            echo "</p>";
        } else {
            echo "<p class='no-records'>Expiration date not found</p>";
        }
        
        echo "</div>"; // End mobile layout
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
            return "Email on <span class='email-provider-name'>Google Workspace</span>";
        }
        
        // Check for Microsoft 365 pattern
        foreach ($mxRecords as $record) {
            $parts = explode(' ', trim($record), 2);
            if (count($parts) >= 2) {
                $hostname = trim($parts[1]);
                if (preg_match('/\.mail\.protection\.outlook\.com\.?$/', $hostname)) {
                    return "Email on <span class='email-provider-name'>Microsoft 365</span>";
                }
            }
        }
        
        // Check for Stackmail/20i pattern
        foreach ($mxRecords as $record) {
            $parts = explode(' ', trim($record), 2);
            if (count($parts) >= 2) {
                $hostname = trim($parts[1]);
                if ($hostname === 'mx.stackmail.com.' || $hostname === 'mx.stackmail.com') {
                    return "Email on <span class='email-provider-name'>Stackmail / 20i</span>";
                }
            }
        }
        
        return null;
    }
    
    private function detectRegistrarProvider($registrarText) {
        $registrarLower = strtolower($registrarText);
        
        if (strpos($registrarLower, 'bozboz') !== false) {
            return 'Bozboz';
        }
        
        if (strpos($registrarLower, 'godaddy') !== false) {
            return 'GoDaddy';
        }
        
        if (strpos($registrarLower, 'cloudflare') !== false) {
            return 'Cloudflare';
        }
        
        if (strpos($registrarLower, 'enom') !== false) {
            return '123-REG ?';
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
        
        // Check for specific Bozboz Cloudflare nameservers
        $bozbozCloudflareNs = ['amy.ns.cloudflare.com', 'woz.ns.cloudflare.com'];
        $foundBozbozNs = [];
        
        foreach ($nsRecords as $record) {
            $hostname = trim($record);
            $hostname = rtrim($hostname, '.');  // Remove trailing dot
            
            if (in_array($hostname, $bozbozCloudflareNs)) {
                $foundBozbozNs[] = $hostname;
            }
        }
        
        // If we found both Bozboz Cloudflare nameservers
        if (count($foundBozbozNs) >= 2) {
            return "DNS on <span class='dns-provider-cloudflare'>Cloudflare (Bozboz account)</span>";
        }
        
        // Check each NS record for provider patterns
        foreach ($nsRecords as $record) {
            $hostname = trim($record);
            
            // Check for Cloudflare (special orange color like hosting)
            if (preg_match('/\.cloudflare\.com\.?$/i', $hostname)) {
                return "DNS on <span class='dns-provider-cloudflare'>Cloudflare</span>";
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
    
    private function analyzeFramework() {
        $this->printSectionHeader('Framework Detection (beta)');
        
        $hosts = [
            "http://{$this->domain}",
            "https://{$this->domain}",
            "http://www.{$this->domain}",
            "https://www.{$this->domain}"
        ];
        
        $detectedFrameworks = [];
        
        foreach ($hosts as $url) {
            $frameworks = $this->detectFrameworks($url);
            if (!empty($frameworks)) {
                $detectedFrameworks = array_merge($detectedFrameworks, $frameworks);
                break; // Found working URL, stop trying others
            }
        }
        
        if (empty($detectedFrameworks)) {
            echo "<div class='no-records'>No frameworks detected or site unavailable</div>";
            return;
        }
        
        // Remove duplicates and sort by confidence
        $uniqueFrameworks = [];
        foreach ($detectedFrameworks as $framework) {
            $key = $framework['name'] . '_' . $framework['version'];
            if (!isset($uniqueFrameworks[$key]) || $uniqueFrameworks[$key]['confidence'] < $framework['confidence']) {
                $uniqueFrameworks[$key] = $framework;
            }
        }
        
        // Custom sorting: prioritize specific frameworks, then by confidence
        usort($uniqueFrameworks, function($a, $b) {
            // Define priority order
            $priorityOrder = ['PHP', 'WordPress', 'Laravel', 'Oxygen', 'Elementor'];
            
            $aPriority = array_search($a['name'], $priorityOrder);
            $bPriority = array_search($b['name'], $priorityOrder);
            
            // If both are in priority list, sort by priority order
            if ($aPriority !== false && $bPriority !== false) {
                return $aPriority - $bPriority;
            }
            
            // If only A is in priority list, A comes first
            if ($aPriority !== false && $bPriority === false) {
                return -1;
            }
            
            // If only B is in priority list, B comes first
            if ($aPriority === false && $bPriority !== false) {
                return 1;
            }
            
            // If neither is in priority list, sort by confidence (highest first)
            return $b['confidence'] - $a['confidence'];
        });
        
        // Desktop table
        echo "<table class='compact-table'>";
        echo "<thead><tr><th>Framework/Technology</th><th>Version</th><th>Confidence</th><th>Detection Method</th></tr></thead>";
        echo "<tbody>";
        
        $frameworkData = [];
        
        foreach ($uniqueFrameworks as $framework) {
            $confidenceClass = '';
            if ($framework['confidence'] >= 90) $confidenceClass = 'status-success';
            elseif ($framework['confidence'] >= 70) $confidenceClass = 'status-redirect';
            else $confidenceClass = 'status-error';
            
            echo "<tr>";
            echo "<td><span class='framework-name'>{$framework['name']}</span></td>";
            echo "<td><span class='framework-version'>{$framework['version']}</span></td>";
            echo "<td><span class='{$confidenceClass}'>{$framework['confidence']}%</span></td>";
            echo "<td><span class='detection-method'>{$framework['method']}</span></td>";
            echo "</tr>";
            
            $frameworkData[] = [
                'name' => "<span class='framework-name'>{$framework['name']}</span>",
                'version' => "<span class='framework-version'>{$framework['version']}</span>",
                'confidence' => "<span class='{$confidenceClass}'>{$framework['confidence']}%</span>",
                'method' => "<span class='detection-method'>{$framework['method']}</span>"
            ];
        }
        
        echo "</tbody></table>";
        
        // Mobile cards
        echo "<div class='framework-info-mobile'>";
        foreach ($frameworkData as $data) {
            echo "<div class='framework-card'>";
            echo "<div class='framework-name-header'>{$data['name']}</div>";
            echo "<div class='framework-detail'><strong>Version:</strong> {$data['version']}</div>";
            echo "<div class='framework-detail'><strong>Confidence:</strong> {$data['confidence']}</div>";
            echo "<div class='framework-detail'><strong>Method:</strong> {$data['method']}</div>";
            echo "</div>";
        }
        echo "</div>";
    }
    
    private function detectFrameworks($url) {
        $frameworks = [];
        
        // Get HTTP response with headers and body
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        
        if ($httpCode !== 200 || !$response) {
            return [];
        }
        
        $headers = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        
        // Analyze HTTP headers
        $frameworks = array_merge($frameworks, $this->analyzeHeaders($headers));
        
        // Analyze HTML content
        $frameworks = array_merge($frameworks, $this->analyzeHtmlContent($body));
        
        // Analyze JavaScript and CSS paths
        $frameworks = array_merge($frameworks, $this->analyzeAssetPaths($body));
        
        // Analyze meta tags
        $frameworks = array_merge($frameworks, $this->analyzeMetaTags($body));
        
        return $frameworks;
    }
    
    private function analyzeHeaders($headers) {
        $frameworks = [];
        $headerLines = explode("\n", $headers);
        
        foreach ($headerLines as $line) {
            $line = trim($line);
            
            // X-Powered-By header
            if (preg_match('/X-Powered-By:\s*(.+)/i', $line, $matches)) {
                $poweredBy = trim($matches[1]);
                
                if (preg_match('/PHP\/(\d+\.\d+\.\d+)/i', $poweredBy, $phpMatches)) {
                    $frameworks[] = [
                        'name' => 'PHP',
                        'version' => $phpMatches[1],
                        'confidence' => 95,
                        'method' => 'X-Powered-By header'
                    ];
                }
                
                if (preg_match('/ASP\.NET/i', $poweredBy)) {
                    $frameworks[] = [
                        'name' => 'ASP.NET',
                        'version' => 'Unknown',
                        'confidence' => 95,
                        'method' => 'X-Powered-By header'
                    ];
                }
            }
            
            // Server header
            if (preg_match('/Server:\s*(.+)/i', $line, $matches)) {
                $server = trim($matches[1]);
                
                if (preg_match('/Apache\/(\d+\.\d+\.\d+)/i', $server, $apacheMatches)) {
                    $frameworks[] = [
                        'name' => 'Apache',
                        'version' => $apacheMatches[1],
                        'confidence' => 90,
                        'method' => 'Server header'
                    ];
                }
                
                if (preg_match('/nginx\/(\d+\.\d+\.\d+)/i', $server, $nginxMatches)) {
                    $frameworks[] = [
                        'name' => 'Nginx',
                        'version' => $nginxMatches[1],
                        'confidence' => 90,
                        'method' => 'Server header'
                    ];
                }
            }
            
            // X-Generator header
            if (preg_match('/X-Generator:\s*(.+)/i', $line, $matches)) {
                $generator = trim($matches[1]);
                $frameworks[] = [
                    'name' => $generator,
                    'version' => 'Unknown',
                    'confidence' => 85,
                    'method' => 'X-Generator header'
                ];
            }
        }
        
        return $frameworks;
    }
    
    private function analyzeHtmlContent($body) {
        $frameworks = [];
        
        // WordPress detection with improved version detection
        if (preg_match('/wp-content|wp-includes|wp-admin/i', $body)) {
            $version = 'Unknown';
            $method = 'Content analysis';
            
            // Try to get WordPress version from various assets
            // Pattern 1: Oxygen styles CSS link (very reliable WordPress indicator)
            if (preg_match('/oxygen-styles-css[^?]*\?[^\'">]*xlink=css[^\'">]*ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $versionNum = $matches[1];
                if (version_compare($versionNum, '3.0', '>=') && version_compare($versionNum, '8.0', '<')) {
                    $version = $versionNum;
                    $method = 'Oxygen styles version';
                }
            }
            // Pattern 2: WordPress emoji settings (very reliable WordPress indicator)
            elseif (preg_match('/wp-emoji-release\.min\.js\?ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $versionNum = $matches[1];
                if (version_compare($versionNum, '3.0', '>=') && version_compare($versionNum, '8.0', '<')) {
                    $version = $versionNum;
                    $method = 'WordPress emoji version';
                }
            }
            // Pattern 3: Oxygen AOS CSS (reliable WordPress indicator)
            elseif (preg_match('/oxygen\/component-framework\/vendor\/aos\/aos\.css\?ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $versionNum = $matches[1];
                if (version_compare($versionNum, '3.0', '>=') && version_compare($versionNum, '8.0', '<')) {
                    $version = $versionNum;
                    $method = 'Oxygen AOS version';
                }
            }
            // Pattern 4: Oxygen cache files with ver= (most reliable WordPress indicator)
            elseif (preg_match('/oxygen-cache-\d+[^?]*\?[^\'">]*ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $versionNum = $matches[1];
                if (version_compare($versionNum, '3.0', '>=') && version_compare($versionNum, '8.0', '<')) {
                    $version = $versionNum;
                    $method = 'Oxygen cache version';
                }
            }
            // Pattern 2: WordPress core styles/scripts (very specific WordPress core assets)
            elseif (preg_match('/wp-(?:admin|includes)\/(?:css|js)\/[^?]*\?[^\'">]*ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $versionNum = $matches[1];
                // WordPress versions are typically 5.0+ currently, exclude plugin versions
                if (version_compare($versionNum, '5.0', '>=') && 
                    version_compare($versionNum, '8.0', '<') &&
                    !preg_match('/^[34]\./', $versionNum)) { // Exclude 3.x and 4.x versions (likely plugins)
                    $version = $versionNum;
                    $method = 'WordPress core asset';
                }
            }
            // Pattern 3: wp-includes assets (fallback, with stricter validation)
            elseif (preg_match('/wp-includes.*ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $versionNum = $matches[1];
                // Validate this looks like a WordPress version (not jQuery, React, etc)
                // WordPress versions: 3.0-7.x range, typically with specific patterns
                // Exclude common false positives: jQuery (3.6.x, 3.7.x), React (18.x)
                if (version_compare($versionNum, '3.0', '>=') && 
                    version_compare($versionNum, '8.0', '<') &&
                    !preg_match('/^3\.[67]\./', $versionNum) && // Exclude jQuery 3.6.x, 3.7.x
                    !preg_match('/^18\./', $versionNum)) {     // Exclude React 18.x
                    $version = $versionNum;
                    $method = 'Asset version analysis';
                }
            }
            // Also check for WordPress REST API indicators
            elseif (preg_match('/wp-json\/wp\/v2|rest_route.*wp\/v(\d+)/i', $body, $matches)) {
                if (isset($matches[1])) {
                    $version = 'v' . $matches[1] . ' (REST API)';
                    $method = 'REST API analysis';
                }
            }
            
            $frameworks[] = [
                'name' => 'WordPress',
                'version' => $version,
                'confidence' => 85, // Lower confidence since meta tag detection is more reliable
                'method' => $method
            ];
        }
        
        // Oxygen Builder detection with version extraction
        if (preg_match('/oxygen.*\.css|oxygen.*\.js|ct-section|oxy-|oxygen-body/i', $body)) {
            $version = 'Unknown';
            $method = 'Content analysis';
            
            // Try to get Oxygen version from CSS link
            if (preg_match('/oxygen\/component-framework\/oxygen\.css\?ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $version = $matches[1];
                $method = 'Oxygen CSS version';
            }
            // Also check for other Oxygen asset patterns
            elseif (preg_match('/oxygen[^?]*\?[^\'">]*ver=(\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $version = $matches[1];
                $method = 'Oxygen asset version';
            }
            
            $frameworks[] = [
                'name' => 'Oxygen',
                'version' => $version,
                'confidence' => 90, // Higher confidence when we find specific Oxygen patterns
                'method' => $method
            ];
        }
        
        // React detection - more specific patterns
        if (preg_match('/data-reactroot|__REACT_DEVTOOLS__|ReactDOM\.render|react\.production\.min\.js|react\.development\.js/i', $body)) {
            $frameworks[] = [
                'name' => 'React',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'JavaScript analysis'
            ];
        }
        
        // Angular detection - more specific patterns
        if (preg_match('/ng-app|ng-controller|ng-version|angular\.min\.js|angular\.js|@angular\/core/i', $body)) {
            $frameworks[] = [
                'name' => 'Angular',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'JavaScript analysis'
            ];
        }
        
        // Vue.js detection - more specific patterns
        if (preg_match('/vue\.min\.js|vue\.js|v-if=|v-for=|v-show=|__VUE__|Vue\.component/i', $body)) {
            $frameworks[] = [
                'name' => 'Vue.js',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'JavaScript analysis'
            ];
        }
        
        // Drupal detection
        if (preg_match('/sites\/default\/files|Drupal\.settings/i', $body)) {
            $frameworks[] = [
                'name' => 'Drupal',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'Content analysis'
            ];
        }
        
        // Joomla detection
        if (preg_match('/\/components\/com_|Joomla!/i', $body)) {
            $frameworks[] = [
                'name' => 'Joomla',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'Content analysis'
            ];
        }
        
        // Shopify detection
        if (preg_match('/cdn\.shopify\.com|Shopify\.theme/i', $body)) {
            $frameworks[] = [
                'name' => 'Shopify',
                'version' => 'Unknown',
                'confidence' => 90,
                'method' => 'CDN analysis'
            ];
        }
        
        // WooCommerce detection - more specific patterns
        if (preg_match('/woocommerce.*\.css|woocommerce.*\.js|wc-ajax|woocommerce-page|shop_table|woocommerce-cart|woocommerce-checkout/i', $body)) {
            $frameworks[] = [
                'name' => 'WooCommerce',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'Content analysis'
            ];
        }
        
        return $frameworks;
    }
    
    private function analyzeAssetPaths($body) {
        $frameworks = [];
        
        // Laravel detection - more specific patterns, exclude Shopify
        if (preg_match('/mix-manifest\.json|laravel_session|Laravel\s+v\d/i', $body) ||
            (preg_match('/csrf-token|_token/i', $body) && !preg_match('/shopify|myshopify/i', $body))) {
            
            // Additional check: Laravel typically has specific asset patterns
            if (preg_match('/\/js\/app\.js|\/css\/app\.css|mix-manifest|laravel_session/i', $body) ||
                preg_match('/Laravel\s+v\d|laravel\.com/i', $body)) {
                $frameworks[] = [
                    'name' => 'Laravel',
                    'version' => 'Unknown',
                    'confidence' => 85,
                    'method' => 'Framework analysis'
                ];
            }
        }
        
        // Next.js detection
        if (preg_match('/_next\/static/i', $body)) {
            $frameworks[] = [
                'name' => 'Next.js',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'Asset path analysis'
            ];
        }
        
        // Nuxt.js detection
        if (preg_match('/_nuxt\//i', $body)) {
            $frameworks[] = [
                'name' => 'Nuxt.js',
                'version' => 'Unknown',
                'confidence' => 85,
                'method' => 'Asset path analysis'
            ];
        }
        
        // Bootstrap detection
        if (preg_match('/bootstrap\.(?:min\.)?(?:css|js)/i', $body)) {
            $version = 'Unknown';
            if (preg_match('/bootstrap[\/-](\d+\.\d+\.?\d*)/i', $body, $matches)) {
                $version = $matches[1];
            }
            $frameworks[] = [
                'name' => 'Bootstrap',
                'version' => $version,
                'confidence' => 80,
                'method' => 'CSS framework analysis'
            ];
        }
        
        // jQuery detection - more specific patterns
        if (preg_match('/jquery[\.-](\d+\.\d+\.?\d*)/i', $body, $matches)) {
            $frameworks[] = [
                'name' => 'jQuery',
                'version' => $matches[1],
                'confidence' => 90,
                'method' => 'JavaScript library analysis'
            ];
        } elseif (preg_match('/jquery\.min\.js|jquery\.js|\$\(document\)\.ready|\$\(function/i', $body)) {
            $frameworks[] = [
                'name' => 'jQuery',
                'version' => 'Unknown',
                'confidence' => 80,
                'method' => 'JavaScript library analysis'
            ];
        }
        
        return $frameworks;
    }
    
    private function analyzeMetaTags($body) {
        $frameworks = [];
        
        // Generator meta tag
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\'>]+)["\'][^>]*>/i', $body, $matches)) {
            $generator = trim($matches[1]);
            
            if (preg_match('/WordPress\s+(\d+\.\d+\.?\d*)/i', $generator, $wpMatches)) {
                $frameworks[] = [
                    'name' => 'WordPress',
                    'version' => $wpMatches[1],
                    'confidence' => 95,
                    'method' => 'Meta generator tag'
                ];
            } elseif (preg_match('/Drupal\s+(\d+)/i', $generator, $drupalMatches)) {
                $frameworks[] = [
                    'name' => 'Drupal',
                    'version' => $drupalMatches[1],
                    'confidence' => 95,
                    'method' => 'Meta generator tag'
                ];
            } elseif (preg_match('/Elementor\s+(\d+\.\d+\.?\d*)/i', $generator, $elementorMatches)) {
                $frameworks[] = [
                    'name' => 'Elementor',
                    'version' => $elementorMatches[1],
                    'confidence' => 95,
                    'method' => 'Meta generator tag'
                ];
            } else {
                // Clean up generic generator content - remove semicolon and everything after
                $cleanName = preg_replace('/;.*$/', '', $generator);
                $cleanName = trim($cleanName);
                
                $frameworks[] = [
                    'name' => $cleanName,
                    'version' => 'Unknown',
                    'confidence' => 85,
                    'method' => 'Meta generator tag'
                ];
            }
        }
        
        return $frameworks;
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
                
                /* Mobile card layout for Framework Detection */
                .framework-info-mobile { display: block; }
                .framework-card { border-radius: 5px; margin: 8px 0; padding: 10px; transition: background-color 0.3s; }
                .dark .framework-card { background: #3d3d3d; border: 1px solid #555; }
                .light .framework-card { background: #f9f9f9; border: 1px solid #ddd; }
                .framework-card .framework-name-header { font-weight: bold; font-size: 13px; margin-bottom: 5px; }
                .framework-card .framework-detail { font-size: 11px; margin: 3px 0; }
                .framework-card .framework-detail strong { min-width: 80px; display: inline-block; }
                
                /* Color coding for mobile framework cards */
                .dark .framework-card .framework-name { color: #4ade80 !important; font-weight: bold; }
                .light .framework-card .framework-name { color: #27ae60 !important; font-weight: bold; }
                .dark .framework-card .framework-version { color: #60a5fa !important; }
                .light .framework-card .framework-version { color: #3498db !important; }
                .dark .framework-card .detection-method { color: #a78bfa !important; }
                .light .framework-card .detection-method { color: #8e44ad !important; }
            }
            @media (min-width: 769px) {
                .host-info-mobile { display: none; }
                .redirect-info-mobile { display: none; }
                .ssl-info-mobile { display: none; }
                .framework-info-mobile { display: none; }
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
            .dark .compact-table .ssl-expiry { color: #60a5fa !important; }
            .light .compact-table .ssl-expiry { color: #3498db !important; }
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
            .dmarc-record { padding: 8px; border-radius: 3px; font-family: monospace; word-break: break-all; font-size: 12px; transition: all 0.3s; }
            .dark .dmarc-record { background: #3d3d3d; color: #e0e0e0; }
            .light .dmarc-record { background: #f8f9fa; color: #333; }
            .registrar, .expiry { font-weight: bold; font-size: 13px; }
            .dark .registrar, .dark .expiry { color: #4ade80; }
            .light .registrar, .light .expiry { color: #27ae60; }
            .no-records { font-style: italic; font-size: 12px; margin: 5px 0; }
            .dark .no-records { color: #9ca3af; }
            .light .no-records { color: #666; }
            .framework-name { font-weight: bold; font-size: 13px; }
            .dark .framework-name { color: #4ade80; }
            .light .framework-name { color: #27ae60; }
            .framework-version { font-family: monospace; font-size: 12px; }
            .dark .framework-version { color: #60a5fa; }
            .light .framework-version { color: #3498db; }
            .detection-method { font-size: 12px; }
            .dark .detection-method { color: #a78bfa; }
            .light .detection-method { color: #8e44ad; }
            h4 { padding-bottom: 2px; margin: 15px 0 8px 0; font-size: 16px; transition: all 0.3s; }
            .dark h4 { color: #60a5fa; border-bottom: 1px solid #60a5fa; }
            .light h4 { color: #2c3e50; border-bottom: 1px solid #3498db; }
            h4:first-child { margin-top: 0; }
            
            /* Adjust spacing for Domain Registration/Expiration sections on desktop */
            @media (min-width: 769px) {
                .domain-info-desktop h4 { margin: 20px 0 5px 0; }
            }
            @media (max-width: 768px) {
                h4 { font-size: 14px; margin: 10px 0 6px 0; }
            }
            
            /* Redirect URL link styling */
            .redirect-link {
                color: inherit !important;
                text-decoration: none !important;
                border-bottom: 1px dotted currentColor !important;
            }
            .redirect-link:hover {
                text-decoration: underline !important;
                opacity: 0.8;
            }
            
            /* Hosting provider styling */
            .hosting-provider-info {
                margin-bottom: 10px;
                font-size: 14px;
                font-weight: normal;
            }
            .hosting-provider-name {
                color: #4CAF50 !important;
                font-weight: bold !important;
            }
            .hosting-provider-cloudflare {
                color: #ff6600 !important;
                font-weight: bold !important;
            }
        </style>
        ";
        
        $this->printHeader();
        $this->analyzeHostInfo();
        $this->analyzeRedirects();
        $this->analyzeSSLCertificate();
        $this->analyzeDnsRecords();
        $this->analyzeDomainInfo();
        $this->analyzeFramework();
        $this->analyzeGtmAnalytics();
        $this->analyzeEmailSecurity();
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