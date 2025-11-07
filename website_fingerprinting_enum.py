#!/usr/bin/env python3
"""
Advanced Python Implementation - Website Fingerprinting Tool
Advanced website technology detection and fingerprinting
"""

import requests
import re
import json
import ssl
import socket
import argparse
import sys
import hashlib
import time
import random
import threading
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class ScanResult:
    """Data class to store scan results"""
    target: str
    status_code: int
    technologies: Dict[str, Any]
    headers: Dict[str, str]
    hashes: Dict[str, str]
    meta_info: Dict[str, Any]
    aggressive_findings: Dict[str, Any]
    timestamp: float

class PluginBase:
    """Base class for all detection plugins"""
    def __init__(self):
        self.name = "Base Plugin"
        self.confidence = 0
        self.patterns = []
    
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

class WordPressPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "WordPress"
        self.confidence = 90
        
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        wp_indicators = [
            (r'wp-content|wp-includes', 20),
            (r'wordpress', 15),
            (r'/wp-json/', 25),
            (r'wp-embed.min.js', 15),
            (r'wp-admin', 10)
        ]
        
        score = 0
        version = None
        content_lower = content.lower()
        
        for pattern, points in wp_indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        
        # Version detection
        version_patterns = [
            r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"',
            r'wp-includes/js/wp-embed.min.js\?ver=(\d+\.\d+(?:\.\d+)?)',
            r'wp-includes/css/wp-embed.min.css\?ver=(\d+\.\d+(?:\.\d+)?)',
            r'wordpress (\d+\.\d+(?:\.\d+)?)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                score += 30
                break
        
        if score >= 50:
            result = {'confidence': min(score, 100)}
            if version:
                result['version'] = version
            return result
        return None

class JoomlaPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Joomla"
        
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        joomla_indicators = [
            (r'joomla', 25),
            (r'/media/jui/', 30),
            (r'/media/system/', 30),
            (r'com_content', 20),
            (r'index.php?option=', 15)
        ]
        
        score = 0
        content_lower = content.lower()
        
        for pattern, points in joomla_indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        
        if score >= 50:
            return {'confidence': min(score, 100)}
        return None

class DrupalPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Drupal"
        
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        drupal_indicators = [
            (r'drupal', 25),
            (r'sites/all/', 30),
            (r'/core/assets/', 30),
            (r'drupal\.js', 20),
            (r'name="generator" content="Drupal', 35)
        ]
        
        score = 0
        content_lower = content.lower()
        
        for pattern, points in drupal_indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        
        # Version detection
        version_match = re.search(r'Drupal (\d+\.\d+(?:\.\d+)?)', content, re.IGNORECASE)
        version = version_match.group(1) if version_match else None
        
        if version:
            score += 25
        
        if score >= 50:
            result = {'confidence': min(score, 100)}
            if version:
                result['version'] = version
            return result
        return None

class PHPPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "PHP"
        
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'\.php', 40),
            (r'PHP/', 60),
            (r'X-Powered-By: PHP', 80)
        ]
        
        score = 0
        
        # Check headers
        x_powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in x_powered_by:
            score += 70
        
        # Check content
        content_lower = content.lower()
        for pattern, points in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        
        if score >= 40:
            return {'confidence': min(score, 100)}
        return None

class ServerPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Web Server"
        
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        server_header = headers.get('server', '').lower()
        
        servers = {
            'nginx': ('nginx', 90),
            'apache': ('apache', 85),
            'iis': ('microsoft-iis', 90),
            'cloudflare': ('cloudflare', 95),
            'litespeed': ('litespeed', 85)
        }
        
        for server_name, (pattern, confidence) in servers.items():
            if pattern in server_header:
                return {
                    'type': server_name,
                    'confidence': confidence,
                    'version': self.extract_version(server_header)
                }
        
        return None
    
    def extract_version(self, server_string: str) -> Optional[str]:
        version_match = re.search(r'/(\d+\.\d+(?:\.\d+)?)', server_string)
        return version_match.group(1) if version_match else None

class JavaScriptFrameworkPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "JavaScript Framework"
        
    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        frameworks = {
            'React': [
                (r'react|react-dom', 70),
                (r'__reactInternalInstance', 90)
            ],
            'Angular': [
                (r'ng-|angular', 70),
                (r'angular\.js', 80)
            ],
            'Vue.js': [
                (r'vue\.js|__vue__', 80),
                (r'v-|@click', 70)
            ],
            'jQuery': [
                (r'jquery', 60),
                (r'\$\.|jQuery', 70)
            ]
        }
        
        results = {}
        content_lower = content.lower()
        
        for framework, patterns in frameworks.items():
            score = 0
            for pattern, confidence in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    score = max(score, confidence)
            
            if score >= 60:
                results[framework] = {'confidence': score}
        
        return results if results else None

class AdvancedScanner:
    def __init__(self, verbose=False, aggression_level=1, max_threads=10, timeout=10):
        self.verbose = verbose
        self.aggression_level = aggression_level
        self.max_threads = max_threads
        self.timeout = timeout
        self.plugins = self._load_plugins()
        self.session = self._create_session()
        
    def _load_plugins(self) -> List[PluginBase]:
        """Load all detection plugins"""
        return [
            WordPressPlugin(),
            JoomlaPlugin(),
            DrupalPlugin(),
            PHPPlugin(),
            ServerPlugin(),
            JavaScriptFrameworkPlugin()
        ]
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; Advanced/2.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        session.verify = False
        session.timeout = self.timeout
        return session
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages with levels"""
        if self.verbose:
            colors = {
                "INFO": "\033[94m",
                "WARNING": "\033[93m",
                "ERROR": "\033[91m",
                "SUCCESS": "\033[92m"
            }
            color = colors.get(level, "\033[0m")
            print(f"{color}[{level}] {message}\033[0m")
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL by adding scheme if missing"""
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first, then HTTP
            try:
                test_url = 'https://' + url
                response = self.session.head(test_url, timeout=5, allow_redirects=True)
                return response.url
            except:
                return 'http://' + url
        return url
    
    def get_response(self, url: str) -> Optional[requests.Response]:
        """Get HTTP response with comprehensive error handling"""
        try:
            response = self.session.get(
                url,
                allow_redirects=True,
                timeout=self.timeout
            )
            return response
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed for {url}: {e}", "ERROR")
            return None
    
    def extract_headers_info(self, response: requests.Response) -> Dict[str, Any]:
        """Extract and analyze HTTP headers"""
        headers_info = {}
        interesting_headers = [
            'server', 'x-powered-by', 'content-type', 'set-cookie',
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy'
        ]
        
        for header in interesting_headers:
            if header in response.headers:
                headers_info[header] = response.headers[header]
        
        # Analyze cookies
        cookies = response.headers.get('set-cookie', '')
        if 'wordpress' in cookies.lower():
            headers_info['wordpress_cookie'] = True
        if 'joomla' in cookies.lower():
            headers_info['joomla_cookie'] = True
        
        return headers_info
    
    def calculate_hashes(self, content: str) -> Dict[str, str]:
        """Calculate various hashes of the content"""
        return {
            'md5': hashlib.md5(content.encode()).hexdigest(),
            'sha1': hashlib.sha1(content.encode()).hexdigest(),
            'sha256': hashlib.sha256(content.encode()).hexdigest()
        }
    
    def run_plugins(self, response: requests.Response) -> Dict[str, Any]:
        """Run all detection plugins"""
        technologies = {}
        content = response.text
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        for plugin in self.plugins:
            try:
                result = plugin.analyze(response, content, headers)
                if result:
                    technologies[plugin.name] = result
            except Exception as e:
                self.log(f"Plugin {plugin.name} failed: {e}", "WARNING")
        
        return technologies
    
    def aggressive_scan(self, base_url: str) -> Dict[str, Any]:
        """Perform aggressive scanning"""
        aggressive_results = {}
        common_paths = [
            '/admin', '/wp-admin', '/administrator', '/login',
            '/admin/login', '/cpanel', '/phpmyadmin', '/webmail',
            '/wp-login.php', '/user/login', '/robots.txt',
            '/sitemap.xml', '/.git/config', '/.env'
        ]
        
        def check_path(path):
            test_url = urljoin(base_url, path)
            try:
                response = self.session.head(test_url, timeout=5)
                if response.status_code < 400:
                    return path, {
                        'status': response.status_code,
                        'url': test_url
                    }
            except:
                pass
            return path, None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {
                executor.submit(check_path, path): path for path in common_paths
            }
            
            for future in as_completed(future_to_path):
                path, result = future.result()
                if result:
                    aggressive_results[path] = result
        
        return aggressive_results
    
    def dns_scan(self, domain: str) -> Dict[str, Any]:
        """Perform DNS reconnaissance"""
        dns_info = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        try:
            parsed = urlparse(domain)
            domain_name = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain_name, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except:
                    continue
                    
        except Exception as e:
            self.log(f"DNS scan failed: {e}", "WARNING")
        
        return dns_info
    
    def scan(self, target: str) -> ScanResult:
        """Main scanning function"""
        self.log(f"Starting scan for: {target}", "INFO")
        
        normalized_url = self.normalize_url(target)
        self.log(f"Normalized URL: {normalized_url}", "INFO")
        
        # Get initial response
        response = self.get_response(normalized_url)
        if not response:
            raise Exception(f"Failed to connect to {normalized_url}")
        
        self.log(f"Response status: {response.status_code}", "SUCCESS")
        
        # Run plugins for technology detection
        technologies = self.run_plugins(response)
        self.log(f"Detected {len(technologies)} technologies", "SUCCESS")
        
        # Extract headers information
        headers_info = self.extract_headers_info(response)
        
        # Calculate content hashes
        hashes = self.calculate_hashes(response.text)
        
        # Aggressive scanning based on level
        aggressive_findings = {}
        if self.aggression_level >= 2:
            self.log("Starting aggressive scan...", "INFO")
            aggressive_findings = self.aggressive_scan(normalized_url)
        
        # DNS scan for additional reconnaissance
        dns_info = {}
        if self.aggression_level >= 3:
            self.log("Starting DNS reconnaissance...", "INFO")
            dns_info = self.dns_scan(target)
        
        # Compile meta information
        meta_info = {
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds(),
            'final_url': response.url,
            'dns_info': dns_info,
            'redirects': len(response.history) if hasattr(response, 'history') else 0
        }
        
        return ScanResult(
            target=target,
            status_code=response.status_code,
            technologies=technologies,
            headers=headers_info,
            hashes=hashes,
            meta_info=meta_info,
            aggressive_findings=aggressive_findings,
            timestamp=time.time()
        )

def print_results(results: ScanResult, output_format: str = 'text', show_all: bool = False, aggression_level: int = 1):
    """Print results in specified format"""
    if output_format == 'json':
        print(json.dumps({
            'target': results.target,
            'status_code': results.status_code,
            'technologies': results.technologies,
            'headers': results.headers,
            'hashes': results.hashes,
            'meta_info': results.meta_info,
            'aggressive_findings': results.aggressive_findings,
            'timestamp': results.timestamp
        }, indent=2))
    else:
        print(f"\n\033[1;36mAdvanced Scan Results for {results.target}\033[0m")
        print("\033[1;36m" + "=" * 60 + "\033[0m")
        
        # Basic info
        print(f"\033[1;32mBasic Information:\033[0m")
        print(f"  Status Code: {results.status_code}")
        print(f"  Final URL: {results.meta_info['final_url']}")
        print(f"  Content Length: {results.meta_info['content_length']} bytes")
        print(f"  Response Time: {results.meta_info['response_time']:.2f}s")
        
        # Technologies
        if results.technologies:
            print(f"\n\033[1;32mTechnologies Detected:\033[0m")
            for tech, info in results.technologies.items():
                if isinstance(info, dict):
                    confidence = info.get('confidence', 'N/A')
                    version = info.get('version', '')
                    version_str = f" (v{version})" if version else ""
                    print(f"  \033[1;33m{tech}\033[0m{version_str} - Confidence: {confidence}%")
                else:
                    print(f"  \033[1;33m{tech}\033[0m")
        
        # Headers
        if results.headers and (show_all or len(results.headers) > 0):
            print(f"\n\033[1;32mInteresting Headers:\033[0m")
            for header, value in results.headers.items():
                print(f"  {header}: {value}")
        
        # Aggressive findings
        if results.aggressive_findings and (show_all or aggression_level >= 2):
            print(f"\n\033[1;32mAggressive Findings:\033[0m")
            for path, info in results.aggressive_findings.items():
                if isinstance(info, dict):
                    print(f"  {path} - Status: {info.get('status', 'N/A')}")
                else:
                    print(f"  {path} - {info}")
        
        # DNS info
        if results.meta_info.get('dns_info') and show_all:
            print(f"\n\033[1;32mDNS Information:\033[0m")
            for record_type, values in results.meta_info['dns_info'].items():
                print(f"  {record_type}: {', '.join(values)}")

def main():
    banner = """
\033[1;36m
University of Kali Linux
Advanced Website Fingerprinting Tool
\033[0m
    """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description='Advanced - Website Fingerprinting Tool')
    parser.add_argument('target', nargs='+', help='Target URL(s) or domain(s) to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-a', '--aggression', type=int, choices=[1, 2, 3], default=1,
                       help='Aggression level (1: Passive, 2: Aggressive, 3: Heavy)')
    parser.add_argument('-o', '--output-format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for aggressive scanning')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--show-all', action='store_true', help='Show all information including DNS data')
    
    args = parser.parse_args()
    
    scanner = AdvancedScanner(
        verbose=args.verbose,
        aggression_level=args.aggression,
        max_threads=args.threads,
        timeout=args.timeout
    )
    
    all_results = []
    
    for target in args.target:
        try:
            result = scanner.scan(target)
            all_results.append(result)
            print_results(result, args.output_format, args.show_all, args.aggression)
            
            if len(args.target) > 1:
                print("\n" + "="*60 + "\n")
                
        except KeyboardInterrupt:
            print("\n\033[1;31mScan interrupted by user\033[0m")
            sys.exit(1)
        except Exception as e:
            print(f"\033[1;31mError scanning {target}: {e}\033[0m")
            continue
    
    if args.output_format == 'json' and len(all_results) > 1:
        print(json.dumps([{
            'target': r.target,
            'status_code': r.status_code,
            'technologies': r.technologies
        } for r in all_results], indent=2))

if __name__ == "__main__":
    main()
