#!/usr/bin/env python3
"""
Advanced Python Implementation - Website Fingerprinting Tool
Enhanced version with superior capabilities compared to WhatWeb.
This tool is designed for ethical use only, such as security research, penetration testing with permission, or educational purposes.
Unauthorized scanning or use against websites without explicit permission may violate laws and terms of service.
Always obtain proper authorization before using this tool.
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
import os
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, quote
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import base64
import zlib
import brotli
import sqlite3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import whois
import ssl as ssl_module
from bs4 import BeautifulSoup
import yaml
import csv
import xml.dom.minidom

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class ScanResult:
    """Data class to store comprehensive scan results"""
    target: str
    status_code: int
    technologies: Dict[str, Any]
    headers: Dict[str, str]
    security_headers: Dict[str, Any]
    cookies: List[Dict[str, Any]]
    hashes: Dict[str, str]
    meta_info: Dict[str, Any]
    aggressive_findings: Dict[str, Any]
    dns_info: Dict[str, Any]
    ssl_info: Dict[str, Any]
    whois_info: Dict[str, Any]
    network_info: Dict[str, Any]
    content_analysis: Dict[str, Any]
    timestamp: float
    scan_duration: float

class PluginBase:
    """Base class for all detection plugins with enhanced capabilities"""
    def __init__(self):
        self.name = "Base Plugin"
        self.confidence = 0
        self.patterns = []
        self.category = "unknown"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def passive_detect(self, response: requests.Response) -> Optional[Dict[str, Any]]:
        return None

    def aggressive_detect(self, base_url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        return None

# Enhanced CMS Detections
class WordPressPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "WordPress"
        self.confidence = 90
        self.category = "CMS"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        wp_indicators = [
            (r'wp-content|wp-includes', 20),
            (r'wordpress', 15),
            (r'/wp-json/', 25),
            (r'wp-embed.min.js', 15),
            (r'wp-admin', 10),
            (r'xmlrpc.php', 20),
            (r'wp-', 5)
        ]
        score = 0
        version = None
        plugins = []
        themes = []
        content_lower = content.lower()
        for pattern, points in wp_indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        # Enhanced version detection
        version_patterns = [
            r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"',
            r'wp-includes/js/wp-embed.min.js\?ver=(\d+\.\d+(?:\.\d+)?)',
            r'wp-includes/css/dist/block-library/style.min.css\?ver=(\d+\.\d+(?:\.\d+)?)',
            r'wp-includes/js/jquery/jquery-migrate.min.js\?ver=(\d+\.\d+(?:\.\d+)?)',
            r'wordpress (\d+\.\d+(?:\.\d+)?)'
        ]
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                score += 30
                break
        # Plugin detection
        plugin_patterns = [
            (r'wp-content/plugins/([^/"\']+)/', 15),
            (r'plugins/([^/"\']+)/', 10)
        ]
        for pattern, confidence in plugin_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in plugins and len(match) > 1:
                    plugins.append(match)
                    score += confidence
        # Theme detection
        theme_patterns = [
            (r'wp-content/themes/([^/"\']+)/', 20),
            (r'themes/([^/"\']+)/', 15)
        ]
        for pattern, confidence in theme_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in themes and len(match) > 1:
                    themes.append(match)
                    score += confidence
        if score >= 30:
            result = {
                'confidence': min(score, 100),
                'category': self.category
            }
            if version:
                result['version'] = version
            if plugins:
                result['plugins'] = list(set(plugins))[:10]  # Limit to top 10
            if themes:
                result['themes'] = list(set(themes))[:5]  # Limit to top 5
            return result
        return None

    def aggressive_detect(self, base_url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """Aggressive WordPress detection"""
        wp_paths = [
            '/wp-login.php',
            '/wp-admin/',
            '/readme.html',
            '/wp-config.php',
            '/xmlrpc.php',
            '/wp-json/wp/v2/users'
        ]
        findings = {}
        for path in wp_paths:
            try:
                url = urljoin(base_url, path)
                response = session.head(url, timeout=5, allow_redirects=False)
                if response.status_code < 400:
                    findings[path] = {
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type', '')
                    }
            except:
                continue
        if findings:
            return {'WordPress': {'aggressive_findings': findings}}
        return None

class JoomlaPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Joomla"
        self.category = "CMS"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        joomla_indicators = [
            (r'joomla', 25),
            (r'/media/jui/', 30),
            (r'/media/system/', 30),
            (r'com_content', 20),
            (r'index.php?option=', 15),
            (r'Joomla!', 35),
            (r'joomla.org', 25)
        ]
        score = 0
        version = None
        content_lower = content.lower()
        for pattern, points in joomla_indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        # Version detection
        version_patterns = [
            r'Joomla! (\d+\.\d+(?:\.\d+)?)',
            r'joomla.org/cms/release-(\d+-\d+-\d+)'
        ]
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1).replace('-', '.') if '-' in match.group(1) else match.group(1)
                score += 25
                break
        if score >= 40:
            result = {
                'confidence': min(score, 100),
                'category': self.category
            }
            if version:
                result['version'] = version
            return result
        return None

    def aggressive_detect(self, base_url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """Aggressive Joomla detection"""
        joomla_paths = [
            '/administrator/',
            '/language/en-GB/en-GB.xml',
            '/htaccess.txt',
            '/robots.txt',
            '/administrator/index.php'
        ]
        findings = {}
        for path in joomla_paths:
            try:
                url = urljoin(base_url, path)
                response = session.head(url, timeout=5, allow_redirects=False)
                if response.status_code < 400:
                    findings[path] = {
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type', '')
                    }
            except:
                continue
        if findings:
            return {'Joomla': {'aggressive_findings': findings}}
        return None

class DrupalPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Drupal"
        self.category = "CMS"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
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
            result = {
                'confidence': min(score, 100),
                'category': self.category
            }
            if version:
                result['version'] = version
            return result
        return None

    def aggressive_detect(self, base_url: str, session: requests.Session) -> Optional[Dict[str, Any]]:
        """Aggressive Drupal detection"""
        drupal_paths = [
            '/CHANGELOG.txt',
            '/sites/default/settings.php',
            '/user/login',
            '/core/INSTALL.txt'
        ]
        findings = {}
        for path in drupal_paths:
            try:
                url = urljoin(base_url, path)
                response = session.head(url, timeout=5, allow_redirects=False)
                if response.status_code < 400:
                    findings[path] = {
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type', '')
                    }
            except:
                continue
        if findings:
            return {'Drupal': {'aggressive_findings': findings}}
        return None

class PHPPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "PHP"
        self.category = "Programming Language"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
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
            return {
                'confidence': min(score, 100),
                'category': self.category
            }
        return None

class ServerPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Web Server"
        self.category = "Server"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
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
                    'version': self.extract_version(server_header),
                    'category': self.category
                }
        return None

    def extract_version(self, server_string: str) -> Optional[str]:
        version_match = re.search(r'/(\d+\.\d+(?:\.\d+)?)', server_string)
        return version_match.group(1) if version_match else None

class JavaScriptFrameworkPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "JavaScript Framework"
        self.category = "JavaScript"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
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
                results[framework] = {
                    'confidence': score,
                    'category': self.category
                }
        return results if results else None

class NodeJSPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Node.js"
        self.category = "Runtime"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'X-Powered-By: Express', 90),
            (r'X-Powered-By: Node.js', 80),
            (r'X-Powered-By: Koa', 70)
        ]
        score = 0
        # Check headers
        x_powered_by = headers.get('x-powered-by', '').lower()
        if 'express' in x_powered_by or 'node.js' in x_powered_by or 'koa' in x_powered_by:
            score += 80
        # Check content
        content_lower = content.lower()
        for pattern, points in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        if score >= 40:
            return {
                'confidence': min(score, 100),
                'category': self.category
            }
        return None

class PythonPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Python"
        self.category = "Programming Language"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'X-Powered-By: Flask', 90),
            (r'X-Powered-By: Django', 80),
            (r'X-Powered-By: Bottle', 70)
        ]
        score = 0
        # Check headers
        x_powered_by = headers.get('x-powered-by', '').lower()
        if 'flask' in x_powered_by or 'django' in x_powered_by or 'bottle' in x_powered_by:
            score += 80
        # Check content
        content_lower = content.lower()
        for pattern, points in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score += points
        if score >= 40:
            return {
                'confidence': min(score, 100),
                'category': self.category
            }
        return None

class ReactPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "React"
        self.category = "JavaScript Framework"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'react|react-dom', 40),
            (r'__reactInternalInstance', 90),
            (r'React.createElement', 70),
            (r'react-root', 60),
            (r'react.production.min.js', 80)
        ]
        score = 0
        version = None
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        # Version detection
        version_patterns = [
            r'react@(\d+\.\d+\.\d+)',
            r'react/(\d+\.\d+\.\d+)',
            r'react.production.min.js\?v=(\d+\.\d+\.\d+)'
        ]
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                score += 20
                break
        if score >= 50:
            result = {
                'confidence': score,
                'category': self.category
            }
            if version:
                result['version'] = version
            return result
        return None

class SecurityHeadersPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Security Headers"
        self.category = "Security"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        security_headers = {
            'Content-Security-Policy': {'score': 20, 'present': False},
            'Strict-Transport-Security': {'score': 25, 'present': False},
            'X-Content-Type-Options': {'score': 15, 'present': False},
            'X-Frame-Options': {'score': 15, 'present': False},
            'X-XSS-Protection': {'score': 10, 'present': False},
            'Referrer-Policy': {'score': 10, 'present': False},
            'Feature-Policy': {'score': 10, 'present': False},
            'Permissions-Policy': {'score': 10, 'present': False}
        }
        score = 0
        findings = {}
        for header, info in security_headers.items():
            if header in response.headers:
                info['present'] = True
                score += info['score']
                findings[header] = {
                    'value': response.headers[header],
                    'score': info['score']
                }
        if findings:
            return {
                'confidence': min(score, 100),
                'headers': findings,
                'category': self.category,
                'security_score': score
            }
        return None

class DatabasePlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Database"
        self.category = "Database"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'mysql', 30),
            (r'postgresql', 30),
            (r'mongodb', 25),
            (r'sqlite', 25),
            (r'microsoft sql server', 30),
            (r'oracle', 30),
            (r'redis', 25)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        # Check connection strings in content
        connection_patterns = [
            (r'mysql_connect', 40),
            (r'pg_connect', 40),
            (r'mongodb://', 50),
            (r'jdbc:', 45)
        ]
        for pattern, confidence in connection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 30:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class CDNPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "CDN"
        self.category = "Infrastructure"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        cdn_indicators = {
            'Cloudflare': [
                (r'cloudflare', 80),
                (r'__cfduid', 90),
                (r'cf-ray', 85)
            ],
            'Akamai': [
                (r'akamai', 80),
                (r'X-Akamai', 85)
            ],
            'AWS CloudFront': [
                (r'cloudfront', 80),
                (r'X-Amz-Cf-', 85)
            ],
            'Fastly': [
                (r'fastly', 80),
                (r'X-Fastly', 85)
            ],
            'Google Cloud CDN': [
                (r'google', 75),
                (r'GCDN', 80)
            ]
        }
        detected_cdns = {}
        headers_lower = {k.lower(): v for k, v in headers.items()}
        content_lower = content.lower()
        for cdn, patterns in cdn_indicators.items():
            cdn_score = 0
            for pattern, confidence in patterns:
                # Check headers
                for header_name, header_value in headers_lower.items():
                    if re.search(pattern, f"{header_name} {header_value}", re.IGNORECASE):
                        cdn_score = max(cdn_score, confidence)
                # Check content
                if re.search(pattern, content_lower, re.IGNORECASE):
                    cdn_score = max(cdn_score, confidence)
            if cdn_score >= 70:
                detected_cdns[cdn] = {
                    'confidence': cdn_score,
                    'category': self.category
                }
        return detected_cdns if detected_cdns else None

class AnalyticsPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Analytics"
        self.category = "Tracking"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        analytics_services = {
            'Google Analytics': [
                (r'google-analytics.com', 90),
                (r'ga.js', 85),
                (r'analytics.js', 85),
                (r'gtag.js', 85)
            ],
            'Google Tag Manager': [
                (r'googletagmanager.com', 90),
                (r'gtm.js', 85)
            ],
            'Facebook Pixel': [
                (r'facebook.com/tr', 90),
                (r'fbq\(', 80)
            ],
            'Hotjar': [
                (r'hotjar.com', 90),
                (r'hj=', 85)
            ],
            'Matomo': [
                (r'matomo', 85),
                (r'piwik.js', 80)
            ]
        }
        detected_analytics = {}
        content_lower = content.lower()
        for service, patterns in analytics_services.items():
            service_score = 0
            for pattern, confidence in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    service_score = max(service_score, confidence)
            if service_score >= 70:
                detected_analytics[service] = {
                    'confidence': service_score,
                    'category': self.category
                }
        return detected_analytics if detected_analytics else None

# Additional plugins for completeness
class LaravelPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Laravel"
        self.category = "PHP Framework"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'laravel', 70),
            (r'csrf-token', 60),
            (r'XSRF-TOKEN', 65)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class RubyOnRailsPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Ruby on Rails"
        self.category = "Web Framework"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'rails', 70),
            (r'ruby', 60),
            (r'csrf-param', 65)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class DotNetPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "ASP.NET"
        self.category = "Web Framework"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'asp.net', 70),
            (r'__VIEWSTATE', 80),
            (r'__EVENTVALIDATION', 75)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class JavaPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Java"
        self.category = "Programming Language"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'\bjava\b', 60),
            (r'jsp', 70),
            (r'servlet', 65),
            (r'jsessionid', 75)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class GraphQLPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "GraphQL"
        self.category = "API"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'graphql', 70),
            (r'__schema', 80),
            (r'query{', 75)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class DockerPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Docker"
        self.category = "Container"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'docker', 70),
            (r'Docker-Content-Digest', 80)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class KubernetesPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Kubernetes"
        self.category = "Orchestration"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'kubernetes', 70),
            (r'k8s', 65)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 60:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

# Additional plugins to surpass WhatWeb
class ShopifyPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Shopify"
        self.category = "Ecommerce"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'shopify', 80),
            (r'cdn.shopify.com', 90),
            (r'shopify.theme', 85)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 70:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class MagentoPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Magento"
        self.category = "Ecommerce"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'\bmagento\b', 80),
            (r'\bmage/', 85),
            (r'skin/frontend', 90)
        ]
        score = 0
        content_lower = content.lower()
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
        if score >= 70:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class AWSPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "AWS"
        self.category = "Cloud"

    def analyze(self, response: requests.Response, content: str, headers: Dict[str, str],
                soup: BeautifulSoup = None) -> Optional[Dict[str, Any]]:
        indicators = [
            (r'amazonaws.com', 80),
            (r'X-Amz-', 85)
        ]
        score = 0
        content_lower = content.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for pattern, confidence in indicators:
            if re.search(pattern, content_lower, re.IGNORECASE):
                score = max(score, confidence)
            for h, v in headers_lower.items():
                if re.search(pattern, h + v, re.IGNORECASE):
                    score = max(score, confidence)
        if score >= 70:
            return {
                'confidence': score,
                'category': self.category
            }
        return None

class AdvancedScanner:
    def __init__(self, verbose=False, aggression_level=1, max_threads=20, timeout=15,
                 user_agent=None, proxy=None, cookies=None, headers=None, follow_redirects=True):
        self.verbose = verbose
        self.aggression_level = aggression_level
        self.max_threads = max_threads
        self.timeout = timeout
        self.plugins = self._load_plugins()
        self.session = self._create_session(user_agent, proxy, cookies, headers, follow_redirects)
        self.scan_stats = {
            'total_requests': 0,
            'failed_requests': 0,
            'start_time': None,
            'end_time': None
        }

    def _load_plugins(self) -> List[PluginBase]:
        """Load all enhanced detection plugins"""
        return [
            WordPressPlugin(),
            JoomlaPlugin(),
            DrupalPlugin(),
            PHPPlugin(),
            ServerPlugin(),
            JavaScriptFrameworkPlugin(),
            NodeJSPlugin(),
            PythonPlugin(),
            ReactPlugin(),
            SecurityHeadersPlugin(),
            DatabasePlugin(),
            CDNPlugin(),
            AnalyticsPlugin(),
            LaravelPlugin(),
            RubyOnRailsPlugin(),
            DotNetPlugin(),
            JavaPlugin(),
            GraphQLPlugin(),
            DockerPlugin(),
            KubernetesPlugin(),
            ShopifyPlugin(),
            MagentoPlugin(),
            AWSPlugin()
        ]

    def _create_session(self, user_agent: str = None, proxy: str = None,
                        cookies: str = None, custom_headers: Dict = None,
                        follow_redirects: bool = True) -> requests.Session:
        """Create configured requests session with enhanced options"""
        session = requests.Session()
        # Default headers
        headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (compatible; AdvancedFingerprinter/3.0)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        # Add custom headers
        if custom_headers:
            headers.update(custom_headers)
        session.headers.update(headers)
        # Configure session
        session.verify = False
        session.timeout = self.timeout
        session.allow_redirects = follow_redirects
        # Set proxy
        if proxy:
            session.proxies = {
                'http': proxy,
                'https': proxy
            }
        # Set cookies
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    session.cookies.set(name.strip(), value.strip())
        return session

    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with colors and levels"""
        if self.verbose or level in ["ERROR", "WARNING"]:
            colors = {
                "INFO": "\033[94m",
                "WARNING": "\033[93m",
                "ERROR": "\033[91m",
                "SUCCESS": "\033[92m",
                "DEBUG": "\033[95m"
            }
            color = colors.get(level, "\033[0m")
            timestamp = time.strftime("%H:%M:%S")
            print(f"{color}[{timestamp}][{level}] {message}\033[0m")

    def normalize_url(self, url: str) -> str:
        """Enhanced URL normalization"""
        if not url.startswith(('http://', 'https://')):
            # Try both HTTP and HTTPS
            for scheme in ['https://', 'http://']:
                try:
                    test_url = scheme + url
                    response = self.session.head(test_url, timeout=5, allow_redirects=True)
                    return response.url
                except:
                    continue
            return 'https://' + url  # Default to HTTPS
        return url

    def get_response(self, url: str) -> Optional[requests.Response]:
        """Get HTTP response with comprehensive error handling"""
        try:
            response = self.session.get(
                url,
                allow_redirects=True,
                timeout=self.timeout
            )
            self.scan_stats['total_requests'] += 1
            return response
        except requests.exceptions.RequestException as e:
            self.scan_stats['failed_requests'] += 1
            self.log(f"Request failed for {url}: {e}", "ERROR")
            return None

    def extract_headers_info(self, response: requests.Response) -> Dict[str, Any]:
        """Extract and analyze HTTP headers"""
        headers_info = {}
        interesting_headers = [
            'server', 'x-powered-by', 'content-type', 'set-cookie',
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy',
            'cache-control', 'expires', 'etag', 'last-modified'
        ]
        for header in interesting_headers:
            if header in response.headers:
                headers_info[header] = response.headers[header]
        return headers_info

    def extract_cookies(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Extract and analyze cookies"""
        cookies = []
        for cookie in response.cookies:
            cookies.append({
                'name': cookie.name,
                'value': cookie.value,
                'secure': cookie.secure,
                'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                'same_site': cookie.get_nonstandard_attr('SameSite')
            })
        return cookies

    def calculate_hashes(self, content: str) -> Dict[str, str]:
        """Calculate various hashes of the content"""
        return {
            'md5': hashlib.md5(content.encode()).hexdigest(),
            'sha1': hashlib.sha1(content.encode()).hexdigest(),
            'sha256': hashlib.sha256(content.encode()).hexdigest()
        }

    def extract_meta_info(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract meta information from HTML"""
        meta_info = {}
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            meta_info['generator'] = generator.get('content')
        description = soup.find('meta', attrs={'name': 'description'})
        if description:
            meta_info['description'] = description.get('content')[:200]
        return meta_info

    def get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Gather DNS information"""
        dns_info = {}
        try:
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [r.to_text() for r in answers]
                except:
                    pass
        except Exception as e:
            self.log(f"DNS lookup failed: {e}", "WARNING")
        return dns_info

    def get_ssl_info(self, url: str) -> Dict[str, Any]:
        """Gather SSL certificate information"""
        if not url.startswith('https://'):
            return {}
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    return {
                        'issuer': cert.issuer.rfc4514_string(),
                        'subject': cert.subject.rfc4514_string(),
                        'not_before': str(cert.not_valid_before_utc),
                        'not_after': str(cert.not_valid_after_utc),
                        'serial_number': cert.serial_number,
                        'version': cert.version.name
                    }
        except Exception as e:
            self.log(f"SSL info failed: {e}", "WARNING")
            return {}

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Gather WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            self.log(f"WHOIS failed: {e}", "WARNING")
            return {}

    def get_network_info(self, domain: str) -> Dict[str, Any]:
        """Gather basic network information (ethical: no port scanning)"""
        try:
            ip = socket.gethostbyname(domain)
            return {'ip_address': ip}
        except Exception as e:
            self.log(f"Network info failed: {e}", "WARNING")
            return {}

    def analyze_content(self, content: str, soup: BeautifulSoup) -> Dict[str, Any]:
        """Perform content analysis"""
        analysis = {
            'word_count': len(content.split()),
            'link_count': len(soup.find_all('a')),
            'script_count': len(soup.find_all('script')),
            'form_count': len(soup.find_all('form'))
        }
        return analysis

    def run_plugins(self, response: requests.Response, soup: BeautifulSoup) -> Dict[str, Any]:
        """Run all detection plugins"""
        technologies = {}
        content = response.text
        headers = {k.lower(): v for k, v in response.headers.items()}
        for plugin in self.plugins:
            try:
                result = plugin.analyze(response, content, headers, soup)
                if result:
                    if isinstance(result, dict) and not 'category' in result:  # Multi-result plugins
                        for key, info in result.items():
                            technologies[key] = info
                    else:
                        technologies[plugin.name] = result
            except Exception as e:
                self.log(f"Plugin {plugin.name} failed: {e}", "WARNING")
        return technologies

    def aggressive_scan(self, base_url: str) -> Dict[str, Any]:
        """Perform aggressive scanning based on aggression level"""
        aggressive_results = {}
        if self.aggression_level == 0:
            return aggressive_results

        # Common paths for general probing (level 1)
        common_paths = [
            '/admin', '/wp-admin', '/administrator', '/login', '/admin/login',
            '/dashboard', '/cpanel', '/phpmyadmin', '/webmail', '/robots.txt',
            '/sitemap.xml', '/.well-known/', '/humans.txt', '/.git/', '/.env'
        ]

        if self.aggression_level >= 1:
            findings = {}
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {}
                for path in common_paths:
                    url = urljoin(base_url, path)
                    futures[executor.submit(self.session.head, url, timeout=5, allow_redirects=False)] = path
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        response = future.result()
                        if response.status_code < 400:
                            findings[path] = {
                                'status': response.status_code,
                                'content_type': response.headers.get('content-type', '')
                            }
                    except:
                        pass
            if findings:
                aggressive_results['common_paths'] = findings

        # Plugin-specific aggressive detection (level 2+)
        if self.aggression_level >= 2:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(plugin.aggressive_detect, base_url, self.session) for plugin in self.plugins]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        aggressive_results.update(result)

        return aggressive_results

    def scan(self, target: str) -> ScanResult:
        """Perform the full scan"""
        self.scan_stats['start_time'] = time.time()
        self.log(f"Starting scan on {target}", "INFO")
        url = self.normalize_url(target)
        response = self.get_response(url)
        if not response:
            self.log(f"Scan failed for {target}", "ERROR")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')
        parsed = urlparse(url)
        domain = parsed.netloc

        technologies = self.run_plugins(response, soup)
        headers_info = self.extract_headers_info(response)
        cookies = self.extract_cookies(response)
        hashes = self.calculate_hashes(response.text)
        meta_info = self.extract_meta_info(soup)
        dns_info = self.get_dns_info(domain)
        ssl_info = self.get_ssl_info(url)
        whois_info = self.get_whois_info(domain)
        network_info = self.get_network_info(domain)
        content_analysis = self.analyze_content(response.text, soup)
        aggressive_findings = self.aggressive_scan(url) if self.aggression_level > 0 else {}

        # Security headers are already in technologies, but extract separately if needed
        security_headers = technologies.get('Security Headers', {}).get('headers', {})

        result = ScanResult(
            target=url,
            status_code=response.status_code,
            technologies=technologies,
            headers=headers_info,
            security_headers=security_headers,
            cookies=cookies,
            hashes=hashes,
            meta_info=meta_info,
            aggressive_findings=aggressive_findings,
            dns_info=dns_info,
            ssl_info=ssl_info,
            whois_info=whois_info,
            network_info=network_info,
            content_analysis=content_analysis,
            timestamp=time.time(),
            scan_duration=0
        )
        self.scan_stats['end_time'] = time.time()
        result.scan_duration = self.scan_stats['end_time'] - self.scan_stats['start_time']
        self.log(f"Scan completed in {result.scan_duration:.2f} seconds", "SUCCESS")
        return result

def output_result(result: ScanResult, format: str, output_file: Optional[str] = None):
    """Output the result in the specified format"""
    data = asdict(result)
    if format == 'json':
        output_str = json.dumps(data, indent=4)
    elif format == 'yaml':
        output_str = yaml.safe_dump(data, default_flow_style=False)
    elif format == 'xml':
        root = ET.Element('scan_result')
        def dict_to_xml(d, parent):
            for k, v in d.items():
                child = ET.SubElement(parent, k)
                if isinstance(v, dict):
                    dict_to_xml(v, child)
                elif isinstance(v, list):
                    for item in v:
                        item_elem = ET.SubElement(child, 'item')
                        if isinstance(item, dict):
                            dict_to_xml(item, item_elem)
                        else:
                            item_elem.text = str(item)
                else:
                    child.text = str(v)
        dict_to_xml(data, root)
        dom = xml.dom.minidom.parseString(ET.tostring(root))
        output_str = dom.toprettyxml(indent='  ')
    elif format == 'csv':
        # Flatten for CSV
        flat_data = []
        def flatten(d, prefix=''):
            for k, v in d.items():
                if isinstance(v, dict):
                    flatten(v, prefix + k + '_')
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        if isinstance(item, dict):
                            flatten(item, prefix + k + f'_{i}_')
                        else:
                            flat_data.append((prefix + k + f'_{i}', str(item)))
                else:
                    flat_data.append((prefix + k, str(v)))
        flatten(data)
        output_str = 'key,value\n' + '\n'.join(f'{k},{v}' for k, v in flat_data)
    else:  # text
        output_str = f"Scan Result for {result.target}\n"
        output_str += "=" * 50 + "\n"
        output_str += f"Status Code: {result.status_code}\n"
        output_str += f"Technologies: {json.dumps(result.technologies, indent=2)}\n"
        output_str += f"Headers: {json.dumps(result.headers, indent=2)}\n"
        output_str += f"Security Headers: {json.dumps(result.security_headers, indent=2)}\n"
        output_str += f"Cookies: {json.dumps(result.cookies, indent=2)}\n"
        output_str += f"Hashes: {json.dumps(result.hashes, indent=2)}\n"
        output_str += f"Meta Info: {json.dumps(result.meta_info, indent=2)}\n"
        output_str += f"Aggressive Findings: {json.dumps(result.aggressive_findings, indent=2)}\n"
        output_str += f"DNS Info: {json.dumps(result.dns_info, indent=2)}\n"
        output_str += f"SSL Info: {json.dumps(result.ssl_info, indent=2)}\n"
        output_str += f"WHOIS Info: {json.dumps(result.whois_info, indent=2)}\n"
        output_str += f"Network Info: {json.dumps(result.network_info, indent=2)}\n"
        output_str += f"Content Analysis: {json.dumps(result.content_analysis, indent=2)}\n"
        output_str += f"Timestamp: {time.ctime(result.timestamp)}\n"
        output_str += f"Scan Duration: {result.scan_duration:.2f} seconds\n"

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output_str)
    else:
        print(output_str)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Website Fingerprinting Tool - Ethical Use Only",
        epilog="This tool is for ethical purposes only. Ensure you have permission to scan the target."
    )
    parser.add_argument('target', help="Target URL or file containing list of URLs")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('-a', '--aggression', type=int, default=1, choices=[0,1,2,3], help="Aggression level (0-3, higher is more intrusive)")
    parser.add_argument('-t', '--threads', type=int, default=20, help="Maximum threads")
    parser.add_argument('--timeout', type=int, default=15, help="Request timeout in seconds")
    parser.add_argument('-u', '--user-agent', help="Custom User-Agent")
    parser.add_argument('-p', '--proxy', help="Proxy URL (e.g., http://proxy:port)")
    parser.add_argument('-c', '--cookies', help="Cookies string (e.g., 'name=value; name2=value2')")
    parser.add_argument('-H', '--headers', nargs='*', help="Custom headers (e.g., 'Header: value')")
    parser.add_argument('-r', '--no-redirects', action='store_false', help="Do not follow redirects")
    parser.add_argument('-f', '--format', default='text', choices=['text', 'json', 'yaml', 'xml', 'csv'], help="Output format")
    parser.add_argument('-o', '--output', help="Output file")
    args = parser.parse_args()

    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                key, value = h.split(':', 1)
                custom_headers[key.strip()] = value.strip()

    scanner = AdvancedScanner(
        verbose=args.verbose,
        aggression_level=args.aggression,
        max_threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        cookies=args.cookies,
        headers=custom_headers,
        follow_redirects=args.no_redirects
    )

    targets = []
    if os.path.isfile(args.target):
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.target]

    for target in targets:
        result = scanner.scan(target)
        if result:
            output_result(result, args.format, args.output)

if __name__ == "__main__":
    main()
