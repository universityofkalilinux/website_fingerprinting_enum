## Program Description

This is an **Advanced Website Fingerprinting Tool** written in Python that performs comprehensive technology detection and reconnaissance on websites. It analyzes web applications to identify underlying technologies, frameworks, servers, and security configurations through multiple detection methods.

### Key Features:
- **Technology Detection**: Identifies CMS platforms (WordPress, Joomla, Drupal), web servers, PHP, and JavaScript frameworks
- **Multi-level Scanning**: Offers passive, aggressive, and heavy scanning modes
- **DNS Reconnaissance**: Gathers DNS record information
- **Parallel Processing**: Uses threading for efficient scanning
- **Multiple Output Formats**: Text and JSON output options
- **Comprehensive Analysis**: Examines headers, content patterns, and file structures

---

## Command-Line Usage Guide

### Basic Syntax:
```bash
python3 website_fingerprinting_enum.py [OPTIONS] TARGET [TARGET2 ...]
```

### Command Options:

#### 1. **Target Specification**
**Command:** `TARGET` (required)
**Description:** Specify one or more URLs or domains to scan
**Examples:**
```bash
# Single target
python3 website_fingerprinting_enum.py example.com

# Multiple targets
python3 website_fingerprinting_enum.py example.com google.com github.com

# Full URL with protocol
python3 website_fingerprinting_enum.py https://wordpress.org
```

#### 2. **Verbose Output**
**Command:** `-v` or `--verbose`
**Description:** Enable detailed logging during the scan process
**Examples:**
```bash
# With verbose output
python3 website_fingerprinting_enum.py -v example.com

# Multiple targets with verbose
python3 website_fingerprinting_enum.py -v site1.com site2.org
```

#### 3. **Aggression Level**
**Command:** `-a` or `--aggression` [1|2|3]
**Description:** Set the scanning intensity level
- **Level 1 (Passive)**: Basic technology detection only
- **Level 2 (Aggressive)**: Adds path enumeration and directory discovery
- **Level 3 (Heavy)**: Includes DNS reconnaissance and full enumeration

**Examples:**
```bash
# Passive scan (default)
python3 website_fingerprinting_enum.py -a 1 example.com

# Aggressive scan with path discovery
python3 website_fingerprinting_enum.py -a 2 example.com

# Heavy scan with DNS reconnaissance
python3 website_fingerprinting_enum.py -a 3 example.com
```

#### 4. **Output Format**
**Command:** `-o` or `--output-format` [text|json]
**Description:** Choose the output format for results
**Examples:**
```bash
# Text output (default, human-readable)
python3 website_fingerprinting_enum.py -o text example.com

# JSON output (machine-readable)
python3 website_fingerprinting_enum.py -o json example.com

# JSON output for multiple targets
python3 website_fingerprinting_enum.py -o json site1.com site2.com
```

#### 5. **Thread Management**
**Command:** `-t` or `--threads` NUMBER
**Description:** Set the number of concurrent threads for aggressive scanning
**Examples:**
```bash
# Default threads (10)
python3 website_fingerprinting_enum.py -a 2 example.com

# Increased threads for faster scanning
python3 website_fingerprinting_enum.py -a 2 -t 20 example.com

# Conservative threading
python3 website_fingerprinting_enum.py -a 2 -t 5 example.com
```

#### 6. **Timeout Configuration**
**Command:** `--timeout` SECONDS
**Description:** Set request timeout in seconds
**Examples:**
```bash
# Default timeout (10 seconds)
python3 website_fingerprinting_enum.py example.com

# Shorter timeout for faster results
python3 website_fingerprinting_enum.py --timeout 5 example.com

# Longer timeout for slow sites
python3 website_fingerprinting_enum.py --timeout 30 example.com
```

#### 7. **Show All Information**
**Command:** `--show-all`
**Description:** Display comprehensive information including DNS data
**Examples:**
```bash
# Show all available information
python3 website_fingerprinting_enum.py --show-all example.com

# Show all with JSON output
python3 website_fingerprinting_enum.py -o json --show-all example.com
```

---

## Complete Usage Examples

### Example 1: Basic Single Target Scan
```bash
python3 website_fingerprinting_enum.py example.com
```
**Output:** Basic technology detection with formatted text output

### Example 2: Aggressive Multi-Target Scan
```bash
python3 website_fingerprinting_enum.py -v -a 2 -t 15 wordpress.org drupal.org joomla.org
```
**Output:** Verbose logging, aggressive scanning with path discovery, 15 threads for three CMS websites

### Example 3: JSON Output for Automation
```bash
python3 website_fingerprinting_enum.py -o json -a 3 --show-all target.com
```
**Output:** Complete scan results in JSON format including DNS information

### Example 4: Professional Security Assessment
```bash
python3 website_fingerprinting_enum.py -v -a 3 -t 20 --timeout 15 --show-all client-website.com
```
**Output:** Comprehensive security assessment with all features enabled

### Example 5: Batch Processing Multiple Sites
```bash
python3 website_fingerprinting_enum.py -o json -a 2 site1.com site2.net site3.org > results.json
```
**Output:** JSON results for multiple sites redirected to a file

---

## Output Interpretation

### Text Output Includes:
- **Basic Information**: Status code, response time, content length
- **Technologies Detected**: CMS, frameworks, servers with confidence levels
- **Interesting Headers**: Security headers, server information
- **Aggressive Findings**: Discovered paths and directories
- **DNS Information**: Various DNS records (if enabled)

### JSON Output Structure:
```json
{
  "target": "example.com",
  "status_code": 200,
  "technologies": {
    "WordPress": {
      "confidence": 85,
      "version": "6.2"
    }
  },
  "headers": {
    "server": "nginx/1.18.0"
  },
  "aggressive_findings": {
    "/admin": {
      "status": 200,
      "url": "https://example.com/admin"
    }
  }
}
```

This tool is designed for security professionals, penetration testers, and system administrators to quickly identify the technology stack of web applications and potential security exposure points.
