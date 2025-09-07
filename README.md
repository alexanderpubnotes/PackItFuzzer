# HTTP Header Fuzzer

A precision network fuzzer designed to test web servers by injecting crafted values into specific HTTP headers. Unlike raw packet tools, this fuzzer uses reliable TCP socket connections while maintaining full control over HTTP payload construction. Now with connection reuse for significantly faster testing.

## Features

- **Precision Fuzzing**: Target specific HTTP headers with custom payloads
- **Reliable Connections**: Uses standard TCP sockets for guaranteed delivery
- **Connection Reuse**: Optional keep-alive mode for dramatically faster testing
- **Response Analysis**: Capture and categorize HTTP status codes automatically
- **Customizable Requests**: Full control over HTTP methods, paths, and headers
- **CSV Output**: Structured results for easy analysis and reporting
- **Firewall Friendly**: Appears as normal HTTP traffic to network security systems

## Installation

### Prerequisites

- Python 3.x
- No special libraries required (uses standard Python modules)

### Setup

```bash
# Clone or download the script
git clone 
cd http-header-fuzzer

# No additional installation needed!
# The tool uses Python's standard socket library
```

## Quick Start

Run a basic test against a target web server:

```bash
python3 http_fuzzer.py -t 192.168.1.100 -p 80 -H "User-Agent" -f wordlists/user_agents.txt
```

For faster testing with connection reuse:

```bash
python3 http_fuzzer.py -t 192.168.1.100 -p 80 -H "User-Agent" -f wordlists/user_agents.txt --keep-alive
```

## Usage

### Basic Syntax

```bash
python3 http_fuzzer.py -t TARGET_IP -p PORT -H HEADER -f WORDLIST [OPTIONS]
```

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-t, --target` | Target IP address | `-t 192.168.1.100` |
| `-p, --port` | Target port | `-p 8080` |
| `-H, --header` | Header to fuzz | `-H "User-Agent"` |
| `-f, --file` | Path to wordlist file | `-f wordlists/payloads.txt` |

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output CSV file | `fuzzer_results.csv` |
| `-d, --delay` | Delay between requests | `1.0` seconds |
| `-T, --timeout` | Response timeout | `5` seconds |
| `--headers-file` | Custom headers file | None |
| `--no-summary` | Hide startup summary | False |
| `--debug` | Show connection details | False |
| `--keep-alive` | Reuse TCP connections | False |

## Connection Reuse Feature

The `--keep-alive` option enables persistent TCP connections, dramatically improving performance:

```bash
# Without connection reuse (slower, more reliable)
python3 http_fuzzer.py -t 10.10.10.10 -p 80 -H "Host" -f hostnames.txt

# With connection reuse (much faster)
python3 http_fuzzer.py -t 10.10.10.10 -p 80 -H "Host" -f hostnames.txt --keep-alive
```

### When to Use Keep-Alive

- **Use --keep-alive for**: 
  - Fast testing against stable servers
  - Large wordlists where performance matters
  - Testing stateful applications

- **Avoid --keep-alive for**:
  - Unstable servers that drop connections
  - Initial testing and debugging
  - Servers that limit requests per connection

## Examples

### 1. Fuzz Host Header with Connection Reuse

```bash
python3 http_fuzzer.py -t 10.10.10.10 -p 80 -H "Host" -f wordlists/hostnames.txt --keep-alive -o host_fuzz_results.csv
```

### 2. Test API Authentication with Debug Output

```bash
python3 http_fuzzer.py -t 192.168.1.100 -p 8080 -H "Authorization" -f wordlists/tokens.txt --headers-file api_headers.txt --debug
```

### 3. Comprehensive Test with Custom Settings

```bash
python3 http_fuzzer.py -t 172.16.10.5 -p 443 -H "Cookie" -f session_cookies.txt --headers-file auth_headers.txt --keep-alive -d 0.5 -T 10 -o results.csv
```

## Creating Headers Files

Your fuzzer needs a base HTTP request to modify. Here's how to create headers files using common tools:

### From Browser Developer Tools

1. Open Developer Tools (F12)
2. Go to the Network tab
3. Visit your target URL
4. Right-click the request and select "Copy" → "Copy as cURL"
5. Extract the headers and save to a file

### From Burp Suite

1. Send a request to Burp's Repeater
2. Right-click in the request panel
3. Select "Copy to file" to save the raw request
4. Remove the body (if present) to create your headers file

### Example Headers File

```
GET /admin HTTP/1.1
Host: vulnerable.com
User-Agent: Mozilla/5.0
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
X-API-Key: 12345
Accept: application/json
```

## Understanding Results

The tool generates a CSV file with the following columns:

- **Fuzz Value**: The payload that was tested
- **Status Code**: HTTP response code or error type
- **Notes**: Categorized result for easy filtering

### Result Interpretation Guide

| Status Code | Meaning | Action |
|-------------|---------|--------|
| `2xx` (SUCCESS) | Request was successful | **Investigate** - A 200 to unexpected input may indicate vulnerability |
| `3xx` (REDIRECTION) | Request was redirected | Note for potential bypass issues |
| `4xx` (CLIENT_ERROR) | Client error | Expected for most fuzz values |
| `5xx` (SERVER_ERROR) | Server error | **High Priority** - May indicate crashes or vulnerabilities |
| `CONN_TIMEOUT` | Connection timeout | Network/firewall issue |
| `CONN_REFUSED` | Connection refused | Port not open/service not running |
| `CONN_ERROR` | Other connection error | Check network connectivity |

## Advanced Usage Tips

### 1. Optimizing Performance

```bash
# For maximum speed with stable servers
python3 http_fuzzer.py -t 10.10.10.10 -p 80 -H "User-Agent" -f big_wordlist.txt --keep-alive -d 0.1

# For reliability with unstable servers
python3 http_fuzzer.py -t 10.10.10.10 -p 80 -H "User-Agent" -f big_wordlist.txt -d 0.5 -T 10
```

### 2. Analyzing Results

```bash
# Filter for interesting results
grep -E '(SERVER_ERROR|SUCCESS)' fuzzer_results.csv > interesting_results.csv

# Count response types
cut -d',' -f2 fuzzer_results.csv | sort | uniq -c
```

### 3. Testing Different Applications

- **APIs**: Focus on `Authorization`, `X-API-Key`, and `Content-Type` headers
- **Admin Panels**: Test `Cookie`, `X-Forwarded-For`, and `Host` headers
- **File Uploads**: Manipulate `Content-Type` and `Content-Length` headers

## Limitations

- **HTTPS Not Supported**: This tool only works with HTTP servers. For HTTPS, consider using a proxy tool.
- **No Raw Packet Manipulation**: Cannot craft malformed TCP packets or manipulate low-level network characteristics.
- **Stateful Connections**: Each request creates a new TCP connection unless using --keep-alive.

## Troubleshooting

### Common Issues

1. **Connection Timeouts**:
   - Verify the target IP and port are correct
   - Check network connectivity
   - Increase timeout with `-T` option

2. **Connection Refused**:
   - The port is not open
   - The service is not listening on that port
   - A firewall is blocking access

3. **Keep-Alive Not Working**:
   - Some servers don't support persistent connections
   - Try without --keep-alive for problematic servers
   - The tool will automatically reconnect if needed

## Legal and Ethical Considerations

This tool is designed for:
- Security research
- Penetration testing (with proper authorization)
- Educational purposes

**Always ensure you have explicit permission** to test any network or system. Unauthorized use of this tool may violate local and international laws.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Recent Updates

- **Connection Reuse**: Added `--keep-alive` option for significantly faster testing
- **Improved Error Handling**: Better handling of network errors and reconnection logic
- **Enhanced Documentation**: Added examples and troubleshooting guide for the new features

For bug reports or feature requests, please open an issue on the project's GitHub repository.
