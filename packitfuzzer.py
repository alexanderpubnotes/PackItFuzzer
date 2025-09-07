#!/usr/bin/env python3

import argparse
import time
import random
import socket

def get_arguments():
    """
    Parses command-line arguments and returns them.
    """
    parser = argparse.ArgumentParser(
        description="PackItFuzzer - Craft and send fuzzed HTTP packets.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Basic test using the default template (fuzzing Host header):
    %(prog)s -t 192.168.1.100 -p 80 -H "Host" -f hostnames.txt

  Test with persistent connection (much faster):
    %(prog)s -t 192.168.1.100 -p 80 -H "User-Agent" -f user_agents.txt --keep-alive

  Test a specific API endpoint:
    %(prog)s -t 10.10.10.10 -p 8080 -H "Authorization" -f tokens.txt --headers-file api_headers.txt
"""
    )
    
    # Required arguments
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument("-t", "--target", dest="target_ip", required=True,
                        help="IP address of the target web server.")
    required_args.add_argument("-p", "--port", dest="target_port", type=int, required=True,
                        help="TCP port of the target web service (e.g., 80, 443, 8080).")
    required_args.add_argument("-H", "--header", dest="header", required=True,
                        help="The HTTP header to inject fuzz values into (e.g., 'Host', 'User-Agent').")
    required_args.add_argument("-f", "--file", dest="file_path", required=True,
                        help="Path to a text file containing fuzz values, one per line.")
    
    # Request Configuration
    config_args = parser.add_argument_group('request configuration')
    config_args.add_argument("--headers-file", dest="headers_file",
                        help="""Path to a file defining the base HTTP request.
Includes the request line and headers. If not provided, a default GET request is used.
Format: 
  GET / HTTP/1.1
  Host: example.com
  User-Agent: Fuzzer/1.0
  ...etc
See documentation for examples.""")

    # Output & Performance
    output_args = parser.add_argument_group('output & performance')
    output_args.add_argument("-o", "--output", dest="output_file", default="fuzzer_results.csv",
                        help="File to save results to (CSV format). Default: fuzzer_results.csv")
    output_args.add_argument("-d", "--delay", dest="delay", type=float, default=1.0,
                        help="Delay (in seconds) between sending packets. Default: 1.0")
    output_args.add_argument("-T", "--timeout", dest="timeout", type=int, default=5,
                        help="Time (in seconds) to wait for a response. Default: 5")
    output_args.add_argument("--no-summary", dest="hide_summary", action="store_true",
                        help="Do not display the configuration summary before starting.")
    output_args.add_argument("--debug", dest="debug", action="store_true",
                        help="Print the raw HTTP request being sent for debugging.")
    output_args.add_argument("--keep-alive", dest="keep_alive", action="store_true",
                        help="Reuse a single TCP connection for multiple requests. Much faster, but may be less reliable with some servers.")
    
    return parser.parse_args()

def read_fuzz_file(file_path):
    """
    Reads the fuzz values from the specified file.
    """
    try:
        with open(file_path, 'r') as f:
            # Read lines, strip whitespace, and ignore empty lines
            fuzz_list = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: The file '{file_path}' was not found.")
        exit(1)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        exit(1)
        
    if not fuzz_list:
        print("[!] Error: The fuzz list file is empty.")
        exit(1)
    return fuzz_list

def read_static_headers(headers_file_path):
    """
    Reads a file of static headers and returns them as a string.
    Returns None if no file path is provided.
    """
    if not headers_file_path:
        return None
    try:
        with open(headers_file_path, 'r') as f:
            headers = [line.strip() for line in f.readlines() if line.strip()]
            # Combine all headers into a single string with CRLF line endings
            return "\r\n".join(headers) + "\r\n"
    except FileNotFoundError:
        print(f"[!] Error: The headers file '{headers_file_path}' was not found.")
        exit(1)
    except Exception as e:
        print(f"[!] Error reading headers file: {e}")
        exit(1)

def build_fuzzed_http_packet(fuzz_value, header_to_fuzz, static_headers):
    """
    Builds an HTTP request packet. Replaces the header if it exists, otherwise appends.
    Uses the provided static_headers, which must include the request line.
    """
    # If no custom headers file is provided, use a default minimal request
    if static_headers is None:
        static_headers = (
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: close\r\n"
            "Cache-Control: max-age=0\r\n"
        )

    # Check if the header we want to fuzz is already in the headers
    header_lower = header_to_fuzz.lower()
    lines = static_headers.split('\r\n')
    new_lines = []

    header_found = False
    for line in lines:
        if line and ':' in line:
            current_header = line.split(':', 1)[0].strip().lower()
            if current_header == header_lower:
                # Replace this line with our fuzzed header
                if fuzz_value != "":
                    new_lines.append(f"{header_to_fuzz}: {fuzz_value}")
                header_found = True
            else:
                # Keep the original header (or the request line)
                new_lines.append(line)
        else:
            # Keep empty lines or the request line (which doesn't have a colon)
            new_lines.append(line)

    # If the header wasn't found and we aren't omitting it, append it.
    if not header_found and fuzz_value != "":
        new_lines.append(f"{header_to_fuzz}: {fuzz_value}")

    # Rebuild the full payload
    http_payload = "\r\n".join(new_lines) + "\r\n"
    return http_payload

def send_and_receive(target_ip, target_port, fuzzed_payload, timeout, debug=False):
    """
    Uses Python sockets for reliable TCP connection, but sends raw HTTP payload.
    Returns the response data, HTTP status code, and notes.
    """
    try:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        if debug:
            print(f"[DEBUG] Attempting to connect to {target_ip}:{target_port}")
        
        # Establish connection (handles SYN/SYN-ACK/ACK)
        s.connect((target_ip, target_port))
        
        if debug:
            print("[DEBUG] TCP connection established successfully")
            print("[DEBUG] HTTP Payload:")
            print("-" * 40)
            print(fuzzed_payload)
            print("-" * 40)
        
        # Send our crafted HTTP payload
        s.sendall(fuzzed_payload.encode())
        
        # Receive response
        response = b""
        try:
            while True:
                chunk = s.recv(4096)  # Read 4KB at a time
                if not chunk:
                    break
                response += chunk
                # Small pause to allow more data to arrive
                time.sleep(0.1)
        except socket.timeout:
            # This is expected - we read until timeout
            pass
        finally:
            s.close()
        
        # Parse HTTP status code from response
        status_code = None
        notes = "HTTP response received"
        
        try:
            http_text = response.decode('utf-8', errors='ignore')
            if debug:
                print(f"[DEBUG] Received response: {len(http_text)} bytes")
                if len(http_text) > 0:
                    print("[DEBUG] First 200 chars of response:")
                    print("-" * 40)
                    print(http_text[:200])
                    print("-" * 40)
                
            lines = http_text.split('\r\n')
            for line in lines:
                if line.startswith('HTTP/'):
                    parts = line.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        status_code = parts[1]
                    break
                    
            if status_code:
                # Classify the status code
                if status_code.startswith('2'):
                    notes = "SUCCESS"
                elif status_code.startswith('3'):
                    notes = "REDIRECTION"
                elif status_code.startswith('4'):
                    notes = "CLIENT_ERROR"
                elif status_code.startswith('5'):
                    notes = "SERVER_ERROR"
                    
        except Exception as e:
            notes = f"Response parsing error: {e}"
            if debug:
                print(f"[DEBUG] Error parsing response: {e}")
        
        return response, status_code, notes
        
    except socket.timeout:
        return None, "CONN_TIMEOUT", "Connection timeout"
    except ConnectionRefusedError:
        return None, "CONN_REFUSED", "Connection refused (port closed?)"
    except Exception as e:
        return None, "CONN_ERROR", f"Connection error: {str(e)}"

class HTTPConnection:
    """Manages a persistent HTTP connection to a target."""
    
    def __init__(self, target_ip, target_port, timeout):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.socket = None
        self.is_connected = False
        
    def connect(self):
        """Establishes a new TCP connection."""
        self.close()  # Close any existing connection first
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.target_ip, self.target_port))
            self.is_connected = True
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.is_connected = False
            return False
            
    def send_receive(self, http_payload, debug=False):
        """
        Sends an HTTP payload and returns the response.
        Automatically reconnects if the connection is broken.
        """
        if not self.is_connected:
            if not self.connect():
                return None, "CONN_ERROR", "Failed to establish connection"
        
        try:
            # Send the request
            self.socket.sendall(http_payload.encode())
            if debug:
                print("[DEBUG] Sent payload on existing connection.")
            
            # Receive the response
            response = b""
            try:
                # Set a shorter timeout for reading to avoid hanging
                self.socket.settimeout(self.timeout)
                while True:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                # It's normal to timeout when no more data is coming
                pass
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Error receiving data: {e}")
                self.is_connected = False
                return None, "RECV_ERROR", f"Error receiving data: {e}"
            
            # Parse HTTP status code from response
            status_code = None
            notes = "HTTP response received"
            
            try:
                http_text = response.decode('utf-8', errors='ignore')
                if debug and http_text:
                    print(f"[DEBUG] Received {len(http_text)} byte response")
                    
                lines = http_text.split('\r\n')
                for line in lines:
                    if line.startswith('HTTP/'):
                        parts = line.split()
                        if len(parts) > 1 and parts[1].isdigit():
                            status_code = parts[1]
                            
                            # Classify the status code
                            if status_code.startswith('2'):
                                notes = "SUCCESS"
                            elif status_code.startswith('3'):
                                notes = "REDIRECTION"
                            elif status_code.startswith('4'):
                                notes = "CLIENT_ERROR"
                            elif status_code.startswith('5'):
                                notes = "SERVER_ERROR"
                        break
            except Exception as e:
                notes = f"Response parsing error: {e}"
                if debug:
                    print(f"[DEBUG] Error parsing response: {e}")
            
            return response, status_code, notes
            
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # Connection was reset by peer or is otherwise broken
            if debug:
                print(f"[DEBUG] Connection error: {e}. Attempting to reconnect.")
            self.is_connected = False
            # Try to reconnect and resend the request
            if self.connect():
                return self.send_receive(http_payload, debug)
            else:
                return None, "CONN_ERROR", f"Connection failed and could not reconnect: {e}"
                
    def close(self):
        """Safely closes the connection."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None
        self.is_connected = False

def main():
    # Get configuration from command line arguments
    args = get_arguments()
    fuzz_list = read_fuzz_file(args.file_path)
    static_headers = read_static_headers(args.headers_file)
    
    # Open the output file for writing at the start
    try:
        output_file = open(args.output_file, 'w')
        output_file.write("Fuzz Value,Status Code,Notes\n") # Write CSV header
    except Exception as e:
        print(f"[!] Failed to open output file {args.output_file}: {e}")
        exit(1)
    
    # Display configuration summary unless disabled
    if not args.hide_summary:
        print("\n[*] Fuzzer Configuration")
        print("    " + "-" * 40)
        print(f"    Target:        {args.target_ip}:{args.target_port}")
        print(f"    Header to Fuzz: '{args.header}'")
        print(f"    Fuzz File:     {args.file_path}")
        if args.headers_file:
            print(f"    Custom Headers: {args.headers_file}")
        else:
            print(f"    Using:         Default request template")
        print(f"    Connection:    {'Persistent (keep-alive)' if args.keep_alive else 'New for each request'}")
        print(f"    Output:        {args.output_file}")
        print(f"    Test Cases:    {len(fuzz_list)}")
        print(f"    Timeout:       {args.timeout}s")
        print("    " + "-" * 40)
        print("[*] Press Ctrl+C to stop at any time.\n")
        time.sleep(2)  # Give user a moment to read

    # Create connection manager if keep-alive is enabled
    conn_manager = None
    if args.keep_alive:
        conn_manager = HTTPConnection(args.target_ip, args.target_port, args.timeout)
        # Test the connection once before starting
        if not conn_manager.connect():
            print("[!] Initial connection failed. Check target and try without --keep-alive.")
            conn_manager.close()
            exit(1)

    try:
        for index, value in enumerate(fuzz_list, 1):
            print(f"[{index:03d}/{len(fuzz_list):03d}] Testing: '{value}'")
            
            # 1. Build the fuzzed packet
            fuzzed_payload = build_fuzzed_http_packet(value, args.header, static_headers)
            
            # 2. Send it and wait for a response
            if args.keep_alive:
                # Use persistent connection
                response, status_code, notes = conn_manager.send_receive(
                    fuzzed_payload, 
                    args.debug
                )
            else:
                # Use the original method (new connection for each request)
                response, status_code, notes = send_and_receive(
                    args.target_ip, 
                    args.target_port, 
                    fuzzed_payload, 
                    args.timeout,
                    args.debug
                )
            
            # 3. Determine the result and write to the file
            if status_code is None:
                status_code = "N/A"
            
            # Write the result to the CSV file
            output_file.write(f'"{value}",{status_code},"{notes}"\n')
            output_file.flush() # Ensure it's written after each packet
            
            print(f"      Result: {status_code} - {notes}")
            time.sleep(args.delay)
            
    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted by user.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        # This ensures the file is always closed, even on error or interrupt
        output_file.close()
        if conn_manager:
            conn_manager.close()
    
    print(f"[*] Fuzzing complete. Results saved to {args.output_file}.")

if __name__ == "__main__":
    main()
