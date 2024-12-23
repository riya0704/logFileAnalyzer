import re
from collections import Counter

def parse_log_file(log_file_path):
    """
    Parses a web server log file and extracts useful information.

    Args:
        log_file_path (str): Path to the web server log file.

    Returns:
        dict: Parsed log data including 404 errors, requested pages, and IP addresses.
    """
    # Regular expression to match log entries (Apache/Nginx common log format)
    log_pattern = re.compile(r'(?P<ip>\S+) \S+ \S+ \[.*?\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \S+')

    # Data structures to hold analysis results
    ip_counter = Counter()
    url_counter = Counter()
    error_404_counter = 0

    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                match = log_pattern.match(line)
                if match:
                    ip = match.group('ip')
                    url = match.group('url')
                    status = match.group('status')

                    # Count occurrences
                    ip_counter[ip] += 1
                    url_counter[url] += 1

                    if status == '404':
                        error_404_counter += 1

    except FileNotFoundError:
        print(f"Error: Log file {log_file_path} not found.")
        return {}
    except Exception as e:
        print(f"An error occurred while parsing the log file: {e}")
        return {}

    return {
        'ip_counter': ip_counter,
        'url_counter': url_counter,
        'error_404_count': error_404_counter
    }

def generate_report(parsed_data):
    """
    Generates a summarized report from parsed log data.

    Args:
        parsed_data (dict): Parsed log data.

    Returns:
        str: Summarized report.
    """
    if not parsed_data:
        return "No data available to generate a report."

    report_lines = []

    # 404 errors
    report_lines.append(f"Total 404 Errors: {parsed_data['error_404_count']}")

    # Most requested pages
    report_lines.append("\nTop 5 Most Requested Pages:")
    for url, count in parsed_data['url_counter'].most_common(5):
        report_lines.append(f"{url}: {count} requests")

    # IPs with the most requests
    report_lines.append("\nTop 5 IP Addresses by Number of Requests:")
    for ip, count in parsed_data['ip_counter'].most_common(5):
        report_lines.append(f"{ip}: {count} requests")

    return "\n".join(report_lines)

def main():
    log_file_path = "web_server.log"  # Replace with the path to your log file

    print("Analyzing log file...")
    parsed_data = parse_log_file(log_file_path)

    print("\nGenerating report...")
    report = generate_report(parsed_data)

    print("\nSummary Report:\n")
    print(report)

if __name__ == "__main__":
    main()
