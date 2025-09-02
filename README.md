# Website Scanner

This Python script is a simple web crawler and scanner that explores a website, checks for errors, redirects, 
and potential open redirects. It saves the results to a text file for further review.

## Features

- Crawls a given website up to a specified depth (default: 3).
- Detects and logs:
  - HTTP errors (4xx, 5xx).
  - Redirects (3xx).
  - Potential open redirects (redirects leading to external domains).
- Saves scan results to `scan_results.txt`.

## Requirements

- Python 3.x
- Required libraries:
  - `requests`
  - `beautifulsoup4`

Install dependencies with:

```bash
pip install -r requirements.txt
```

### Example `requirements.txt`

```
requests
beautifulsoup4
```

## Usage

Run the scanner with:

```bash
python scanner.py <url>
```

### Example

```bash
python scanner.py https://example.com
```

## Output

- Logs are displayed in the console while scanning.
- A `scan_results.txt` file is generated with a summary of:
  - Errors
  - Redirects
  - Potential open redirects

## Notes

- Default maximum crawl depth is `3`. You can adjust this in the code (`crawl(domain, max_depth=3)`).
- Use responsibly. Only scan websites you own or have permission to test.
