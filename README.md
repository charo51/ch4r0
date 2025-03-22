#Ch4R0 "lm9wd"
*CH4R0 - A powerful tool for mapping and analyzing attack surfaces.*

---

## 📖 **Overview**
CH4R0 is an advanced attack surface mapping tool designed for security professionals and bug bounty hunters. It automates the process of gathering URLs, analyzing web assets, and identifying potential vulnerabilities using multiple open-source tools like Katana, GoSpider, Wayback Machine, and Nuclei.

---

## ✨ **Features**
- **URL Harvesting**: Collects URLs from multiple sources:
  - **Katana**: Advanced web crawler.
  - **GoSpider**: Fast and efficient web spider.
  - **Wayback Machine**: Historical URL discovery.
  - **Common Crawl**: Large-scale web dataset.
- **URL Processing**:
  - Filters URLs with query parameters.
  - Extracts JavaScript files for analysis.
  - Categorizes links by file type and sensitivity.
- **Vulnerability Scanning**:
  - Integrates **Nuclei** for automated vulnerability detection.
- **Live URL Checking**:
  - Uses **httpx** to verify live URLs.
- **Detailed Reporting**:
  - Generates categorized output files for easy analysis.

---

## 🚀 **Usage**

### Basic Command
```bash
python3 CH4R0.py -t example.com -o output
```

### Options
- `-t` or `--target`: Target domain or URL (e.g., `example.com`).
- `-o` or `--output`: Output directory (default: `output`).
- `-f` or `--filter`: Filter Wayback Machine URLs by file extensions.
- `-v` or `--verbose`: Enable verbose mode for detailed logging.

### Example
```bash
python3 CH4R0.py -t example.com -o results -f
```

---

## 📂 **Output Structure**
The tool generates the following files in the output directory:
```
output/
├── example.com/
│   ├── katana_urls.txt
│   ├── gospider_urls.txt
│   ├── wayback_urls.txt
│   ├── commoncrawl_urls.txt
│   ├── combined_urls.txt
│   ├── filtered_urls.txt
│   ├── js_files.txt
│   ├── live_urls.txt
│   ├── nuclei_results.txt
│   ├── category-js.txt
│   ├── category-pdf.txt
│   ├── category-sensitive.txt
│   └── wayback_details.json
```

---

## 🛡️ **Tools Used**
CH4R0 integrates the following tools:
- **Katana**: Advanced web crawler.
- **GoSpider**: Fast web spider.
- **Hakrawler**: Simple web crawler.
- **httpx**: HTTP probe for live URL verification.
- **Nuclei**: Vulnerability scanner.
- **Wayback Machine**: Historical URL discovery.
- **Common Crawl**: Large-scale web dataset.

---

## 📜 **License**
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🤝 **Contributing**
Contributions are welcome! Here’s how you can help:
1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature`.
3. Commit your changes: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Submit a pull request.


---

## 🙏 **Acknowledgments**
- Thanks to the creators of Katana, GoSpider, Nuclei, and other tools for their amazing work.
- Inspired by the bug bounty and security research community.

---

## ⚠️ **Disclaimer**
This tool is intended for educational and ethical purposes only. Do not use it for illegal or malicious activities. The authors are not responsible for any misuse of this tool.

---

```

---
