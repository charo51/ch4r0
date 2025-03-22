# CH4R0

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
