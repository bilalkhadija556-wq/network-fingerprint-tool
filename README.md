# 🌐 Network Fingerprint Generator

A web-based tool that captures live network traffic and generates behavioral fingerprints for websites. Built for networking students to understand how different websites communicate over networks.

## 📋 Table of Contents
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Results](#results)
- [Project Structure](#project-structure)
- [Video Demonstration](#video-demonstration)
- [Author](#author)

## ✨ Features

- ✅ Real-time packet capture using Scapy
- ✅ Website behavior classification (Streaming, Social Media, Static Content, API-Heavy)
- ✅ Interactive visualizations with Chart.js
- ✅ Side-by-side website comparison
- ✅ Protocol distribution pie chart
- ✅ Packet size histogram
- ✅ Traffic timeline graph

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.x | Backend logic |
| Flask | Web framework |
| Scapy | Packet capture |
| Chart.js | Data visualization |
| HTML/CSS/JS | Frontend interface |

## 📥 Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for packet capture)
- Active internet connection

### Steps

1. **Clone the repository**
```bash
git clone https://github.com/bilalkhadija556/network-fingerprint-tool.git
cd network-fingerprint-tool
## 🎥 Video Demonstration

Click the link below to watch the complete demonstration of this project:

**👉 [Watch the Demonstration Video](https://drive.google.com/file/d/1Ttj5gLyTAKXVoYAhAA-wPU14jn5ODFfQ/view?usp=sharing)**

### What the video shows:

- Starting the Flask server and opening the web interface
- Analyzing **google.com** → Static Content (85% confidence)
- Analyzing **youtube.com** → Streaming (92% confidence)
- Protocol Distribution Pie Chart
- Packet Size Histogram
- Traffic Timeline Graph
- Side-by-side comparison of two websites