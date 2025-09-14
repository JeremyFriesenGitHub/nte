# Network Data Analyzer

A Python application that analyzes network data from JSON files using Cohere's Large Language Models (LLM) and displays comprehensive analysis results.

## Features

- 📁 Load network data from JSON files
- 🤖 Analyze network data using Cohere's Command models
- 📊 Display formatted analysis reports with network statistics
- 🔒 Security assessment and vulnerability identification
- 📈 Performance analysis and traffic pattern insights
- 🚨 Security event monitoring and alerting
- 💡 Actionable recommendations for network improvement

## Installation

1. Clone or download this project
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Setup

### Cohere API Key

You need a Cohere API key to use this application. You can get one from [Cohere's dashboard](https://dashboard.cohere.ai/api-keys).

Set your API key in one of these ways:

**Option 1: Environment Variable (Recommended)**
```bash
# Windows
set COHERE_API_KEY=your_api_key_here

# Linux/Mac
export COHERE_API_KEY=your_api_key_here
```

**Option 2: Command Line Parameter**
```bash
python script.py sample_network_data.json --api-key your_api_key_here
```

## Usage

### Basic Usage
```bash
python script.py sample_network_data.json
```

### With API Key Parameter
```bash
python script.py sample_network_data.json --api-key your_api_key_here
```

### Help
```bash
python script.py --help
```

## JSON Data Format

The application expects JSON files with the following structure:

```json
{
  "network_info": {
    "name": "Network Name",
    "timestamp": "2025-01-15T10:30:00Z",
    "scan_duration": "45 minutes"
  },
  "nodes": [
    {
      "id": "192.168.1.1",
      "type": "router",
      "hostname": "main-router",
      "status": "active",
      "last_seen": "2025-01-15T10:29:45Z",
      "ports": [22, 80, 443],
      "services": ["SSH", "HTTP", "HTTPS"]
    }
  ],
  "connections": [
    {
      "source": "192.168.1.1",
      "destination": "192.168.1.10",
      "protocol": "TCP",
      "port": 80,
      "status": "established",
      "bandwidth_usage": "2.5 Mbps"
    }
  ],
  "security_events": [
    {
      "timestamp": "2025-01-15T10:25:00Z",
      "type": "failed_login",
      "source": "192.168.1.100",
      "target": "192.168.1.10",
      "severity": "medium",
      "details": "Multiple SSH login attempts from unknown IP"
    }
  ],
  "traffic_statistics": {
    "total_packets": 125847,
    "total_bytes": "45.2 GB",
    "peak_bandwidth": "15.8 Mbps",
    "average_bandwidth": "3.2 Mbps",
    "protocols": {
      "TCP": "78%",
      "UDP": "15%",
      "ICMP": "7%"
    }
  }
}
```

## Sample Data

The project includes `sample_network_data.json` with example network data that you can use to test the application.

## Output

The application generates a comprehensive report including:

1. **Network Overview**: Summary of network topology and components
2. **Security Assessment**: Potential risks and vulnerabilities
3. **Performance Analysis**: Traffic patterns and performance metrics
4. **Connectivity Issues**: Connection problems and failed services
5. **Recommendations**: Actionable improvement suggestions

## Example Output

```
================================================================================
🌐 NETWORK DATA ANALYSIS REPORT
================================================================================

📊 Network: Corporate Network Analysis
⏰ Scan Time: 2025-01-15T10:30:00Z
⏱️  Duration: 45 minutes

🖥️  Total Nodes: 4 (Active: 3)
   • Router: 1
   • Server: 2
   • Workstation: 1

🔗 Connections: 3 (Established: 2)

🚨 Security Events: 2 (High Severity: 1)

📈 Traffic: 125847 packets, 45.2 GB
   Peak: 15.8 Mbps, Average: 3.2 Mbps

================================================================================
🤖 LLM ANALYSIS RESULTS
================================================================================
[Detailed LLM analysis results appear here]
================================================================================
```

## Error Handling

The application includes comprehensive error handling for:
- Missing or invalid JSON files
- API connection issues
- Invalid API keys
- Network timeouts
- Malformed data structures

## Requirements

- Python 3.7+
- Cohere API key
- Internet connection for LLM analysis

## Dependencies

- `requests`: HTTP library for API calls
- `cohere`: Cohere Python client for LLM analysis

## Security Notes

- Never hardcode API keys in your code
- Use environment variables for sensitive information
- Keep your API key secure and don't share it publicly
- Monitor your Cohere API usage to avoid unexpected charges

## License

This project is open source and available under the MIT License.
