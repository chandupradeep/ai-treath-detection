# Network Threat Detection System

A real-time network traffic monitoring and threat detection system with a user-friendly GUI interface.

## Features

- Real-time packet capture and analysis
- AI-powered threat detection
- Live traffic statistics and visualization
- Alert system for detected threats
- User-friendly Streamlit-based GUI

## Prerequisites

- Python 3.8 or higher
- Administrative/root privileges (for packet capture)
- Network interface with promiscuous mode support

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd network-threat-detector
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Download a network traffic dataset (e.g., CICIDS2017) and save it as `network_traffic.csv`

4. Train the model:
```bash
python train_model.py
```

## Usage

1. Start the GUI application:
```bash
streamlit run network_threat_detector.py
```

2. In the GUI:
   - Click "Start Capture" to begin monitoring network traffic
   - View live packet statistics and threat alerts
   - Click "Stop Capture" to stop monitoring

## System Architecture

The system consists of three main components:

1. **Packet Capture Module**
   - Uses Scapy for low-level packet capture
   - Extracts relevant features from network packets
   - Runs in a separate thread for real-time processing

2. **AI Detection Module**
   - Uses a pre-trained Random Forest classifier
   - Analyzes packet features for suspicious patterns
   - Generates alerts for detected threats

3. **GUI Interface**
   - Built with Streamlit
   - Displays live traffic statistics
   - Shows threat alerts with confidence scores
   - Provides controls for starting/stopping capture

## Security Considerations

- The system requires administrative privileges for packet capture
- Network traffic data is processed locally
- No sensitive data is stored or transmitted
- Alerts are generated only for high-confidence threats

## Troubleshooting

1. **Permission Issues**
   - Ensure you're running the application with administrative privileges
   - On Linux/Mac: `sudo streamlit run network_threat_detector.py`
   - On Windows: Run PowerShell/Command Prompt as Administrator

2. **Model Not Found**
   - Make sure you've run `train_model.py` successfully
   - Check that `model.joblib` and `scaler.joblib` exist in the project directory

3. **No Network Traffic**
   - Verify your network interface is active
   - Check if your network interface supports promiscuous mode
   - Try running with a different network interface

## License

This project is licensed under the MIT License - see the LICENSE file for details. 