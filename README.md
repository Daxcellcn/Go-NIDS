Go NIDS

Go NIDS is a high-performance Network Intrusion Detection System (NIDS) implemented in Go. This tool is designed to monitor and analyze network traffic for suspicious activities and potential threats. It provides real-time traffic analysis and alerting mechanisms, making it a useful tool for network security professionals.
Features

    Real-Time Packet Capture: Captures and analyzes network packets in real-time using the gopacket library.
    Anomaly Detection: Monitors payload sizes and triggers alerts if suspiciously large payloads are detected.
    Alert Logging: Logs detected anomalies to a file for later review.
    Concurrent Processing: Utilizes goroutines and channels for efficient packet processing and analysis.

Installation

    Install Dependencies: Ensure that you have the required dependencies. You'll need to have Npcap (or WinPcap) installed for packet capture on Windows.
        Download and Install Npcap: Npcap Download

    Clone the Repository:


git clone https://github.com/Daxcellcn/go-nids.git
cd go-nids

Build the Application:


go build -o go-nids main.go

Run the Application:


    go run main.go

    Ensure you replace "en0" in the networkInterface constant with the appropriate network interface name for your system.

Configuration

    networkInterface: Set this to the name of the network interface you want to capture packets from. For example, on Windows, it might be "Ethernet" or "Wi-Fi".
    maxPayloadSize: The threshold for detecting large payloads. Adjust this value based on your specific needs.
    logFile: The path to the log file where alerts will be written.

Usage

Once the application is running, it will start capturing network packets on the specified interface. It will analyze each packet for large payloads and log any detected anomalies to the nids_alerts.log file.
Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. For major changes, please open an issue to discuss what you would like to change.
License

This project is licensed under the MIT License. See the LICENSE file for details.
