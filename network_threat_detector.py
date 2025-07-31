import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
import threading
import time
from datetime import datetime
import matplotlib.pyplot as plt
from playsound import playsound
import os
import logging
import random

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkThreatDetector:
    def __init__(self):
        self.packet_data = []
        self.threat_alerts = []
        self.is_capturing = False
        self.capture_thread = None
        self.model = None
        self.scaler = None
        self.load_model()
        
    def load_model(self):
        """Load the trained model and scaler"""
        try:
            self.model = joblib.load('model.joblib')
            self.scaler = joblib.load('scaler.joblib')
            st.success("Model loaded successfully!")
            logger.info("Model and scaler loaded successfully")
        except FileNotFoundError:
            st.error("Model files not found. Please train the model first.")
            logger.error("Model files not found")
        except Exception as e:
            st.error(f"Error loading model: {str(e)}")
            logger.error(f"Error loading model: {str(e)}")
            
    def generate_simulated_packet(self):
        """Generate simulated packet data"""
        # Simulate different types of network traffic
        packet_types = ['normal', 'suspicious', 'attack']
        packet_type = random.choices(packet_types, weights=[0.7, 0.2, 0.1])[0]
        
        # Base features for normal traffic
        features = {
            ' Destination Port': random.randint(1, 65535),
            ' Flow Duration': random.randint(1, 1000),
            ' Total Fwd Packets': random.randint(1, 10),
            ' Total Backward Packets': random.randint(0, 5),
            'Total Length of Fwd Packets': random.randint(100, 1500),
            ' Total Length of Bwd Packets': random.randint(0, 1000),
            ' Fwd Packet Length Max': random.randint(100, 1500),
            ' Fwd Packet Length Min': random.randint(50, 100),
            ' Fwd Packet Length Mean': random.randint(100, 1000),
            ' Fwd Packet Length Std': random.randint(10, 100),
            'Bwd Packet Length Max': random.randint(0, 1000),
            ' Bwd Packet Length Min': random.randint(0, 500),
            ' Bwd Packet Length Mean': random.randint(0, 800),
            ' Bwd Packet Length Std': random.randint(0, 50),
            'Flow Bytes/s': random.randint(1000, 1000000),
            ' Flow Packets/s': random.randint(1, 1000),
            ' Flow IAT Mean': random.randint(1, 100),
            ' Flow IAT Std': random.randint(1, 50),
            ' Flow IAT Max': random.randint(10, 200),
            ' Flow IAT Min': random.randint(1, 10),
            'Fwd IAT Total': random.randint(1, 1000),
            ' Fwd IAT Mean': random.randint(1, 100),
            ' Fwd IAT Std': random.randint(1, 50),
            ' Fwd IAT Max': random.randint(10, 200),
            ' Fwd IAT Min': random.randint(1, 10),
            'Bwd IAT Total': random.randint(0, 500),
            ' Bwd IAT Mean': random.randint(0, 50),
            ' Bwd IAT Std': random.randint(0, 25),
            ' Bwd IAT Max': random.randint(0, 100),
            ' Bwd IAT Min': random.randint(0, 10),
            'Fwd PSH Flags': random.randint(0, 1),
            ' Bwd PSH Flags': random.randint(0, 1),
            ' Fwd URG Flags': random.randint(0, 1),
            ' Bwd URG Flags': random.randint(0, 1),
            ' Fwd Header Length': random.randint(20, 60),
            ' Bwd Header Length': random.randint(0, 40),
            'Fwd Packets/s': random.randint(1, 1000),
            ' Bwd Packets/s': random.randint(0, 500),
            ' Min Packet Length': random.randint(50, 100),
            ' Max Packet Length': random.randint(100, 1500),
            ' Packet Length Mean': random.randint(100, 1000),
            ' Packet Length Std': random.randint(10, 100),
            ' Packet Length Variance': random.randint(100, 10000),
            'FIN Flag Count': random.randint(0, 1),
            ' SYN Flag Count': random.randint(0, 1),
            ' RST Flag Count': random.randint(0, 1),
            ' PSH Flag Count': random.randint(0, 1),
            ' ACK Flag Count': random.randint(0, 1),
            ' URG Flag Count': random.randint(0, 1),
            ' CWE Flag Count': 0,
            ' ECE Flag Count': 0,
            ' Down/Up Ratio': random.random(),
            ' Average Packet Size': random.randint(100, 1000),
            ' Avg Fwd Segment Size': random.randint(100, 1000),
            ' Avg Bwd Segment Size': random.randint(0, 500),
            ' Fwd Header Length.1': random.randint(20, 60),
            'Fwd Avg Bytes/Bulk': random.randint(0, 1000),
            ' Fwd Avg Packets/Bulk': random.randint(0, 10),
            ' Fwd Avg Bulk Rate': random.randint(0, 1000),
            ' Bwd Avg Bytes/Bulk': random.randint(0, 500),
            ' Bwd Avg Packets/Bulk': random.randint(0, 5),
            'Bwd Avg Bulk Rate': random.randint(0, 500),
            'Subflow Fwd Packets': random.randint(1, 10),
            ' Subflow Fwd Bytes': random.randint(100, 1000),
            ' Subflow Bwd Packets': random.randint(0, 5),
            ' Subflow Bwd Bytes': random.randint(0, 500),
            'Init_Win_bytes_forward': random.randint(1000, 65535),
            ' Init_Win_bytes_backward': random.randint(0, 32768),
            ' act_data_pkt_fwd': random.randint(1, 10),
            ' min_seg_size_forward': random.randint(20, 100),
            'Active Mean': random.randint(1, 100),
            ' Active Std': random.randint(1, 50),
            ' Active Max': random.randint(10, 200),
            ' Active Min': random.randint(1, 10),
            'Idle Mean': random.randint(1, 100),
            ' Idle Std': random.randint(1, 50),
            ' Idle Max': random.randint(10, 200),
            ' Idle Min': random.randint(1, 10)
        }
        
        # Modify features for suspicious/attack traffic
        if packet_type == 'suspicious':
            features[' SYN Flag Count'] = 1
            features[' Total Fwd Packets'] = random.randint(10, 50)
            features['Flow Bytes/s'] = random.randint(1000000, 5000000)
        elif packet_type == 'attack':
            features[' SYN Flag Count'] = 1
            features[' RST Flag Count'] = 1
            features[' Total Fwd Packets'] = random.randint(50, 100)
            features['Flow Bytes/s'] = random.randint(5000000, 10000000)
            
        return features
            
    def detect_threats(self, features):
        """Detect potential threats using the loaded model"""
        if self.model and self.scaler:
            try:
                # Prepare features for prediction
                df = pd.DataFrame([features])
                X = self.scaler.transform(df)
                
                # Predict threat
                prediction = self.model.predict(X)[0]
                probability = self.model.predict_proba(X)[0][1]
                
                if prediction == 1 and probability > 0.8:
                    alert = {
                        'timestamp': datetime.now(),
                        'port': features[' Destination Port'],
                        'packet_length': features['Total Length of Fwd Packets'],
                        'threat_type': 'Suspicious Activity',
                        'confidence': probability
                    }
                    self.threat_alerts.append(alert)
                    logger.warning(f"Threat detected: {alert}")
                    self.play_alert()
            except Exception as e:
                logger.error(f"Error detecting threats: {str(e)}")
                
    def play_alert(self):
        """Play alert sound for detected threats"""
        try:
            playsound('alert.wav')
        except Exception as e:
            logger.error(f"Error playing alert sound: {str(e)}")
            
    def start_capture(self):
        """Start simulated packet capture in a separate thread"""
        try:
            if self.is_capturing:
                logger.warning("Capture already in progress")
                return False
                
            self.is_capturing = True
            self.packet_data = []  # Clear previous data
            self.threat_alerts = []  # Clear previous alerts
            self.capture_thread = threading.Thread(target=self._capture_thread)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            logger.info("Simulated packet capture started")
            return True
        except Exception as e:
            logger.error(f"Error starting capture: {str(e)}")
            self.is_capturing = False
            return False
        
    def _capture_thread(self):
        """Thread function for simulated packet capture"""
        try:
            logger.info("Starting simulated packet capture thread")
            while self.is_capturing:
                # Generate and process simulated packet
                features = self.generate_simulated_packet()
                self.packet_data.append(features)
                self.detect_threats(features)
                time.sleep(0.1)  # Simulate packet arrival rate
        except Exception as e:
            logger.error(f"Error in capture thread: {str(e)}")
            st.error(f"Error capturing packets: {str(e)}")
        finally:
            self.is_capturing = False
            logger.info("Simulated packet capture thread stopped")
        
    def stop_capture(self):
        """Stop packet capture"""
        try:
            if not self.is_capturing:
                logger.warning("No capture in progress")
                return
                
            self.is_capturing = False
            if self.capture_thread:
                self.capture_thread.join(timeout=1.0)
            logger.info("Packet capture stopped")
        except Exception as e:
            logger.error(f"Error stopping capture: {str(e)}")
            
    def get_packet_stats(self):
        """Get statistics about captured packets"""
        if not self.packet_data:
            return None
            
        try:
            df = pd.DataFrame(self.packet_data)
            return {
                'total_packets': len(df),
                'unique_ports': df[' Destination Port'].nunique(),
                'avg_packet_length': df['Total Length of Fwd Packets'].mean(),
                'total_bytes': df['Total Length of Fwd Packets'].sum(),
                'protocol_flags': {
                    'SYN': df[' SYN Flag Count'].sum(),
                    'ACK': df[' ACK Flag Count'].sum(),
                    'FIN': df['FIN Flag Count'].sum(),
                    'RST': df[' RST Flag Count'].sum(),
                    'PSH': df[' PSH Flag Count'].sum(),
                    'URG': df[' URG Flag Count'].sum()
                }
            }
        except Exception as e:
            logger.error(f"Error getting packet stats: {str(e)}")
            return None

def main():
    st.title("Network Threat Detection System")
    
    # Initialize detector
    if 'detector' not in st.session_state:
        st.session_state.detector = NetworkThreatDetector()
    
    # Sidebar controls
    st.sidebar.title("Controls")
    if st.sidebar.button("Start Capture"):
        if st.session_state.detector.start_capture():
            st.sidebar.success("Simulated packet capture started!")
        else:
            st.sidebar.error("Failed to start packet capture")
        
    if st.sidebar.button("Stop Capture"):
        st.session_state.detector.stop_capture()
        st.sidebar.warning("Packet capture stopped!")
    
    # Main display area
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Live Packet Statistics")
        stats = st.session_state.detector.get_packet_stats()
        if stats:
            # Create metrics display
            metric_col1, metric_col2, metric_col3 = st.columns(3)
            with metric_col1:
                st.metric("Total Packets", stats['total_packets'])
            with metric_col2:
                st.metric("Unique Ports", stats['unique_ports'])
            with metric_col3:
                st.metric("Total Bytes", f"{stats['total_bytes']:,}")
            
            # Protocol flags chart
            st.subheader("Protocol Flags Distribution")
            fig, ax = plt.subplots(figsize=(10, 4))
            ax.bar(stats['protocol_flags'].keys(), stats['protocol_flags'].values())
            ax.set_ylabel('Count')
            ax.set_title('TCP Flags Distribution')
            st.pyplot(fig)
        else:
            st.info("No packets captured yet. Click 'Start Capture' to begin monitoring.")
    
    with col2:
        st.subheader("Threat Alerts")
        if st.session_state.detector.threat_alerts:
            for alert in st.session_state.detector.threat_alerts[-5:]:
                st.error(f"""
                    **Time:** {alert['timestamp']}
                    **Port:** {alert['port']}
                    **Packet Length:** {alert['packet_length']}
                    **Threat:** {alert['threat_type']}
                    **Confidence:** {alert['confidence']:.2%}
                """)
        else:
            st.info("No threats detected yet")
    
    # Use Streamlit's built-in refresh mechanism
    st.empty()  # Placeholder for auto-refresh

if __name__ == "__main__":
    main() 