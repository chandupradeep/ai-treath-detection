import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
from tqdm import tqdm

def load_and_preprocess_data(file_path):
    """Load and preprocess network traffic data"""
    try:
        print(f"Loading dataset from {file_path}...")
        df = pd.read_csv(file_path)
        
        if df.empty:
            print("Error: Dataset is empty")
            return None, None, None, None, None
            
        # Print column names for debugging
        print("\nAvailable columns in the dataset:")
        print(df.columns.tolist())
        
        # Select relevant features and target
        features = [
            ' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
            'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max',
            ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
            'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
            ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean',
            ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean',
            ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
            ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
            ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
            'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
            ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
            'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count',
            ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count',
            ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
            ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
            ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
            ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
            ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
            'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd',
            ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max',
            ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
        ]
        
        # Check which features exist in the dataset
        available_features = [col for col in features if col in df.columns]
        missing_features = [col for col in features if col not in df.columns]
        
        if missing_features:
            print("\nWarning: The following features are missing from the dataset:")
            print(missing_features)
            print("\nPlease provide the correct column names for these features.")
            return None, None, None, None, None
        
        # Create binary threat label (1 for attack, 0 for benign)
        if ' Label' not in df.columns:
            print("\nWarning: 'Label' column not found. Please identify the column containing threat labels.")
            print("Available columns that might contain labels:")
            print([col for col in df.columns if 'label' in col.lower() or 'class' in col.lower() or 'type' in col.lower()])
            return None, None, None, None, None
        
        df['is_threat'] = df[' Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
        
        # Select features and target
        X = df[features]
        y = df['is_threat']
        
        # Handle infinite values
        X = X.replace([np.inf, -np.inf], np.nan)
        # Fill NaN values with mean for each column
        X = X.fillna(X.mean())
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale the features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, y_train, y_test, scaler
    except Exception as e:
        print(f"Error in data preprocessing: {str(e)}")
        return None, None, None, None, None

def train_model(X_train, y_train):
    """Train a Random Forest classifier"""
    try:
        print("Training model...")
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1  # Use all available cores
        )
        model.fit(X_train, y_train)
        return model
    except Exception as e:
        print(f"Error training model: {str(e)}")
        return None

def evaluate_model(model, X_test, y_test):
    """Evaluate the model's performance"""
    try:
        y_pred = model.predict(X_test)
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
    except Exception as e:
        print(f"Error evaluating model: {str(e)}")

def main():
    # Set the dataset path
    dataset_path = 'network_traffic.csv'
    
    # Check if dataset exists
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at {dataset_path}")
        return
    
    try:
        # Load and preprocess data
        print("Loading and preprocessing data...")
        X_train, X_test, y_train, y_test, scaler = load_and_preprocess_data(dataset_path)
        
        if X_train is None:
            print("\nPlease update the feature names in the code to match your dataset's column names.")
            return
        
        # Train the model
        print("Training model...")
        model = train_model(X_train, y_train)
        
        if model is None:
            print("\nFailed to train the model.")
            return
        
        # Evaluate the model
        print("Evaluating model...")
        evaluate_model(model, X_test, y_test)
        
        # Save the model and scaler
        print("Saving model and scaler...")
        joblib.dump(model, 'model.joblib')
        joblib.dump(scaler, 'scaler.joblib')
        print("Model and scaler saved successfully!")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Please ensure the dataset is properly formatted and contains the required columns.")

if __name__ == "__main__":
    main() 