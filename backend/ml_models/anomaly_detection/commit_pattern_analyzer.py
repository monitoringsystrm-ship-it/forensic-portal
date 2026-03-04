import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

class CommitPatternAnalyzer:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def extract_features(self, commit_data):
        features = []
        for commit in commit_data:
            hour = commit.get('timestamp_hour', 12)
            day_of_week = commit.get('day_of_week', 3)
            
            feature_vector = [
                hour,
                day_of_week,
                commit.get('files_changed', 0),
                commit.get('lines_added', 0),
                commit.get('lines_removed', 0),
                commit.get('commit_message_length', 0),
                commit.get('is_weekend', 0),
                commit.get('is_off_hours', 0),
                commit.get('author_commit_count', 0),
                commit.get('time_since_last_commit', 0),
            ]
            features.append(feature_vector)
        return np.array(features)
    
    def train(self, commit_data, labels):
        features = self.extract_features(commit_data)
        features_scaled = self.scaler.fit_transform(features)
        
        X_train, X_test, y_train, y_test = train_test_split(
            features_scaled, labels, test_size=0.2, random_state=42
        )
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        return {
            'train_accuracy': train_score,
            'test_accuracy': test_score
        }
    
    def predict(self, commit_data):
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        features = self.extract_features(commit_data)
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        probabilities = self.model.predict_proba(features_scaled)
        
        results = []
        for i, commit in enumerate(commit_data):
            is_anomaly = predictions[i] == 1
            confidence = float(probabilities[i][1] * 100)
            results.append({
                'commit_id': commit.get('id', f'commit_{i}'),
                'is_anomaly': is_anomaly,
                'confidence': confidence,
                'anomaly_type': 'unusual_commit_pattern' if is_anomaly else 'normal'
            })
        
        return results
    
    def save_model(self, filepath='backend/ml_models/anomaly_detection/commit_pattern_model.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath='backend/ml_models/anomaly_detection/commit_pattern_model.pkl'):
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = data['is_trained']
        return self


