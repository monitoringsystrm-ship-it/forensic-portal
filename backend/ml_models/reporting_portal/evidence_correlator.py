import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os
from datetime import datetime

class EvidenceCorrelator:
    def __init__(self):
        self.clustering_model = DBSCAN(eps=0.5, min_samples=2)
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=500)
        self.is_trained = False
        
    def extract_temporal_features(self, evidence_data):
        features = []
        for evidence in evidence_data:
            timestamp = evidence.get('timestamp', '')
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour = dt.hour
                    day_of_week = dt.weekday()
                    day_of_month = dt.day
                except:
                    hour = 12
                    day_of_week = 3
                    day_of_month = 15
            else:
                hour = 12
                day_of_week = 3
                day_of_month = 15
            
            feature_vector = [
                hour,
                day_of_week,
                day_of_month,
                evidence.get('evidence_type_encoded', 0),
                evidence.get('source_encoded', 0),
            ]
            features.append(feature_vector)
        return np.array(features)
    
    def extract_text_features(self, evidence_data):
        texts = []
        for evidence in evidence_data:
            text = f"{evidence.get('description', '')} {evidence.get('type', '')} {evidence.get('source', '')}"
            texts.append(text)
        return texts
    
    def train(self, evidence_data):
        temporal_features = self.extract_temporal_features(evidence_data)
        text_features = self.extract_text_features(evidence_data)
        
        text_vectors = self.vectorizer.fit_transform(text_features).toarray()
        temporal_scaled = self.scaler.fit_transform(temporal_features)
        
        combined_features = np.hstack([temporal_scaled, text_vectors])
        
        clusters = self.clustering_model.fit_predict(combined_features)
        
        self.is_trained = True
        
        unique_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
        noise_points = list(clusters).count(-1)
        
        return {
            'clusters_found': unique_clusters,
            'noise_points': noise_points,
            'total_points': len(evidence_data)
        }
    
    def correlate(self, evidence_data):
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        temporal_features = self.extract_temporal_features(evidence_data)
        text_features = self.extract_text_features(evidence_data)
        
        text_vectors = self.vectorizer.transform(text_features).toarray()
        temporal_scaled = self.scaler.transform(temporal_features)
        
        combined_features = np.hstack([temporal_scaled, text_vectors])
        clusters = self.clustering_model.fit_predict(combined_features)
        
        correlation_results = []
        cluster_groups = {}
        
        for i, cluster_id in enumerate(clusters):
            if cluster_id not in cluster_groups:
                cluster_groups[cluster_id] = []
            cluster_groups[cluster_id].append(i)
        
        for i, evidence in enumerate(evidence_data):
            cluster_id = int(clusters[i])
            related_evidence = []
            
            if cluster_id != -1:
                related_indices = [idx for idx in cluster_groups[cluster_id] if idx != i]
                related_evidence = [
                    {
                        'id': evidence_data[idx].get('id', f'evidence_{idx}'),
                        'type': evidence_data[idx].get('type', ''),
                        'timestamp': evidence_data[idx].get('timestamp', ''),
                    }
                    for idx in related_indices[:5]
                ]
            
            correlation_results.append({
                'evidence_id': evidence.get('id', f'evidence_{i}'),
                'cluster_id': cluster_id,
                'is_correlated': cluster_id != -1,
                'related_evidence_count': len(related_evidence),
                'related_evidence': related_evidence,
                'correlation_score': len(related_evidence) / max(len(cluster_groups.get(cluster_id, [])), 1)
            })
        
        return correlation_results
    
    def build_timeline(self, evidence_data, correlation_results):
        timeline = []
        
        for i, evidence in enumerate(evidence_data):
            correlation = correlation_results[i]
            
            timeline_event = {
                'id': evidence.get('id', f'event_{i}'),
                'timestamp': evidence.get('timestamp', ''),
                'type': evidence.get('type', ''),
                'description': evidence.get('description', ''),
                'cluster_id': correlation['cluster_id'],
                'related_events': correlation['related_evidence'],
                'is_correlated': correlation['is_correlated']
            }
            
            timeline.append(timeline_event)
        
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline
    
    def save_model(self, filepath='backend/ml_models/reporting_portal/evidence_correlator_model.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'clustering_model': self.clustering_model,
            'scaler': self.scaler,
            'vectorizer': self.vectorizer,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath='backend/ml_models/reporting_portal/evidence_correlator_model.pkl'):
        data = joblib.load(filepath)
        self.clustering_model = data['clustering_model']
        self.scaler = data['scaler']
        self.vectorizer = data['vectorizer']
        self.is_trained = data['is_trained']
        return self


