#!/usr/bin/env python3
"""
Advanced ARP Defense Strategies Implementation

This module implements sophisticated defense mechanisms against ARP DoS attacks
using machine learning, network analysis, and adaptive protection strategies.
"""

import numpy as np
import time
import json
import collections
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

# Try to import ML libraries, but handle gracefully if not available
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
    import numpy as np
except ImportError:
    ML_AVAILABLE = False
    print("Warning: Machine learning libraries not available. Running in basic mode.")
    # Create dummy numpy for compatibility

    class DummyNumpy:
        @staticmethod
        def mean(data): return sum(data) / len(data) if data else 0

        @staticmethod
        def std(data):
            if not data:
                return 0
            mean_val = sum(data) / len(data)
            return (sum((x - mean_val) ** 2 for x in data) / len(data)) ** 0.5

        @staticmethod
        def percentile(data, p):
            if not data:
                return 0
            sorted_data = sorted(data)
            index = int(len(sorted_data) * p / 100)
            return sorted_data[min(index, len(sorted_data) - 1)]

        @staticmethod
        def array(data): return data
    np = DummyNumpy()


class AdaptiveThresholdManager:
    """
    Manages adaptive thresholds based on network traffic patterns
    using statistical analysis and machine learning techniques
    """

    def __init__(self):
        self.baseline_stats = {
            'packets_per_second': [],
            'unique_senders_per_minute': [],
            'gratuitous_ratio': [],
            'mac_changes_per_ip': []
        }
        self.current_thresholds = {
            'packets_per_second': 10,
            'unique_senders_per_minute': 5,
            'gratuitous_ratio': 0.1,
            'mac_changes_per_ip': 1
        }
        self.learning_period = 3600  # 1 hour
        self.start_time = time.time()
        self.adaptation_factor = 2.0  # Multiply baseline by this factor

    def update_baseline(self, metrics: Dict):
        """Update baseline statistics with new measurements"""
        current_time = time.time()

        # Only update baseline during learning period
        if current_time - self.start_time < self.learning_period:
            for metric, value in metrics.items():
                if metric in self.baseline_stats:
                    self.baseline_stats[metric].append(value)

                    # Keep only recent values (last 1000 measurements)
                    if len(self.baseline_stats[metric]) > 1000:
                        self.baseline_stats[metric] = self.baseline_stats[metric][-1000:]

    def calculate_adaptive_thresholds(self) -> Dict:
        """Calculate adaptive thresholds based on learned baselines"""
        new_thresholds = self.current_thresholds.copy()

        for metric, values in self.baseline_stats.items():
            if len(values) >= 10:  # Need sufficient data
                # Calculate statistical measures
                mean_val = np.mean(values)
                std_val = np.std(values)
                p95_val = np.percentile(values, 95)

                # Use 95th percentile + 2 standard deviations as threshold
                adaptive_threshold = max(p95_val, mean_val + 2 * std_val)

                # Apply adaptation factor for safety margin
                new_thresholds[metric] = adaptive_threshold * \
                    self.adaptation_factor

        self.current_thresholds = new_thresholds
        return new_thresholds


class MLAnomalyDetector:
    """
    Machine learning-based anomaly detector for ARP traffic patterns
    """

    def __init__(self):
        self.model = None
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.features_buffer = collections.deque(maxlen=10000)
        self.training_size = 1000
        self.retrain_interval = 3600  # Retrain every hour
        self.last_training = 0
        self.is_trained = False

    def extract_features(self, packet_info: Dict, traffic_stats: Dict) -> List[float]:
        """Extract features for ML model"""
        features = [
            # Time-based features
            datetime.now().hour / 24.0,  # Hour of day
            datetime.now().weekday() / 7.0,  # Day of week

            # Traffic volume features
            traffic_stats.get('recent_packet_rate', 0) / 100.0,
            traffic_stats.get('recent_sender_count', 0) / 50.0,

            # Packet characteristics
            1.0 if packet_info.get('is_gratuitous', False) else 0.0,
            packet_info.get('operation', 1) / 2.0,  # Normalize operation type

            # Network features
            len(packet_info.get('src_ip_str', '').split('.')) /
            4.0,  # IP validity indicator
            packet_info.get('anomaly_score', 0.0),

            # Historical features
            traffic_stats.get('mac_change_frequency', 0) / 10.0,
            traffic_stats.get('ip_entropy', 0) / 10.0
        ]

        return features

    def add_sample(self, features: List[float], is_anomaly: bool = False):
        """Add training sample"""
        if ML_AVAILABLE:
            self.features_buffer.append((features, is_anomaly))

    def train_model(self) -> bool:
        """Train the anomaly detection model"""
        if not ML_AVAILABLE or len(self.features_buffer) < self.training_size:
            return False

        try:
            # Prepare training data (use only normal samples for unsupervised learning)
            features = [sample[0] for sample in list(
                self.features_buffer) if not sample[1]]

            if len(features) < 100:  # Need minimum normal samples
                return False

            X = np.array(features)

            # Scale features
            X_scaled = self.scaler.fit_transform(X)

            # Train Isolation Forest
            self.model = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            self.model.fit(X_scaled)

            self.is_trained = True
            self.last_training = time.time()

            return True

        except Exception as e:
            print(f"Error training ML model: {e}")
            return False

    def predict_anomaly(self, features: List[float]) -> Tuple[bool, float]:
        """Predict if sample is anomalous"""
        if not ML_AVAILABLE or not self.is_trained or not self.model:
            return False, 0.0

        try:
            X = np.array([features])
            X_scaled = self.scaler.transform(X)

            # Get prediction and anomaly score
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.decision_function(X_scaled)[0]

            # Isolation Forest returns -1 for anomalies, 1 for normal
            is_anomaly = (prediction == -1)

            # Convert score to 0-1 range (lower scores = more anomalous)
            anomaly_score = max(0, min(1, (1 - score) / 2))

            return is_anomaly, anomaly_score

        except Exception as e:
            print(f"Error in ML prediction: {e}")
            return False, 0.0

    def should_retrain(self) -> bool:
        """Check if model should be retrained"""
        return (time.time() - self.last_training) > self.retrain_interval


class ThreatIntelligence:
    """
    Threat intelligence and attack pattern recognition
    """

    def __init__(self):
        self.attack_patterns = {
            'arp_storm': {
                'indicators': ['high_packet_rate', 'multiple_senders', 'gratuitous_arp'],
                'threshold_score': 0.8,
                'mitigation': ['rate_limit', 'blacklist_source']
            },
            'arp_poisoning': {
                'indicators': ['mac_spoofing', 'targeted_replies', 'mitm_pattern'],
                'threshold_score': 0.7,
                'mitigation': ['static_arp', 'alert_admin']
            },
            'arp_flooding': {
                'indicators': ['packet_flood', 'broadcast_storm', 'resource_exhaustion'],
                'threshold_score': 0.6,
                'mitigation': ['global_rate_limit', 'network_isolation']
            }
        }

        self.known_malicious_patterns = set()
        self.attack_history = collections.deque(maxlen=1000)

    def analyze_attack_pattern(self, traffic_data: Dict) -> Dict:
        """Analyze traffic data to identify attack patterns"""
        pattern_scores = {}
        detected_indicators = []

        # Check for ARP storm indicators
        if traffic_data.get('packet_rate', 0) > 50:
            detected_indicators.append('high_packet_rate')

        if traffic_data.get('unique_senders', 0) > 20:
            detected_indicators.append('multiple_senders')

        if traffic_data.get('gratuitous_ratio', 0) > 0.7:
            detected_indicators.append('gratuitous_arp')

        # Check for MAC spoofing
        if traffic_data.get('mac_changes', 0) > 3:
            detected_indicators.append('mac_spoofing')

        # Calculate pattern scores
        for pattern_name, pattern_info in self.attack_patterns.items():
            score = 0.0
            matching_indicators = 0

            for indicator in pattern_info['indicators']:
                if indicator in detected_indicators:
                    matching_indicators += 1

            if len(pattern_info['indicators']) > 0:
                score = matching_indicators / len(pattern_info['indicators'])

            pattern_scores[pattern_name] = score

        # Determine most likely attack type
        best_match = max(pattern_scores.items(), key=lambda x: x[1])
        attack_type = best_match[0] if best_match[1] >= self.attack_patterns[best_match[0]
                                                                             ]['threshold_score'] else 'unknown'

        return {
            'attack_type': attack_type,
            'confidence': best_match[1],
            'indicators': detected_indicators,
            'pattern_scores': pattern_scores,
            'recommended_mitigations': self.attack_patterns.get(attack_type, {}).get('mitigation', [])
        }

    def update_threat_intelligence(self, attack_info: Dict):
        """Update threat intelligence with new attack information"""
        attack_record = {
            'timestamp': time.time(),
            'attack_type': attack_info.get('attack_type'),
            'source_ip': attack_info.get('source_ip'),
            'source_mac': attack_info.get('source_mac'),
            'confidence': attack_info.get('confidence', 0),
            'indicators': attack_info.get('indicators', [])
        }

        self.attack_history.append(attack_record)

        # Update malicious patterns
        if attack_info.get('confidence', 0) > 0.8:
            pattern_hash = self._generate_pattern_hash(attack_info)
            self.known_malicious_patterns.add(pattern_hash)

    def _generate_pattern_hash(self, attack_info: Dict) -> str:
        """Generate hash for attack pattern"""
        pattern_str = f"{attack_info.get('attack_type', '')}_" \
            f"{len(attack_info.get('indicators', []))}_" \
            f"{attack_info.get('confidence', 0):.2f}"

        import hashlib
        return hashlib.md5(pattern_str.encode()).hexdigest()[:16]


class AutoRecoverySystem:
    """
    Automatic network recovery after attacks
    """

    def __init__(self):
        self.recovery_actions = {
            'clear_arp_cache': self._clear_arp_cache,
            'reset_static_entries': self._reset_static_entries,
            'restore_connectivity': self._restore_connectivity,
            'validate_network': self._validate_network
        }
        self.recovery_history = []

    def initiate_recovery(self, attack_type: str) -> Dict:
        """Initiate automatic recovery sequence"""
        recovery_plan = self._get_recovery_plan(attack_type)
        results = {}

        for action in recovery_plan:
            if action in self.recovery_actions:
                try:
                    result = self.recovery_actions[action]()
                    results[action] = {'success': True, 'result': result}
                except Exception as e:
                    results[action] = {'success': False, 'error': str(e)}

        recovery_record = {
            'timestamp': time.time(),
            'attack_type': attack_type,
            'actions_performed': list(results.keys()),
            'success_rate': sum(1 for r in results.values() if r['success']) / len(results),
            'results': results
        }

        self.recovery_history.append(recovery_record)
        return recovery_record

    def _get_recovery_plan(self, attack_type: str) -> List[str]:
        """Get recovery plan for specific attack type"""
        plans = {
            'arp_storm': ['clear_arp_cache', 'reset_static_entries', 'validate_network'],
            'arp_poisoning': ['reset_static_entries', 'restore_connectivity', 'validate_network'],
            'arp_flooding': ['clear_arp_cache', 'restore_connectivity', 'validate_network'],
            'unknown': ['validate_network']
        }

        return plans.get(attack_type, plans['unknown'])

    def _clear_arp_cache(self) -> str:
        """Clear ARP cache"""
        import subprocess
        try:
            # Clear ARP cache (requires root)
            result = subprocess.run(['ip', 'neigh', 'flush', 'all'],
                                    capture_output=True, text=True, timeout=10)
            return f"ARP cache cleared: {result.returncode == 0}"
        except Exception as e:
            return f"Failed to clear ARP cache: {e}"

    def _reset_static_entries(self) -> str:
        """Reset static ARP entries"""
        # This would integrate with the main defense engine
        return "Static ARP entries reset (placeholder)"

    def _restore_connectivity(self) -> str:
        """Restore network connectivity"""
        # This would implement connectivity restoration logic
        return "Connectivity restoration initiated (placeholder)"

    def _validate_network(self) -> str:
        """Validate network state after recovery"""
        # This would implement network validation logic
        return "Network validation completed (placeholder)"


class DefenseCoordinator:
    """
    Coordinates multiple defense strategies and systems
    """

    def __init__(self):
        self.threshold_manager = AdaptiveThresholdManager()
        self.ml_detector = MLAnomalyDetector() if ML_AVAILABLE else None
        self.threat_intel = ThreatIntelligence()
        self.recovery_system = AutoRecoverySystem()

        self.defense_state = {
            'mode': 'learning',  # learning, protecting, recovering
            'threat_level': 'low',  # low, medium, high, critical
            'active_defenses': set(),
            'last_update': time.time()
        }

    def process_traffic_sample(self, packet_info: Dict, traffic_stats: Dict) -> Dict:
        """Process a traffic sample through all defense systems"""

        # Update adaptive thresholds
        metrics = {
            'packets_per_second': traffic_stats.get('packet_rate', 0),
            'unique_senders_per_minute': traffic_stats.get('sender_count', 0),
            'gratuitous_ratio': traffic_stats.get('gratuitous_ratio', 0),
            'mac_changes_per_ip': traffic_stats.get('mac_changes', 0)
        }
        self.threshold_manager.update_baseline(metrics)

        # ML anomaly detection
        ml_result = {'is_anomaly': False, 'score': 0.0}
        if self.ml_detector:
            features = self.ml_detector.extract_features(
                packet_info, traffic_stats)
            self.ml_detector.add_sample(features)

            if self.ml_detector.is_trained:
                ml_result['is_anomaly'], ml_result['score'] = self.ml_detector.predict_anomaly(
                    features)
            elif self.ml_detector.should_retrain():
                self.ml_detector.train_model()

        # Threat intelligence analysis
        threat_analysis = self.threat_intel.analyze_attack_pattern(
            traffic_stats)

        # Combine all analyses
        combined_analysis = {
            'timestamp': time.time(),
            'packet_info': packet_info,
            'traffic_stats': traffic_stats,
            'ml_analysis': ml_result,
            'threat_analysis': threat_analysis,
            'adaptive_thresholds': self.threshold_manager.current_thresholds,
            'defense_recommendations': self._generate_defense_recommendations(
                ml_result, threat_analysis
            )
        }

        # Update defense state
        self._update_defense_state(combined_analysis)

        return combined_analysis

    def _generate_defense_recommendations(self, ml_result: Dict, threat_analysis: Dict) -> List[str]:
        """Generate defense recommendations based on analysis"""
        recommendations = []

        # ML-based recommendations
        if ml_result['is_anomaly'] and ml_result['score'] > 0.7:
            recommendations.append('ml_based_blocking')

        # Threat intelligence recommendations
        recommendations.extend(threat_analysis.get(
            'recommended_mitigations', []))

        # Adaptive threshold recommendations
        if threat_analysis.get('confidence', 0) > 0.8:
            recommendations.append('adaptive_threshold_update')

        return list(set(recommendations))  # Remove duplicates

    def _update_defense_state(self, analysis: Dict):
        """Update overall defense system state"""

        # Determine threat level
        ml_score = analysis['ml_analysis']['score']
        threat_confidence = analysis['threat_analysis']['confidence']

        max_threat = max(ml_score, threat_confidence)

        if max_threat > 0.9:
            self.defense_state['threat_level'] = 'critical'
        elif max_threat > 0.7:
            self.defense_state['threat_level'] = 'high'
        elif max_threat > 0.5:
            self.defense_state['threat_level'] = 'medium'
        else:
            self.defense_state['threat_level'] = 'low'

        # Update defense mode
        if self.defense_state['threat_level'] in ['high', 'critical']:
            self.defense_state['mode'] = 'protecting'
        elif self.defense_state['threat_level'] == 'medium':
            self.defense_state['mode'] = 'monitoring'
        else:
            self.defense_state['mode'] = 'learning'

        self.defense_state['last_update'] = time.time()

    def get_defense_status(self) -> Dict:
        """Get current defense system status"""
        return {
            'defense_state': self.defense_state.copy(),
            'adaptive_thresholds': self.threshold_manager.current_thresholds,
            'ml_trained': self.ml_detector.is_trained if self.ml_detector else False,
            'threat_patterns': len(self.threat_intel.known_malicious_patterns),
            'recovery_actions': len(self.recovery_system.recovery_history)
        }
