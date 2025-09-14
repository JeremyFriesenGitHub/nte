import duckdb
import pandas as pd
import numpy as np
from typing import Dict, Any, List
import json
import os
from pathlib import Path
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from scipy import stats
import warnings
warnings.filterwarnings('ignore')


class NetworkAnalyticsEngine:
    """
    DuckDB-powered analytics engine for processing large JSON network datasets.
    """
    
    def __init__(self, db_path: str = None):
        """
        Initialize the analytics engine with DuckDB.
        
        Args:
            db_path: Path to DuckDB database file. If None, uses in-memory database.
        """
        self.db_path = db_path or ":memory:"
        self.conn = duckdb.connect(self.db_path)
        self.setup_database()
    
    def setup_database(self):
        """Set up DuckDB with JSON extension and optimizations for large datasets."""
        # Install and load JSON extension
        self.conn.execute("INSTALL json")
        self.conn.execute("LOAD json")
        
        # Set memory and threading optimizations
        self.conn.execute("SET memory_limit='8GB'")
        self.conn.execute("SET threads=4")
        
        print("✅ DuckDB analytics engine initialized")
    
    def load_json_data(self, file_path: str, table_name: str = "network_events") -> Dict[str, Any]:
        """
        Load JSON data into DuckDB table with streaming for large files.
        
        Args:
            file_path: Path to JSON file (supports JSONL format)
            table_name: Name for the DuckDB table
            
        Returns:
            Dictionary with load statistics
        """
        start_time = time.time()
        file_size = Path(file_path).stat().st_size / (1024**3)  # Size in GB
        
        print(f"📊 Loading {file_size:.2f} GB JSON file into DuckDB...")
        
        try:
            # Load with simple approach first, then create a view with extracted columns
            query = f"""
            CREATE OR REPLACE TABLE {table_name}_raw AS 
            SELECT * FROM read_json_auto('{file_path}')
            """
            self.conn.execute(query)
            
            # Create a processed view with extracted columns
            try:
                processed_query = f"""
                CREATE OR REPLACE TABLE {table_name} AS 
                SELECT 
                    timestamp,
                    COALESCE(flow_id, 0) as flow_id,
                    event_type,
                    src_ip,
                    COALESCE(src_port, 0) as src_port,
                    dest_ip,
                    COALESCE(dest_port, 0) as dest_port,
                    proto,
                    COALESCE(alert.signature, 'Unknown') as signature,
                    COALESCE(alert.severity, 0) as severity,
                    COALESCE(alert.category, 'Unknown') as alert_category,
                    COALESCE(flow.bytes_toserver, 0) as bytes_sent,
                    COALESCE(flow.bytes_toclient, 0) as bytes_received,
                    COALESCE(flow.pkts_toserver, 0) as pkts_sent,
                    COALESCE(flow.pkts_toclient, 0) as pkts_received,
                    COALESCE(http.http_user_agent, '') as http_user_agent,
                    COALESCE(payload, '') as payload
                FROM {table_name}_raw
                """
                self.conn.execute(processed_query)
                # Drop the raw table
                self.conn.execute(f"DROP TABLE {table_name}_raw")
            except Exception as nested_e:
                print(f"Warning: Column extraction failed, using raw table: {nested_e}")
                # Rename raw table to main table
                self.conn.execute(f"ALTER TABLE {table_name}_raw RENAME TO {table_name}")
            
            # Get row count
            row_count = self.conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            
            load_time = time.time() - start_time
            
            stats = {
                "file_size_gb": file_size,
                "rows_loaded": row_count,
                "load_time_seconds": load_time,
                "rows_per_second": row_count / load_time if load_time > 0 else 0,
                "table_name": table_name
            }
            
            print(f"✅ Loaded {row_count:,} rows in {load_time:.2f}s ({stats['rows_per_second']:.0f} rows/sec)")
            return stats
            
        except Exception as e:
            print(f"❌ Error loading JSON data: {e}")
            raise
    
    def get_basic_statistics(self, table_name: str = "network_events") -> Dict[str, Any]:
        """
        Generate basic statistics about the dataset using pandas operations.
        
        Args:
            table_name: Name of the table to analyze
            
        Returns:
            Dictionary containing basic statistics
        """
        print("📈 Generating basic statistics with pandas...")
        
        try:
            # Get all data in one query
            df = self.conn.execute(f"SELECT * FROM {table_name}").df()
            
            # Check available columns and handle missing ones gracefully
            available_cols = df.columns.tolist()
            print(f"Available columns: {available_cols}")
            
            results = {
                "total_events": len(df),
                "event_types": [],
                "protocols": [],
                "time_range": None,
                "unique_sources": 0,
                "unique_destinations": 0
            }
            
            # Handle event_type column
            if 'event_type' in df.columns:
                event_counts = df['event_type'].value_counts().reset_index()
                event_counts.columns = ['event_type', 'count']
                results["event_types"] = event_counts.to_dict('records')
            
            # Handle proto column
            if 'proto' in df.columns:
                proto_counts = df['proto'].value_counts().reset_index()
                proto_counts.columns = ['proto', 'count']
                results["protocols"] = proto_counts.to_dict('records')
            
            # Handle timestamp
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                earliest = df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S')
                latest = df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
                results["time_range"] = f"{earliest} to {latest}"
            
            # Handle IP addresses
            if 'src_ip' in df.columns:
                results["unique_sources"] = df['src_ip'].nunique()
            if 'dest_ip' in df.columns:
                results["unique_destinations"] = df['dest_ip'].nunique()
            
            return results
            
        except Exception as e:
            print(f"⚠️  Warning: Could not generate basic statistics: {e}")
            return {
                "total_events": 0,
                "event_types": [],
                "protocols": [],
                "time_range": None,
                "unique_sources": 0,
                "unique_destinations": 0
            }
    
    def analyze_security_events(self, table_name: str = "network_events") -> Dict[str, Any]:
        """
        Analyze security-specific patterns using pandas operations.
        
        Args:
            table_name: Name of the table to analyze
            
        Returns:
            Dictionary containing security analysis results
        """
        print("🔒 Analyzing security events with pandas...")
        
        try:
            # Get all data in one query
            df = self.conn.execute(f"SELECT * FROM {table_name}").df()
            
            # Initialize results with safe defaults
            results = {
                "alert_severity": [],
                "top_signatures": [],
                "top_source_ips": [],
                "suspicious_ports": [],
                "failed_connections": 0,
                "anomaly_detection": [],
                "data_science_anomalies": []
            }
            
            if len(df) == 0:
                return results
            
            # Extract alert data from nested JSON structure
            if 'event_type' in df.columns:
                alert_df = df[df['event_type'] == 'alert'].copy()
                
                if len(alert_df) > 0:
                    # Extract severity from nested alert structure
                    if 'severity' in df.columns:
                        severity_counts = alert_df['severity'].value_counts()
                        results["alert_severity"] = [{'severity': k, 'count': v} for k, v in severity_counts.items()]
                    
                    # Extract signatures
                    if 'signature' in df.columns:
                        signature_counts = alert_df['signature'].value_counts().head(10)
                        results["top_signatures"] = [{'signature': k, 'count': v} for k, v in signature_counts.items()]
                    
                    # Count failed connections based on alert category
                    if 'alert_category' in df.columns:
                        attack_keywords = ['Attack', 'Scan', 'Trojan', 'Malware']
                        failed_connections = alert_df['alert_category'].str.contains('|'.join(attack_keywords), case=False, na=False).sum()
                        results["failed_connections"] = int(failed_connections)
            
            # Top source IPs
            if 'src_ip' in df.columns:
                top_source_ips = df['src_ip'].value_counts().head(10).reset_index()
                top_source_ips.columns = ['src_ip', 'event_count']
                results["top_source_ips"] = top_source_ips.to_dict('records')
            
            # Suspicious ports (excluding common ones)
            if 'dest_port' in df.columns:
                common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
                suspicious_ports = df[~df['dest_port'].isin(common_ports)]['dest_port'].value_counts().head(10).reset_index()
                suspicious_ports.columns = ['dest_port', 'connection_count']
                results["suspicious_ports"] = suspicious_ports.to_dict('records')
            
            # Add data science-based anomaly detection
            results['data_science_anomalies'] = self._detect_data_science_anomalies(table_name)
            
            return results
            
        except Exception as e:
            print(f"⚠️  Warning: Could not analyze security events: {e}")
            return {
                "alert_severity": [],
                "top_signatures": [],
                "top_source_ips": [],
                "suspicious_ports": [],
                "failed_connections": 0,
                "anomaly_detection": [],
                "data_science_anomalies": []
            }
    
    def _detect_data_science_anomalies(self, table_name: str) -> List[Dict[str, Any]]:
        """
        Detect anomalies using modern data science libraries (scikit-learn, scipy).
        
        Args:
            table_name: Name of the table to analyze
            
        Returns:
            List of detected anomalies with ML-based scoring
        """
        try:
            # Get all data in one query and handle missing columns gracefully
            df = self.conn.execute(f"SELECT * FROM {table_name}").df()
            
            if len(df) < 10:
                return [{"anomaly_type": "insufficient_data", "count": 0, "description": "Not enough data for ML analysis"}]
            
            # Extract hour from timestamp if available
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df['hour'] = df['timestamp'].dt.hour
            else:
                df['hour'] = 0
            
            # Extract flow data - use direct columns if available
            if 'bytes_sent' in df.columns:
                df['bytes_sent'] = pd.to_numeric(df['bytes_sent'], errors='coerce').fillna(0)
            else:
                df['bytes_sent'] = 0
                
            if 'bytes_received' in df.columns:
                df['bytes_received'] = pd.to_numeric(df['bytes_received'], errors='coerce').fillna(0)
            else:
                df['bytes_received'] = 0
            
            # Extract payload size
            if 'payload' in df.columns:
                df['payload_size'] = df['payload'].apply(lambda x: len(str(x)) if pd.notna(x) else 0)
            else:
                df['payload_size'] = 0
            
            # Create is_alert flag
            if 'event_type' in df.columns:
                df['is_alert'] = (df['event_type'] == 'alert').astype(int)
            else:
                df['is_alert'] = 0
            
            # Extract user agent from http_user_agent column if available
            if 'http_user_agent' in df.columns:
                df['user_agent'] = df['http_user_agent'].fillna('')
            else:
                df['user_agent'] = ''
            
            # Ensure dest_port exists
            if 'dest_port' not in df.columns:
                df['dest_port'] = 80  # Default port
            else:
                df['dest_port'] = pd.to_numeric(df['dest_port'], errors='coerce').fillna(80)
            
            anomalies = []
            
            # 1. Isolation Forest for multivariate anomaly detection
            numerical_features = ['hour', 'dest_port', 'bytes_sent', 'bytes_received', 'payload_size', 'is_alert']
            feature_data = df[numerical_features].fillna(0)
            
            if len(feature_data) > 0:
                # Standardize features
                scaler = StandardScaler()
                scaled_features = scaler.fit_transform(feature_data)
                
                # Apply Isolation Forest
                iso_forest = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
                outlier_labels = iso_forest.fit_predict(scaled_features)
                
                outlier_count = np.sum(outlier_labels == -1)
                if outlier_count > 0:
                    anomalies.append({
                        "anomaly_type": "isolation_forest_outliers",
                        "count": int(outlier_count),
                        "description": f"Multivariate outliers detected using Isolation Forest",
                        "anomaly_score": float(np.mean(iso_forest.score_samples(scaled_features)))
                    })
            
            # 2. Statistical outliers using Z-scores and IQR
            for column in ['bytes_sent', 'bytes_received', 'payload_size']:
                if column in df.columns and df[column].std() > 0:
                    # Z-score method
                    z_scores = np.abs(stats.zscore(df[column].fillna(0)))
                    z_outliers = np.sum(z_scores > 3)
                    
                    # IQR method
                    Q1 = df[column].quantile(0.25)
                    Q3 = df[column].quantile(0.75)
                    IQR = Q3 - Q1
                    iqr_outliers = np.sum((df[column] < (Q1 - 1.5 * IQR)) | (df[column] > (Q3 + 1.5 * IQR)))
                    
                    if z_outliers > 0:
                        anomalies.append({
                            "anomaly_type": f"{column}_z_score_outliers",
                            "count": int(z_outliers),
                            "description": f"Statistical outliers in {column} (Z-score > 3)",
                            "threshold": 3.0
                        })
                    
                    if iqr_outliers > 0:
                        anomalies.append({
                            "anomaly_type": f"{column}_iqr_outliers",
                            "count": int(iqr_outliers),
                            "description": f"Statistical outliers in {column} (IQR method)",
                            "iqr_bounds": [float(Q1 - 1.5 * IQR), float(Q3 + 1.5 * IQR)]
                        })
            
            # 3. DBSCAN clustering for behavioral anomalies
            if len(feature_data) > 20:  # Need sufficient data for clustering
                dbscan = DBSCAN(eps=0.5, min_samples=5)
                cluster_labels = dbscan.fit_predict(scaled_features)
                
                noise_points = np.sum(cluster_labels == -1)
                if noise_points > 0:
                    anomalies.append({
                        "anomaly_type": "dbscan_noise_points",
                        "count": int(noise_points),
                        "description": f"Behavioral outliers detected using DBSCAN clustering",
                        "n_clusters": int(len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0))
                    })
            
            # 4. Time series anomalies using rolling statistics
            hourly_stats = df.groupby('hour').agg({
                'bytes_sent': ['count', 'mean', 'std'],
                'is_alert': 'sum'
            }).fillna(0)
            
            hourly_stats.columns = ['event_count', 'avg_bytes', 'std_bytes', 'alert_count']
            
            if len(hourly_stats) > 3:
                # Rolling window anomalies
                window_size = min(3, len(hourly_stats) // 2)
                rolling_mean = hourly_stats['event_count'].rolling(window=window_size, center=True).mean()
                rolling_std = hourly_stats['event_count'].rolling(window=window_size, center=True).std().fillna(1)
                
                anomaly_threshold = 2.0
                deviations = np.abs(hourly_stats['event_count'] - rolling_mean)
                time_anomalies = np.sum(deviations > anomaly_threshold * rolling_std)
                
                if time_anomalies > 0:
                    anomalies.append({
                        "anomaly_type": "temporal_pattern_anomalies",
                        "count": int(time_anomalies),
                        "description": f"Unusual temporal patterns detected using rolling statistics",
                        "window_size": window_size
                    })
            
            # 5. Rule-based anomalies using pandas operations
            rule_anomalies = self._detect_rule_based_anomalies(df)
            anomalies.extend(rule_anomalies)
            
            return anomalies if anomalies else [{"anomaly_type": "no_ml_anomalies", "count": 0, "description": "No anomalies detected using ML methods"}]
            
        except Exception as e:
            print(f"⚠️  Warning: Data science anomaly detection failed: {e}")
            return [{"anomaly_type": "ml_analysis_error", "count": 0, "description": f"ML analysis failed: {str(e)}"}]
    
    def _detect_rule_based_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Detect rule-based anomalies using pandas operations.
        
        Args:
            df: DataFrame with network data
            
        Returns:
            List of rule-based anomalies
        """
        anomalies = []
        
        # Large payload anomalies
        large_payloads = df[df['payload_size'] > 10000]
        if len(large_payloads) > 0:
            anomalies.append({
                "anomaly_type": "oversized_payloads",
                "count": len(large_payloads),
                "description": f"Payloads larger than 10KB detected",
                "max_size": int(large_payloads['payload_size'].max())
            })
        
        # Suspicious user agents
        suspicious_ua = df[df['user_agent'].str.contains('nmap|sqlmap|bot|crawler|scanner', case=False, na=False)]
        if len(suspicious_ua) > 0:
            anomalies.append({
                "anomaly_type": "suspicious_user_agents",
                "count": len(suspicious_ua),
                "description": f"Suspicious user agents detected (scanners, bots, tools)",
                "unique_agents": suspicious_ua['user_agent'].nunique()
            })
        
        # Rare ports (ephemeral range)
        rare_ports = df[df['dest_port'] > 49152]
        if len(rare_ports) > 0:
            anomalies.append({
                "anomaly_type": "rare_ports",
                "count": len(rare_ports),
                "description": f"Connections to ephemeral ports (>49152)",
                "unique_ports": rare_ports['dest_port'].nunique()
            })
        
        # High-frequency sources (potential scanning)
        if 'src_ip' in df.columns:
            source_counts = df['src_ip'].value_counts()
            if len(source_counts) > 0:
                high_freq_threshold = source_counts.quantile(0.95)  # Top 5%
                high_freq_sources = source_counts[source_counts > high_freq_threshold]
                
                if len(high_freq_sources) > 0:
                    anomalies.append({
                        "anomaly_type": "high_frequency_sources",
                        "count": len(high_freq_sources),
                        "description": f"Source IPs with unusually high activity (top 5%)",
                        "max_events": int(high_freq_sources.max())
                    })
        
        return anomalies
    
    def analyze_traffic_patterns(self, table_name: str = "network_events") -> Dict[str, Any]:
        """
        Analyze network traffic patterns using pandas operations.
        
        Args:
            table_name: Name of the table to analyze
            
        Returns:
            Dictionary containing traffic analysis results
        """
        print("🌐 Analyzing traffic patterns with pandas...")
        
        try:
            # Get all data in one query
            df = self.conn.execute(f"SELECT * FROM {table_name}").df()
            
            # Initialize results with safe defaults
            results = {
                "hourly_distribution": [],
                "top_destinations": [],
                "protocol_distribution": [],
                "top_talkers_by_traffic": [],
                "top_alert_generators": [],
                "event_type_trends": [],
                "port_analysis": []
            }
            
            if len(df) == 0:
                return results
            
            # Hourly distribution - use timestamp if available, otherwise create default
            if 'timestamp' in df.columns:
                df_copy = df.copy()
                df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'])
                df_copy['hour'] = df_copy['timestamp'].dt.hour
                hourly_distribution = df_copy.groupby('hour').size().reset_index(name='event_count')
                # Sort by event count to show peak hours first
                hourly_distribution = hourly_distribution.sort_values('event_count', ascending=False)
                results["hourly_distribution"] = hourly_distribution.to_dict('records')
                
                # Event type trends
                if 'event_type' in df_copy.columns:
                    event_type_trends = df_copy.groupby(['hour', 'event_type']).size().reset_index(name='count')
                    results["event_type_trends"] = event_type_trends.to_dict('records')
            else:
                # Create default hourly distribution
                results["hourly_distribution"] = [{"hour": 12, "event_count": len(df)}]
            
            # Top destinations - force create if dest_ip exists
            if 'dest_ip' in df.columns:
                dest_counts = df['dest_ip'].value_counts()
                if len(dest_counts) > 0:
                    top_destinations = dest_counts.head(10).reset_index()
                    top_destinations.columns = ['dest_ip', 'connection_count']
                    results["top_destinations"] = top_destinations.to_dict('records')
            
            # Protocol distribution - force create if proto exists
            if 'proto' in df.columns:
                proto_counts = df['proto'].value_counts()
                if len(proto_counts) > 0:
                    protocol_distribution = proto_counts.head(10).reset_index()
                    protocol_distribution.columns = ['protocol', 'count']
                    results["protocol_distribution"] = protocol_distribution.to_dict('records')
            
            # Top talkers - use bytes if available, otherwise event count
            if 'src_ip' in df.columns and 'dest_ip' in df.columns:
                if 'bytes_sent' in df.columns and 'bytes_received' in df.columns:
                    # Calculate total bytes per connection
                    talker_stats = df.groupby(['src_ip', 'dest_ip']).agg({
                        'bytes_sent': 'sum',
                        'bytes_received': 'sum',
                        'src_ip': 'size'  # Count of events
                    }).reset_index()
                    talker_stats.columns = ['src_ip', 'dest_ip', 'bytes_sent', 'bytes_received', 'total_events']
                    talker_stats['total_bytes'] = talker_stats['bytes_sent'] + talker_stats['bytes_received']
                    top_talkers = talker_stats.nlargest(10, 'total_bytes')
                else:
                    # Fallback to event count
                    talker_counts = df.groupby(['src_ip', 'dest_ip']).size().reset_index(name='total_events')
                    top_talkers = talker_counts.nlargest(10, 'total_events')
                    top_talkers['bytes_sent'] = 0
                    top_talkers['bytes_received'] = 0
                
                results["top_talkers_by_traffic"] = top_talkers.to_dict('records')
            
            # Alert generators - force create if event_type and src_ip exist
            if 'event_type' in df.columns and 'src_ip' in df.columns:
                alert_events = df[df['event_type'].str.contains('alert', case=False, na=False)]
                if len(alert_events) > 0:
                    alert_generators = alert_events['src_ip'].value_counts().head(10).reset_index()
                    alert_generators.columns = ['src_ip', 'alert_count']
                    results["top_alert_generators"] = alert_generators.to_dict('records')
            
            # Port analysis - force create if dest_port and src_ip exist
            if 'dest_port' in df.columns and 'src_ip' in df.columns:
                port_stats = df.groupby('dest_port').agg({
                    'dest_port': 'size',
                    'src_ip': 'nunique'
                }).reset_index()
                port_stats.columns = ['dest_port', 'connection_count', 'unique_sources']
                if len(port_stats) > 0:
                    port_analysis = port_stats.nlargest(15, 'connection_count')
                    results["port_analysis"] = port_analysis.to_dict('records')
            
            return results
            
        except Exception as e:
            print(f"⚠️  Warning: Could not analyze traffic patterns: {e}")
            # Return empty results on error
            return {
                "hourly_distribution": [],
                "top_destinations": [],
                "protocol_distribution": [],
                "top_talkers_by_traffic": [],
                "top_alert_generators": [],
                "event_type_trends": [],
                "port_analysis": []
            }
    
    def run_custom_query(self, query: str) -> pd.DataFrame:
        """
        Execute a custom SQL query and return results as DataFrame.
        
        Args:
            query: SQL query string
            
        Returns:
            Pandas DataFrame with query results
        """
        try:
            return self.conn.execute(query).df()
        except Exception as e:
            print(f"❌ Error executing custom query: {e}")
            raise
    
    def generate_comprehensive_report(self, table_name: str = "network_events") -> Dict[str, Any]:
        """
        Generate a comprehensive analytics report.
        
        Args:
            table_name: Name of the table to analyze
            
        Returns:
            Dictionary containing all analysis results
        """
        print("📋 Generating comprehensive analytics report...")
        start_time = time.time()
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "table_name": table_name,
                "analysis_duration": None
            },
            "basic_statistics": self.get_basic_statistics(table_name),
            "security_analysis": self.analyze_security_events(table_name),
            "traffic_patterns": self.analyze_traffic_patterns(table_name)
        }
        
        report["metadata"]["analysis_duration"] = time.time() - start_time
        
        print(f"✅ Report generated in {report['metadata']['analysis_duration']:.2f} seconds")
        return report
    
    def export_results(self, results: Dict[str, Any], output_path: str):
        """
        Export analysis results to JSON file.
        
        Args:
            results: Analysis results dictionary
            output_path: Path to save the JSON file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"💾 Results exported to {output_path}")
        except Exception as e:
            print(f"❌ Error exporting results: {e}")
            raise
    
    def close(self):
        """Close the DuckDB connection."""
        if self.conn:
            self.conn.close()
            print("🔌 DuckDB connection closed")


def main():
    """Example usage of the analytics engine."""
    # Initialize engine
    engine = NetworkAnalyticsEngine()
    
    # Example: Load data and run analysis
    # engine.load_json_data("large_network_data.jsonl")
    # report = engine.generate_comprehensive_report()
    # engine.export_results(report, "network_analysis_report.json")
    
    print("🚀 Analytics engine ready for use!")


if __name__ == "__main__":
    main()
