import json
import os
from typing import Dict, Any
import cohere
from dotenv import load_dotenv
from analytics_engine import NetworkAnalyticsEngine

# Load environment variables
load_dotenv()


class AnalyticsLLMInterface:
    """
    Interface to pass DuckDB analytics results to LLM for interpretation.
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize the LLM interface.
        
        Args:
            api_key: Cohere API key. If None, will try to get from environment variable.
        """
        self.api_key = api_key or os.getenv('COHERE_API_KEY')
        if not self.api_key:
            print("⚠️  Warning: No Cohere API key found. Set COHERE_API_KEY environment variable.")
            print("   You can get an API key from: https://dashboard.cohere.ai/api-keys")
        
        self.cohere_client = cohere.Client(self.api_key) if self.api_key else None
    
    def format_analytics_for_llm(self, analytics_results: Dict[str, Any]) -> str:
        """
        Format analytics results into a structured prompt for LLM analysis.
        
        Args:
            analytics_results: Results from NetworkAnalyticsEngine
            
        Returns:
            Formatted prompt string
        """
        prompt = """
You are a cybersecurity analyst reviewing network analytics results from a large dataset. Please provide insights and recommendations based on the following data:

## Dataset Overview
"""
        
        # Basic Statistics
        if 'basic_statistics' in analytics_results:
            stats = analytics_results['basic_statistics']
            prompt += f"""
### Basic Statistics
- Total Events: {stats.get('total_events', 'Unknown'):,}
- Unique Source IPs: {stats.get('unique_sources', 'Unknown'):,}
- Unique Destination IPs: {stats.get('unique_destinations', 'Unknown'):,}
- Time Range: {stats.get('time_range', 'Unknown')}

### Event Type Distribution:
"""
            if stats.get('event_types'):
                for event in stats['event_types'][:5]:  # Top 5
                    prompt += f"- {event['event_type']}: {event['count']:,} events\n"
            
            prompt += "\n### Protocol Distribution:\n"
            if stats.get('protocols'):
                for proto in stats['protocols'][:5]:  # Top 5
                    prompt += f"- {proto['proto']}: {proto['count']:,} events\n"
        
        # Security Analysis
        if 'security_analysis' in analytics_results:
            security = analytics_results['security_analysis']
            prompt += "\n## Security Analysis\n"
            
            if security.get('alert_severity'):
                prompt += "\n### Alert Severity Distribution:\n"
                for alert in security['alert_severity']:
                    prompt += f"- Severity {alert['severity']}: {alert['count']:,} alerts\n"
            
            if security.get('top_signatures'):
                prompt += "\n### Top Alert Signatures:\n"
                for sig in security['top_signatures'][:5]:
                    prompt += f"- {sig['signature']}: {sig['count']:,} occurrences\n"
            
            if security.get('top_source_ips'):
                prompt += "\n### Most Active Source IPs:\n"
                for ip in security['top_source_ips'][:5]:
                    prompt += f"- {ip['src_ip']}: {ip['event_count']:,} events\n"
            
            if security.get('suspicious_ports'):
                prompt += "\n### Suspicious Port Activity:\n"
                for port in security['suspicious_ports'][:5]:
                    prompt += f"- Port {port['dest_port']}: {port['connection_count']:,} connections\n"
        
        # Traffic Patterns
        if 'traffic_patterns' in analytics_results:
            traffic = analytics_results['traffic_patterns']
            prompt += "\n## Traffic Patterns\n"
            
            if traffic.get('top_destinations'):
                prompt += "\n### Most Targeted Destinations:\n"
                for dest in traffic['top_destinations'][:5]:
                    prompt += f"- {dest['dest_ip']}: {dest['connection_count']:,} connections\n"
            
            if traffic.get('port_analysis'):
                prompt += "\n### Port Usage Analysis:\n"
                for port in traffic['port_analysis'][:5]:
                    prompt += f"- Port {port['dest_port']}: {port['connection_count']:,} connections from {port['unique_sources']} unique sources\n"
        
        prompt += """

## Analysis Request
Please provide a comprehensive security assessment including:

1. **Threat Assessment**: Identify potential security threats and attack patterns
2. **Risk Analysis**: Evaluate the severity and impact of identified issues
3. **Behavioral Analysis**: Analyze unusual patterns in network traffic
4. **Recommendations**: Provide specific, actionable security recommendations
5. **Priority Actions**: List immediate actions that should be taken

Focus on practical insights that a security team can act upon. Highlight any anomalies or concerning patterns in the data.
"""
        
        return prompt
    
    def analyze_with_llm(self, analytics_results: Dict[str, Any]) -> str:
        """
        Send analytics results to LLM for interpretation.
        
        Args:
            analytics_results: Results from NetworkAnalyticsEngine
            
        Returns:
            LLM analysis and recommendations
        """
        if not self.api_key or not self.cohere_client:
            raise Exception("Cohere API key is required for LLM analysis")
        
        prompt = self.format_analytics_for_llm(analytics_results)
        
        try:
            print("🤖 Sending analytics results to LLM for interpretation...")
            
            response = self.cohere_client.generate(
                model='command',
                prompt=prompt,
                max_tokens=3000,
                temperature=0.3,
                k=0,
                stop_sequences=[],
                return_likelihoods='NONE'
            )
            
            analysis = response.generations[0].text.strip()
            print("✅ LLM analysis completed successfully")
            return analysis
            
        except Exception as e:
            raise Exception(f"LLM analysis failed: {e}")
    
    def generate_full_report(self, json_file_path: str, output_path: str = None) -> Dict[str, Any]:
        """
        Complete pipeline: Load data -> Run analytics -> Get LLM insights.
        
        Args:
            json_file_path: Path to the JSON data file
            output_path: Optional path to save the complete report
            
        Returns:
            Complete report with analytics and LLM insights
        """
        print("🚀 Starting complete analytics pipeline...")
        
        # Initialize analytics engine
        engine = NetworkAnalyticsEngine()
        
        try:
            # Load data
            load_stats = engine.load_json_data(json_file_path)
            
            # Run analytics
            analytics_results = engine.generate_comprehensive_report()
            
            # Get LLM insights
            llm_insights = self.analyze_with_llm(analytics_results)
            
            # Combine everything
            complete_report = {
                "load_statistics": load_stats,
                "analytics_results": analytics_results,
                "llm_insights": llm_insights,
                "pipeline_metadata": {
                    "source_file": json_file_path,
                    "processing_complete": True
                }
            }
            
            # Save if output path provided
            if output_path:
                engine.export_results(complete_report, output_path)
            
            return complete_report
            
        finally:
            engine.close()


def main():
    """Example usage of the LLM interface."""
    interface = AnalyticsLLMInterface()
    
    # Example: Process a large JSON file
    # report = interface.generate_full_report(
    #     json_file_path="large_network_data.jsonl",
    #     output_path="complete_analysis_report.json"
    # )
    
    print("🎯 LLM interface ready for analytics processing!")


if __name__ == "__main__":
    main()
