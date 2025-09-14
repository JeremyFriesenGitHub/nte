from flask import Flask, render_template, request, jsonify
import json
import os
import tempfile
from analytics_engine import NetworkAnalyticsEngine
from llm_interface import AnalyticsLLMInterface
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Initialize the analytics interface
llm_interface = AnalyticsLLMInterface()

@app.route('/')
def index():
    """Serve the main frontend page."""
    return render_template('index.html')

@app.route('/api/sample-data')
def get_sample_data():
    """Return the sample network data."""
    try:
        with open('sample_network_data.json', 'r', encoding='utf-8') as file:
            sample_data = json.load(file)
        return jsonify(sample_data)
    except FileNotFoundError:
        return jsonify({'error': 'Sample data file not found'}), 404
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid sample data file'}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_bulk_data():
    """Analyze bulk network data using DuckDB analytics + LLM."""
    try:
        # Get JSON data from request
        network_data = request.get_json()
        
        if not network_data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate that we have an API key
        if not llm_interface.api_key:
            return jsonify({'error': 'Cohere API key not configured. Please set COHERE_API_KEY environment variable.'}), 500
        
        # Create temporary file for the data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            json.dump(network_data, temp_file)
            temp_path = temp_file.name
        
        try:
            # Initialize analytics engine
            engine = NetworkAnalyticsEngine()
            
            # Load data into DuckDB
            load_stats = engine.load_json_data(temp_path)
            
            # Run comprehensive analytics
            analytics_results = engine.generate_comprehensive_report()
            
            # Get LLM insights
            llm_analysis = llm_interface.analyze_with_llm(analytics_results)
            
            # Combine results
            complete_report = {
                'load_statistics': load_stats,
                'analytics_results': analytics_results,
                'llm_analysis': llm_analysis,
                'success': True
            }
            
            return jsonify(complete_report)
            
        finally:
            # Clean up
            engine.close()
            os.unlink(temp_path)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics-only', methods=['POST'])
def run_analytics_only():
    """Run only DuckDB analytics without LLM analysis."""
    try:
        # Get JSON data from request
        network_data = request.get_json()
        
        if not network_data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Create temporary file for the data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            json.dump(network_data, temp_file)
            temp_path = temp_file.name
        
        try:
            # Initialize analytics engine
            engine = NetworkAnalyticsEngine()
            
            # Load data into DuckDB
            load_stats = engine.load_json_data(temp_path)
            
            # Run comprehensive analytics
            analytics_results = engine.generate_comprehensive_report()
            
            return jsonify({
                'load_statistics': load_stats,
                'analytics_results': analytics_results,
                'success': True
            })
            
        finally:
            # Clean up
            engine.close()
            os.unlink(temp_path)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'cohere_configured': bool(llm_interface.api_key)
    })

if __name__ == '__main__':
    # Check if API key is configured
    if not llm_interface.api_key:
        print("⚠️  Warning: No Cohere API key found. The analysis feature will not work.")
        print("   Set COHERE_API_KEY in your .env file or environment variables.")
    else:
        print("✅ Cohere API key configured successfully.")
    
    print("🌐 Starting Network Data Analyzer web application...")
    print("📍 Open your browser to: http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
