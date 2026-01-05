#!/usr/bin/env python3
"""
Test script for the URL Analyzer ML model
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(__file__))
from url_analyzer import URLAnalyzer

def test_urls():
    """
    Test the ML model with various URLs
    """
    # Initialize the analyzer
    print("Initializing URL Analyzer...")
    analyzer = URLAnalyzer()
    
    # Test URLs (mix of benign and potentially malicious)
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "http://192.168.1.1/login",
        "https://suspicious-site.xyz/verify-account",
        "https://bit.ly/shortened-link",
        "https://fake-bank-login.tk/secure",
        "https://www.amazon.com",
        "https://malware-site.cc/download",
        "https://www.stackoverflow.com"
    ]
    
    print("\n" + "="*60)
    print("URL ANALYSIS RESULTS")
    print("="*60)
    
    for i, url in enumerate(test_urls, 1):
        print(f"\n{i}. Testing URL: {url}")
        print("-" * 50)
        
        try:
            # Get detailed analysis
            analysis = analyzer.get_detailed_analysis(url)
            
            # Print results
            prediction = analysis['prediction']
            print(f"Prediction: {prediction['prediction']}")
            print(f"Confidence: {prediction['confidence']:.3f}")
            print(f"Method: {prediction['method']}")
            
            if prediction['method'] == 'ml_model':
                print(f"Malicious Probability: {prediction['malicious_probability']:.3f}")
                print(f"Benign Probability: {prediction['benign_probability']:.3f}")
            
            # Print key features
            features = analysis['features']
            print(f"URL Length: {features['url_length']}")
            print(f"Domain Length: {features['domain_length']}")
            print(f"Uses HTTPS: {features['uses_https']}")
            print(f"Has Suspicious TLD: {features['has_suspicious_tld']}")
            print(f"Has IP in Domain: {features['has_ip_in_domain']}")
            print(f"Special Char Ratio: {features['special_char_ratio']:.3f}")
            
            # Print explanations
            if analysis['explanations']:
                print("Explanations:")
                for exp in analysis['explanations']:
                    print(f"  • {exp}")
            
        except Exception as e:
            print(f"Error analyzing URL: {e}")
        
        print("-" * 50)

def test_feature_extraction():
    """
    Test feature extraction specifically
    """
    print("\n" + "="*60)
    print("FEATURE EXTRACTION TEST")
    print("="*60)
    
    analyzer = URLAnalyzer()
    
    test_url = "https://suspicious-site.xyz/verify-account?redirect=true"
    print(f"Testing feature extraction for: {test_url}")
    
    features = analyzer.extract_features(test_url)
    
    print("\nExtracted Features:")
    for key, value in features.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    print("URL Analyzer ML Model Test")
    print("="*60)
    
    # Test feature extraction
    test_feature_extraction()
    
    # Test full analysis
    test_urls()
    
    print("\n" + "="*60)
    print("TEST COMPLETED")
    print("="*60)
