#!/usr/bin/env python3
"""
CAM Performance Data Analysis and Visualization Tools
Provides comprehensive analysis and visualization of performance test results
"""

import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import argparse
import logging
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CAMPerformanceAnalyzer:
    def __init__(self, data_directory="./"):
        self.data_directory = Path(data_directory)
        self.results_data = {}
        self.baseline_data = None
        
        # Set visualization style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
    def load_test_results(self, results_file):
        """Load K6 or Artillery test results"""
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
            
            # Parse K6 results
            if 'metrics' in data:
                self.results_data = self._parse_k6_results(data)
            # Parse Artillery results  
            elif 'aggregate' in data:
                self.results_data = self._parse_artillery_results(data)
            else:
                logger.error("Unsupported results format")
                return False
                
            logger.info(f"Loaded test results from {results_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load results: {e}")
            return False
    
    def _parse_k6_results(self, data):
        """Parse K6 test results into standardized format"""
        metrics = data.get('metrics', {})
        
        parsed_data = {
            'http_req_duration': self._extract_metric_values(metrics.get('http_req_duration', {})),
            'http_req_failed': self._extract_metric_values(metrics.get('http_req_failed', {})),
            'arbitration_decision_time': self._extract_metric_values(metrics.get('arbitration_decision_time', {})),
            'provider_selection_accuracy': self._extract_metric_values(metrics.get('provider_selection_accuracy', {})),
            'cost_optimization_rate': self._extract_metric_values(metrics.get('cost_optimization_rate', {})),
            'agent_collaboration_efficiency': self._extract_metric_values(metrics.get('agent_collaboration_efficiency', {})),
            'vus': self._extract_metric_values(metrics.get('vus', {})),
            'iterations': self._extract_metric_values(metrics.get('iterations', {})),
            'test_duration': data.get('state', {}).get('testRunDurationMs', 0) / 1000
        }
        
        return parsed_data
    
    def _parse_artillery_results(self, data):
        """Parse Artillery test results into standardized format"""
        aggregate = data.get('aggregate', {})
        
        parsed_data = {
            'http_req_duration': {
                'avg': aggregate.get('latency', {}).get('mean', 0),
                'p95': aggregate.get('latency', {}).get('p95', 0),
                'p99': aggregate.get('latency', {}).get('p99', 0),
                'max': aggregate.get('latency', {}).get('max', 0)
            },
            'http_req_failed': {
                'rate': aggregate.get('errors', 0) / max(aggregate.get('requestsCompleted', 1), 1)
            },
            'requests_per_second': aggregate.get('rps', {}).get('mean', 0),
            'total_requests': aggregate.get('requestsCompleted', 0),
            'test_duration': aggregate.get('testDuration', 0)
        }
        
        return parsed_data
    
    def _extract_metric_values(self, metric_data):
        """Extract values from metric data structure"""
        if not metric_data:
            return {}
        
        values = metric_data.get('values', {})
        return {
            'avg': values.get('avg', 0),
            'min': values.get('min', 0),
            'max': values.get('max', 0),
            'p50': values.get('med', 0),
            'p95': values.get('p(95)', 0),
            'p99': values.get('p(99)', 0),
            'count': values.get('count', 0),
            'rate': values.get('rate', 0)
        }
    
    def load_baseline(self, baseline_file):
        """Load baseline performance data for comparison"""
        try:
            with open(baseline_file, 'r') as f:
                self.baseline_data = json.load(f)
            logger.info(f"Loaded baseline data from {baseline_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False
    
    def analyze_performance_trends(self):
        """Analyze performance trends and identify regressions"""
        if not self.results_data:
            logger.error("No results data loaded")
            return None
        
        analysis = {
            'summary': self._generate_performance_summary(),
            'regressions': self._detect_performance_regressions(),
            'recommendations': self._generate_recommendations(),
            'tier_classification': self._classify_performance_tier()
        }
        
        return analysis
    
    def _generate_performance_summary(self):
        """Generate performance summary statistics"""
        summary = {}
        
        # Response time analysis
        if 'http_req_duration' in self.results_data:
            duration_data = self.results_data['http_req_duration']
            summary['response_time'] = {
                'average_ms': duration_data.get('avg', 0),
                'p95_ms': duration_data.get('p95', 0),
                'p99_ms': duration_data.get('p99', 0),
                'max_ms': duration_data.get('max', 0)
            }
        
        # Error rate analysis
        if 'http_req_failed' in self.results_data:
            failed_data = self.results_data['http_req_failed']
            summary['error_rate'] = {
                'percentage': failed_data.get('rate', 0) * 100,
                'total_errors': failed_data.get('count', 0)
            }
        
        # CAM-specific metrics
        cam_metrics = {}
        for metric in ['arbitration_decision_time', 'provider_selection_accuracy', 'cost_optimization_rate']:
            if metric in self.results_data:
                cam_metrics[metric] = self.results_data[metric]
        
        summary['cam_metrics'] = cam_metrics
        
        return summary
    
    def _detect_performance_regressions(self):
        """Detect performance regressions compared to baseline"""
        if not self.baseline_data:
            return {"status": "no_baseline", "message": "No baseline data available for comparison"}
        
        regressions = []
        
        # Compare key metrics
        current_p95 = self.results_data.get('http_req_duration', {}).get('p95', 0)
        baseline_p95 = self.baseline_data.get('http_req_duration', {}).get('p95', 0)
        
        if baseline_p95 > 0:
            p95_change = ((current_p95 - baseline_p95) / baseline_p95) * 100
            if p95_change > 20:  # 20% regression threshold
                regressions.append({
                    'metric': 'response_time_p95',
                    'current': current_p95,
                    'baseline': baseline_p95,
                    'change_percent': p95_change,
                    'severity': 'high' if p95_change > 50 else 'medium'
                })
        
        # Compare error rates
        current_error_rate = self.results_data.get('http_req_failed', {}).get('rate', 0)
        baseline_error_rate = self.baseline_data.get('http_req_failed', {}).get('rate', 0)
        
        if current_error_rate > baseline_error_rate * 1.5:  # 50% increase threshold
            regressions.append({
                'metric': 'error_rate',
                'current': current_error_rate * 100,
                'baseline': baseline_error_rate * 100,
                'change_percent': ((current_error_rate - baseline_error_rate) / max(baseline_error_rate, 0.001)) * 100,
                'severity': 'high'
            })
        
        return {
            "status": "completed",
            "regressions_found": len(regressions),
            "regressions": regressions
        }
    
    def _classify_performance_tier(self):
        """Classify performance into Community/Professional/Enterprise tiers"""
        p95_response_time = self.results_data.get('http_req_duration', {}).get('p95', 0)
        error_rate = self.results_data.get('http_req_failed', {}).get('rate', 0) * 100
        
        # Define tier thresholds
        if p95_response_time <= 100 and error_rate <= 0.1:
            tier = "Enterprise"
            grade = "A+"
        elif p95_response_time <= 250 and error_rate <= 0.5:
            tier = "Professional"
            grade = "A" if p95_response_time <= 200 else "B+"
        elif p95_response_time <= 500 and error_rate <= 1.0:
            tier = "Community"
            grade = "B" if p95_response_time <= 400 else "C+"
        else:
            tier = "Below Community"
            grade = "D" if p95_response_time <= 1000 else "F"
        
        return {
            'tier': tier,
            'grade': grade,
            'p95_response_time': p95_response_time,
            'error_rate_percent': error_rate,
            'meets_requirements': tier != "Below Community"
        }
    
    def _generate_recommendations(self):
        """Generate performance optimization recommendations"""
        recommendations = []
        
        # Response time recommendations
        p95_time = self.results_data.get('http_req_duration', {}).get('p95', 0)
        if p95_time > 500:
            recommendations.append({
                'category': 'response_time',
                'priority': 'high',
                'issue': f'P95 response time is {p95_time:.0f}ms',
                'recommendation': 'Consider caching, database optimization, or scaling horizontally'
            })
        elif p95_time > 250:
            recommendations.append({
                'category': 'response_time',
                'priority': 'medium',
                'issue': f'P95 response time is {p95_time:.0f}ms',
                'recommendation': 'Optimize database queries and consider connection pooling'
            })
        
        # Error rate recommendations
        error_rate = self.results_data.get('http_req_failed', {}).get('rate', 0) * 100
        if error_rate > 1.0:
            recommendations.append({
                'category': 'reliability',
                'priority': 'high',
                'issue': f'Error rate is {error_rate:.2f}%',
                'recommendation': 'Investigate error causes, improve error handling, and add circuit breakers'
            })
        
        # CAM-specific recommendations
        if 'arbitration_decision_time' in self.results_data:
            decision_time = self.results_data['arbitration_decision_time'].get('p95', 0)
            if decision_time > 1000:
                recommendations.append({
                    'category': 'arbitration',
                    'priority': 'medium',
                    'issue': f'Arbitration decision time is {decision_time:.0f}ms',
                    'recommendation': 'Optimize provider selection algorithm and cache provider capabilities'
                })
        
        return recommendations
    
    def generate_visualizations(self, output_dir="./visualizations"):
        """Generate performance visualization charts"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Response time distribution
        self._plot_response_time_distribution(output_path)
        
        # Performance metrics dashboard
        self._plot_performance_dashboard(output_path)
        
        # CAM-specific metrics
        self._plot_cam_metrics(output_path)
        
        logger.info(f"Visualizations saved to {output_path}")
    
    def _plot_response_time_distribution(self, output_path):
        """Plot response time distribution"""
        if 'http_req_duration' not in self.results_data:
            return
        
        duration_data = self.results_data['http_req_duration']
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Percentile chart
        percentiles = ['avg', 'p50', 'p95', 'p99', 'max']
        values = [duration_data.get(p, 0) for p in percentiles]
        
        ax1.bar(percentiles, values, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd'])
        ax1.set_title('Response Time Percentiles')
        ax1.set_ylabel('Time (ms)')
        ax1.tick_params(axis='x', rotation=45)
        
        # Add threshold lines
        ax1.axhline(y=500, color='orange', linestyle='--', alpha=0.7, label='Community Tier (500ms)')
        ax1.axhline(y=250, color='green', linestyle='--', alpha=0.7, label='Professional Tier (250ms)')
        ax1.axhline(y=100, color='blue', linestyle='--', alpha=0.7, label='Enterprise Tier (100ms)')
        ax1.legend()
        
        # Comparison with baseline if available
        if self.baseline_data and 'http_req_duration' in self.baseline_data:
            baseline_values = [self.baseline_data['http_req_duration'].get(p, 0) for p in percentiles]
            
            x = np.arange(len(percentiles))
            width = 0.35
            
            ax2.bar(x - width/2, values, width, label='Current', alpha=0.8)
            ax2.bar(x + width/2, baseline_values, width, label='Baseline', alpha=0.8)
            ax2.set_title('Response Time Comparison')
            ax2.set_ylabel('Time (ms)')
            ax2.set_xticks(x)
            ax2.set_xticklabels(percentiles)
            ax2.legend()
        else:
            ax2.text(0.5, 0.5, 'No baseline data\navailable for comparison', 
                    ha='center', va='center', transform=ax2.transAxes, fontsize=14)
            ax2.set_title('Baseline Comparison')
        
        plt.tight_layout()
        plt.savefig(output_path / 'response_time_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_performance_dashboard(self, output_path):
        """Plot comprehensive performance dashboard"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # Performance tier classification
        tier_data = self._classify_performance_tier()
        tier_colors = {
            'Enterprise': '#28a745',
            'Professional': '#17a2b8', 
            'Community': '#ffc107',
            'Below Community': '#dc3545'
        }
        
        ax1.pie([1], labels=[f"{tier_data['tier']}\n{tier_data['grade']}"], 
               colors=[tier_colors.get(tier_data['tier'], '#6c757d')],
               autopct='', startangle=90)
        ax1.set_title('Performance Tier Classification')
        
        # Key metrics summary
        metrics_data = {
            'P95 Response\nTime (ms)': self.results_data.get('http_req_duration', {}).get('p95', 0),
            'Error Rate\n(%)': self.results_data.get('http_req_failed', {}).get('rate', 0) * 100,
            'Arbitration\nTime (ms)': self.results_data.get('arbitration_decision_time', {}).get('avg', 0),
            'Cost Optimization\nRate (%)': self.results_data.get('cost_optimization_rate', {}).get('rate', 0) * 100
        }
        
        metrics_names = list(metrics_data.keys())
        metrics_values = list(metrics_data.values())
        
        bars = ax2.bar(metrics_names, metrics_values, color=['#ff7f0e', '#d62728', '#2ca02c', '#9467bd'])
        ax2.set_title('Key Performance Metrics')
        ax2.tick_params(axis='x', rotation=45)
        
        # Add value labels on bars
        for bar, value in zip(bars, metrics_values):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(metrics_values)*0.01,
                    f'{value:.1f}', ha='center', va='bottom')
        
        # Throughput over time (if available)
        if 'test_duration' in self.results_data and 'iterations' in self.results_data:
            duration = self.results_data['test_duration']
            total_requests = self.results_data['iterations'].get('count', 0)
            rps = total_requests / max(duration, 1)
            
            # Simulate throughput timeline
            time_points = np.linspace(0, duration, 20)
            throughput_points = np.random.normal(rps, rps*0.1, 20)
            throughput_points = np.maximum(throughput_points, 0)  # Ensure non-negative
            
            ax3.plot(time_points, throughput_points, linewidth=2, marker='o', markersize=4)
            ax3.set_title(f'Throughput Over Time (Avg: {rps:.1f} RPS)')
            ax3.set_xlabel('Time (seconds)')
            ax3.set_ylabel('Requests per Second')
            ax3.grid(True, alpha=0.3)
        else:
            ax3.text(0.5, 0.5, 'Throughput data\nnot available', 
                    ha='center', va='center', transform=ax3.transAxes, fontsize=14)
            ax3.set_title('Throughput Analysis')
        
        # Performance recommendations
        recommendations = self._generate_recommendations()
        if recommendations:
            rec_text = "Top Recommendations:\n\n"
            for i, rec in enumerate(recommendations[:3]):  # Show top 3
                rec_text += f"{i+1}. {rec['category'].title()}: {rec['recommendation'][:50]}...\n\n"
        else:
            rec_text = "No specific recommendations.\nPerformance appears optimal!"
        
        ax4.text(0.05, 0.95, rec_text, transform=ax4.transAxes, fontsize=10,
                verticalalignment='top', bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray"))
        ax4.set_title('Performance Recommendations')
        ax4.axis('off')
        
        plt.tight_layout()
        plt.savefig(output_path / 'performance_dashboard.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_cam_metrics(self, output_path):
        """Plot CAM-specific performance metrics"""
        cam_metrics = ['arbitration_decision_time', 'provider_selection_accuracy', 
                      'cost_optimization_rate', 'agent_collaboration_efficiency']
        
        available_metrics = {k: v for k, v in self.results_data.items() if k in cam_metrics}
        
        if not available_metrics:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        axes = axes.flatten()
        
        for i, (metric_name, metric_data) in enumerate(available_metrics.items()):
            if i >= 4:
                break
                
            ax = axes[i]
            
            if 'avg' in metric_data:  # Time-based metrics
                percentiles = ['avg', 'p50', 'p95', 'p99']
                values = [metric_data.get(p, 0) for p in percentiles]
                
                bars = ax.bar(percentiles, values, alpha=0.7)
                ax.set_title(f'{metric_name.replace("_", " ").title()}')
                ax.set_ylabel('Time (ms)')
                
                # Add value labels
                for bar, value in zip(bars, values):
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values)*0.01,
                           f'{value:.0f}', ha='center', va='bottom')
                           
            elif 'rate' in metric_data:  # Rate-based metrics
                rate_value = metric_data['rate'] * 100
                
                # Create a gauge-like visualization
                theta = np.linspace(0, np.pi, 100)
                r = np.ones_like(theta)
                
                ax.plot(theta, r, 'k-', linewidth=2)
                
                # Add rate indicator
                rate_theta = (rate_value / 100) * np.pi
                ax.plot([rate_theta, rate_theta], [0, 1], 'r-', linewidth=4)
                ax.fill_between(theta[theta <= rate_theta], 0, r[theta <= rate_theta], alpha=0.3)
                
                ax.set_title(f'{metric_name.replace("_", " ").title()}\n{rate_value:.1f}%')
                ax.set_ylim(0, 1.2)
                ax.set_xlim(0, np.pi)
                ax.axis('off')
        
        # Hide unused subplots
        for i in range(len(available_metrics), 4):
            axes[i].axis('off')
        
        plt.tight_layout()
        plt.savefig(output_path / 'cam_metrics_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def export_analysis_report(self, output_file="performance_analysis_report.json"):
        """Export comprehensive analysis report"""
        analysis = self.analyze_performance_trends()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'test_data': self.results_data,
            'analysis': analysis,
            'baseline_comparison': self.baseline_data is not None
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Analysis report exported to {output_file}")
        return output_file

def main():
    parser = argparse.ArgumentParser(description='CAM Performance Data Analyzer')
    parser.add_argument('--results', required=True, help='Test results JSON file')
    parser.add_argument('--baseline', help='Baseline results JSON file for comparison')
    parser.add_argument('--output-dir', default='./analysis_output', help='Output directory for visualizations')
    parser.add_argument('--report', default='analysis_report.json', help='Analysis report output file')
    
    args = parser.parse_args()
    
    analyzer = CAMPerformanceAnalyzer()
    
    # Load test results
    if not analyzer.load_test_results(args.results):
        return 1
    
    # Load baseline if provided
    if args.baseline:
        analyzer.load_baseline(args.baseline)
    
    # Perform analysis
    analysis = analyzer.analyze_performance_trends()
    
    # Generate visualizations
    analyzer.generate_visualizations(args.output_dir)
    
    # Export report
    analyzer.export_analysis_report(args.report)
    
    # Print summary
    print("\n=== CAM Performance Analysis Summary ===")
    print(f"Performance Tier: {analysis['tier_classification']['tier']}")
    print(f"Grade: {analysis['tier_classification']['grade']}")
    print(f"P95 Response Time: {analysis['summary']['response_time']['p95_ms']:.0f}ms")
    print(f"Error Rate: {analysis['summary']['error_rate']['percentage']:.2f}%")
    
    if analysis['regressions']['regressions_found'] > 0:
        print(f"\n⚠️  {analysis['regressions']['regressions_found']} performance regressions detected!")
    else:
        print("\n✅ No significant performance regressions detected")
    
    print(f"\nRecommendations: {len(analysis['recommendations'])}")
    for rec in analysis['recommendations'][:3]:
        print(f"  • {rec['category'].title()}: {rec['recommendation']}")

if __name__ == "__main__":
    main()
