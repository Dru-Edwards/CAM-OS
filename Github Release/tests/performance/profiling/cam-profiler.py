#!/usr/bin/env python3
"""
CAM Performance Profiler - Memory and CPU Analysis Tool
Provides comprehensive profiling capabilities for the Complete Arbitration Mesh system
"""

import psutil
import time
import json
import csv
import argparse
import requests
import threading
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CAMPerformanceProfiler:
    def __init__(self, cam_base_url="http://localhost:3000", api_token=None):
        self.cam_base_url = cam_base_url
        self.api_token = api_token
        self.monitoring = False
        self.data_points = deque(maxlen=10000)  # Store last 10k data points
        self.start_time = None
        
        # Performance thresholds
        self.thresholds = {
            'cpu_warning': 70.0,
            'cpu_critical': 85.0,
            'memory_warning': 75.0,
            'memory_critical': 90.0,
            'response_time_warning': 2000,  # ms
            'response_time_critical': 5000  # ms
        }
        
    def start_monitoring(self, duration_seconds=300, interval_seconds=1):
        """Start system monitoring for specified duration"""
        self.monitoring = True
        self.start_time = datetime.now()
        
        logger.info(f"Starting performance monitoring for {duration_seconds} seconds")
        
        monitor_thread = threading.Thread(
            target=self._monitor_system_metrics,
            args=(duration_seconds, interval_seconds)
        )
        monitor_thread.start()
        
        return monitor_thread
    
    def _monitor_system_metrics(self, duration, interval):
        """Monitor system metrics continuously"""
        end_time = datetime.now() + timedelta(seconds=duration)
        
        while datetime.now() < end_time and self.monitoring:
            timestamp = datetime.now()
            
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            network_io = psutil.net_io_counters()
            
            # CAM-specific metrics
            cam_metrics = self._get_cam_metrics()
            
            data_point = {
                'timestamp': timestamp.isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': memory.available / (1024**3),
                'memory_used_gb': memory.used / (1024**3),
                'disk_read_mb': disk_io.read_bytes / (1024**2) if disk_io else 0,
                'disk_write_mb': disk_io.write_bytes / (1024**2) if disk_io else 0,
                'network_sent_mb': network_io.bytes_sent / (1024**2) if network_io else 0,
                'network_recv_mb': network_io.bytes_recv / (1024**2) if network_io else 0,
                **cam_metrics
            }
            
            self.data_points.append(data_point)
            
            # Check thresholds and log warnings
            self._check_thresholds(data_point)
            
            time.sleep(interval)
    
    def _get_cam_metrics(self):
        """Get CAM-specific performance metrics"""
        try:
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Bearer {self.api_token}'
            
            # Get system status
            status_response = requests.get(
                f"{self.cam_base_url}/api/v1/status",
                headers=headers,
                timeout=5
            )
            
            # Get performance metrics
            metrics_response = requests.get(
                f"{self.cam_base_url}/api/v1/metrics/performance",
                headers=headers,
                timeout=5
            )
            
            cam_metrics = {}
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                cam_metrics.update({
                    'cam_status': status_data.get('status', 'unknown'),
                    'active_connections': status_data.get('connections', 0),
                    'uptime_seconds': status_data.get('uptime', 0)
                })
            
            if metrics_response.status_code == 200:
                metrics_data = metrics_response.json()
                cam_metrics.update({
                    'arbitration_requests_per_second': metrics_data.get('rps', 0),
                    'average_response_time_ms': metrics_data.get('avg_response_time', 0),
                    'p95_response_time_ms': metrics_data.get('p95_response_time', 0),
                    'error_rate_percent': metrics_data.get('error_rate', 0),
                    'active_arbitrations': metrics_data.get('active_arbitrations', 0),
                    'provider_health_score': metrics_data.get('provider_health', 1.0),
                    'cost_optimization_rate': metrics_data.get('cost_optimization_rate', 0)
                })
            
            return cam_metrics
            
        except Exception as e:
            logger.warning(f"Failed to get CAM metrics: {e}")
            return {
                'cam_status': 'unreachable',
                'active_connections': 0,
                'arbitration_requests_per_second': 0,
                'average_response_time_ms': 0,
                'error_rate_percent': 100
            }
    
    def _check_thresholds(self, data_point):
        """Check performance thresholds and log warnings"""
        if data_point['cpu_percent'] > self.thresholds['cpu_critical']:
            logger.critical(f"CRITICAL: CPU usage at {data_point['cpu_percent']:.1f}%")
        elif data_point['cpu_percent'] > self.thresholds['cpu_warning']:
            logger.warning(f"WARNING: CPU usage at {data_point['cpu_percent']:.1f}%")
        
        if data_point['memory_percent'] > self.thresholds['memory_critical']:
            logger.critical(f"CRITICAL: Memory usage at {data_point['memory_percent']:.1f}%")
        elif data_point['memory_percent'] > self.thresholds['memory_warning']:
            logger.warning(f"WARNING: Memory usage at {data_point['memory_percent']:.1f}%")
        
        avg_response_time = data_point.get('average_response_time_ms', 0)
        if avg_response_time > self.thresholds['response_time_critical']:
            logger.critical(f"CRITICAL: Response time at {avg_response_time:.0f}ms")
        elif avg_response_time > self.thresholds['response_time_warning']:
            logger.warning(f"WARNING: Response time at {avg_response_time:.0f}ms")
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.monitoring = False
        logger.info("Stopping performance monitoring")
    
    def export_data(self, filename_prefix="cam_performance"):
        """Export collected data to files"""
        if not self.data_points:
            logger.warning("No data points to export")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export to JSON
        json_filename = f"{filename_prefix}_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(list(self.data_points), f, indent=2)
        logger.info(f"Exported JSON data to {json_filename}")
        
        # Export to CSV
        csv_filename = f"{filename_prefix}_{timestamp}.csv"
        if self.data_points:
            fieldnames = self.data_points[0].keys()
            with open(csv_filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.data_points)
            logger.info(f"Exported CSV data to {csv_filename}")
        
        return json_filename, csv_filename
    
    def generate_report(self, filename_prefix="cam_performance_report"):
        """Generate performance analysis report"""
        if not self.data_points:
            logger.warning("No data points for report generation")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{filename_prefix}_{timestamp}.html"
        
        # Calculate statistics
        cpu_values = [dp['cpu_percent'] for dp in self.data_points]
        memory_values = [dp['memory_percent'] for dp in self.data_points]
        response_times = [dp.get('average_response_time_ms', 0) for dp in self.data_points]
        
        stats = {
            'duration_minutes': len(self.data_points) / 60,
            'cpu_avg': np.mean(cpu_values),
            'cpu_max': np.max(cpu_values),
            'cpu_p95': np.percentile(cpu_values, 95),
            'memory_avg': np.mean(memory_values),
            'memory_max': np.max(memory_values),
            'memory_p95': np.percentile(memory_values, 95),
            'response_time_avg': np.mean(response_times),
            'response_time_max': np.max(response_times),
            'response_time_p95': np.percentile(response_times, 95),
            'total_data_points': len(self.data_points)
        }
        
        # Generate HTML report
        html_content = self._generate_html_report(stats)
        
        with open(report_filename, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Generated performance report: {report_filename}")
        return report_filename
    
    def _generate_html_report(self, stats):
        """Generate HTML performance report"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>CAM Performance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .metric {{ margin: 10px 0; padding: 10px; border-left: 4px solid #007acc; }}
        .warning {{ border-left-color: #ff9900; }}
        .critical {{ border-left-color: #cc0000; }}
        .summary {{ background-color: #f5f5f5; padding: 20px; margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>CAM Performance Analysis Report</h1>
    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Monitoring Duration: {stats['duration_minutes']:.1f} minutes</p>
        <p>Total Data Points: {stats['total_data_points']}</p>
    </div>
    
    <h2>System Performance Metrics</h2>
    <table>
        <tr><th>Metric</th><th>Average</th><th>Maximum</th><th>95th Percentile</th></tr>
        <tr><td>CPU Usage (%)</td><td>{stats['cpu_avg']:.1f}</td><td>{stats['cpu_max']:.1f}</td><td>{stats['cpu_p95']:.1f}</td></tr>
        <tr><td>Memory Usage (%)</td><td>{stats['memory_avg']:.1f}</td><td>{stats['memory_max']:.1f}</td><td>{stats['memory_p95']:.1f}</td></tr>
        <tr><td>Response Time (ms)</td><td>{stats['response_time_avg']:.1f}</td><td>{stats['response_time_max']:.1f}</td><td>{stats['response_time_p95']:.1f}</td></tr>
    </table>
    
    <h2>Performance Analysis</h2>
    <div class="metric {'critical' if stats['cpu_p95'] > 85 else 'warning' if stats['cpu_p95'] > 70 else ''}">
        <strong>CPU Performance:</strong> P95 usage of {stats['cpu_p95']:.1f}%
        {'- CRITICAL: Exceeds 85% threshold' if stats['cpu_p95'] > 85 else '- WARNING: Exceeds 70% threshold' if stats['cpu_p95'] > 70 else '- NORMAL: Within acceptable range'}
    </div>
    
    <div class="metric {'critical' if stats['memory_p95'] > 90 else 'warning' if stats['memory_p95'] > 75 else ''}">
        <strong>Memory Performance:</strong> P95 usage of {stats['memory_p95']:.1f}%
        {'- CRITICAL: Exceeds 90% threshold' if stats['memory_p95'] > 90 else '- WARNING: Exceeds 75% threshold' if stats['memory_p95'] > 75 else '- NORMAL: Within acceptable range'}
    </div>
    
    <div class="metric {'critical' if stats['response_time_p95'] > 5000 else 'warning' if stats['response_time_p95'] > 2000 else ''}">
        <strong>Response Time Performance:</strong> P95 of {stats['response_time_p95']:.1f}ms
        {'- CRITICAL: Exceeds 5000ms threshold' if stats['response_time_p95'] > 5000 else '- WARNING: Exceeds 2000ms threshold' if stats['response_time_p95'] > 2000 else '- NORMAL: Within acceptable range'}
    </div>
    
    <h2>Recommendations</h2>
    <ul>
        {'<li>URGENT: CPU utilization is critically high. Consider scaling up or optimizing CPU-intensive operations.</li>' if stats['cpu_p95'] > 85 else ''}
        {'<li>WARNING: CPU utilization is elevated. Monitor for sustained high usage.</li>' if 70 < stats['cpu_p95'] <= 85 else ''}
        {'<li>URGENT: Memory usage is critically high. Consider increasing memory allocation or optimizing memory usage.</li>' if stats['memory_p95'] > 90 else ''}
        {'<li>WARNING: Memory usage is elevated. Monitor for memory leaks or optimize memory allocation.</li>' if 75 < stats['memory_p95'] <= 90 else ''}
        {'<li>URGENT: Response times are critically slow. Investigate performance bottlenecks.</li>' if stats['response_time_p95'] > 5000 else ''}
        {'<li>WARNING: Response times are slower than optimal. Consider performance optimizations.</li>' if 2000 < stats['response_time_p95'] <= 5000 else ''}
        {'<li>System performance appears normal. Continue regular monitoring.</li>' if stats['cpu_p95'] <= 70 and stats['memory_p95'] <= 75 and stats['response_time_p95'] <= 2000 else ''}
    </ul>
</body>
</html>
        """

def main():
    parser = argparse.ArgumentParser(description='CAM Performance Profiler')
    parser.add_argument('--url', default='http://localhost:3000', help='CAM base URL')
    parser.add_argument('--token', help='API token for authentication')
    parser.add_argument('--duration', type=int, default=300, help='Monitoring duration in seconds')
    parser.add_argument('--interval', type=float, default=1.0, help='Monitoring interval in seconds')
    parser.add_argument('--output', default='cam_performance', help='Output filename prefix')
    
    args = parser.parse_args()
    
    profiler = CAMPerformanceProfiler(args.url, args.token)
    
    try:
        # Start monitoring
        monitor_thread = profiler.start_monitoring(args.duration, args.interval)
        monitor_thread.join()
        
        # Export data and generate report
        json_file, csv_file = profiler.export_data(args.output)
        report_file = profiler.generate_report(args.output)
        
        print(f"Performance profiling completed!")
        print(f"Data exported to: {json_file}, {csv_file}")
        print(f"Report generated: {report_file}")
        
    except KeyboardInterrupt:
        print("\nMonitoring interrupted by user")
        profiler.stop_monitoring()
        
        if profiler.data_points:
            profiler.export_data(args.output)
            profiler.generate_report(args.output)

if __name__ == "__main__":
    main()
