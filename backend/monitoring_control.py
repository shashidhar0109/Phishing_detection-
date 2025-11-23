"""Control background monitoring workers"""
import subprocess
import os
import signal
import psutil
from typing import Dict, Any
import time


class MonitoringController:
    """Control Celery workers for background monitoring"""
    
    def __init__(self):
        self.project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.worker_script = os.path.join(self.project_dir, 'start_worker.sh')
        self.beat_script = os.path.join(self.project_dir, 'start_beat.sh')
    
    def is_worker_running(self) -> bool:
        """Check if Celery worker is running"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'celery' in cmdline.lower() and 'worker' in cmdline.lower() and 'backend.worker' in cmdline:
                    return True
            except:
                pass
        return False
    
    def is_beat_running(self) -> bool:
        """Check if Celery beat is running"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'celery' in cmdline.lower() and 'beat' in cmdline.lower() and 'backend.worker' in cmdline:
                    return True
            except:
                pass
        return False
    
    def start_worker(self) -> Dict[str, Any]:
        """Start Celery worker"""
        if self.is_worker_running():
            return {
                'success': False,
                'message': 'Worker is already running'
            }
        
        try:
            # Create start script with better configuration
            script_content = f'''#!/bin/bash
cd {self.project_dir}
source ../newedz/venv/bin/activate
nohup celery -A backend.worker.celery_app worker --loglevel=info --concurrency=2 --max-tasks-per-child=50 > logs/worker.log 2>&1 &
echo $! > /tmp/phishing_worker.pid
'''
            with open(self.worker_script, 'w') as f:
                f.write(script_content)
            os.chmod(self.worker_script, 0o755)
            
            # Execute script
            subprocess.run(['bash', self.worker_script], check=True)
            time.sleep(2)  # Give it time to start
            
            if self.is_worker_running():
                return {
                    'success': True,
                    'message': 'Worker started successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'Worker failed to start. Check logs/worker.log'
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to start worker: {str(e)}'
            }
    
    def start_beat(self) -> Dict[str, Any]:
        """Start Celery beat scheduler"""
        if self.is_beat_running():
            return {
                'success': False,
                'message': 'Beat scheduler is already running'
            }
        
        try:
            # Create start script
            script_content = f'''#!/bin/bash
cd {self.project_dir}
source ../newedz/venv/bin/activate
nohup celery -A backend.worker.celery_app beat --loglevel=info --schedule=/tmp/celerybeat-schedule > logs/beat.log 2>&1 &
echo $! > /tmp/phishing_beat.pid
'''
            with open(self.beat_script, 'w') as f:
                f.write(script_content)
            os.chmod(self.beat_script, 0o755)
            
            # Execute script
            subprocess.run(['bash', self.beat_script], check=True)
            time.sleep(2)  # Give it time to start
            
            if self.is_beat_running():
                return {
                    'success': True,
                    'message': 'Beat scheduler started successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'Beat failed to start. Check logs/beat.log'
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to start beat: {str(e)}'
            }
    
    def stop_worker(self) -> Dict[str, Any]:
        """Stop Celery worker"""
        stopped = False
        
        # Try to stop from PID file
        pid_file = '/tmp/phishing_worker.pid'
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                os.remove(pid_file)
                stopped = True
            except:
                pass
        
        # Use subprocess to kill ALL celery workers more aggressively
        try:
            # Kill all celery workers (not just backend.worker ones)
            result = subprocess.run(['pkill', '-f', 'celery.*worker'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                stopped = True
                print(f"[DEBUG] Killed all celery workers with pkill")
        except Exception as e:
            print(f"[DEBUG] pkill failed: {e}")
        
        # Also try to kill any remaining celery processes
        try:
            result = subprocess.run(['pkill', '-f', 'celery'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                stopped = True
                print(f"[DEBUG] Killed all celery processes with pkill")
        except Exception as e:
            print(f"[DEBUG] pkill all celery failed: {e}")
        
        # Also try psutil approach as backup
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'celery' in cmdline.lower() and 'worker' in cmdline.lower() and 'backend.worker' in cmdline:
                    print(f"[DEBUG] Terminating worker process {proc.info['pid']}")
                    proc.terminate()
                    time.sleep(1)  # Give it time to terminate gracefully
                    if proc.is_running():
                        print(f"[DEBUG] Force killing worker process {proc.info['pid']}")
                        proc.kill()  # Force kill if it doesn't terminate
                    stopped = True
            except Exception as e:
                print(f"[DEBUG] Error stopping process: {e}")
                pass
        
        if stopped:
            return {
                'success': True,
                'message': 'Worker stopped successfully'
            }
        else:
            return {
                'success': False,
                'message': 'No worker process found'
            }
    
    def stop_beat(self) -> Dict[str, Any]:
        """Stop Celery beat scheduler"""
        stopped = False
        
        pid_file = '/tmp/phishing_beat.pid'
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                os.remove(pid_file)
                stopped = True
            except:
                pass
        
        # Use subprocess to kill ALL celery beat processes more aggressively
        try:
            # Kill all celery beat processes (not just backend.worker ones)
            result = subprocess.run(['pkill', '-f', 'celery.*beat'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                stopped = True
                print(f"[DEBUG] Killed all celery beat with pkill")
        except Exception as e:
            print(f"[DEBUG] pkill beat failed: {e}")
        
        # Also try to kill any remaining celery processes
        try:
            result = subprocess.run(['pkill', '-f', 'celery'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                stopped = True
                print(f"[DEBUG] Killed all celery processes with pkill")
        except Exception as e:
            print(f"[DEBUG] pkill all celery failed: {e}")
        
        # Also try psutil approach as backup
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'celery' in cmdline.lower() and 'beat' in cmdline.lower() and 'backend.worker' in cmdline:
                    print(f"[DEBUG] Terminating beat process {proc.info['pid']}")
                    proc.terminate()
                    time.sleep(1)  # Give it time to terminate gracefully
                    if proc.is_running():
                        print(f"[DEBUG] Force killing beat process {proc.info['pid']}")
                        proc.kill()  # Force kill if it doesn't terminate
                    stopped = True
            except Exception as e:
                print(f"[DEBUG] Error stopping beat process: {e}")
                pass
        
        if stopped:
            return {
                'success': True,
                'message': 'Beat scheduler stopped successfully'
            }
        else:
            return {
                'success': False,
                'message': 'No beat process found'
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        worker_running = self.is_worker_running()
        beat_running = self.is_beat_running()
        
        # Monitoring is active if workers are running (beat is optional for basic monitoring)
        monitoring_active = worker_running
        
        return {
            'worker_running': worker_running,
            'beat_running': beat_running,
            'monitoring_active': monitoring_active
        }
    
    def start_monitoring(self) -> Dict[str, Any]:
        """Start both worker and beat immediately"""
        print("🚀 Starting monitoring workers...")
        
        # Start workers immediately without domain classification
        worker_result = self.start_worker()
        beat_result = self.start_beat()
        
        # Monitoring is successful if workers start (beat is optional)
        if worker_result['success']:
            print("✅ Monitoring started successfully!")
            return {
                'success': True,
                'message': 'Monitoring started successfully',
                'worker_running': True,
                'beat_running': beat_result['success'],
                'monitoring_active': True
            }
        else:
            return {
                'success': False,
                'message': f"Failed to start monitoring: Worker: {worker_result['message']}",
                'worker_running': False,
                'beat_running': beat_result['success'],
                'monitoring_active': False
            }
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop both worker and beat - AGGRESSIVE APPROACH"""
        print("🛑 Stopping monitoring workers...")
        
        # First, kill ALL celery processes aggressively
        try:
            print("[DEBUG] Killing all celery processes...")
            subprocess.run(['pkill', '-9', '-f', 'celery'], timeout=10)
            time.sleep(2)
            print("[DEBUG] All celery processes killed")
        except Exception as e:
            print(f"[DEBUG] Error killing celery processes: {e}")
        
        # Then try the normal stop methods
        worker_result = self.stop_worker()
        beat_result = self.stop_beat()
        
        # Check if any celery processes are still running
        remaining_celery = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'celery' in cmdline.lower():
                    remaining_celery.append(proc.info['pid'])
            except:
                pass
        
        if remaining_celery:
            print(f"[DEBUG] Still {len(remaining_celery)} celery processes running: {remaining_celery}")
            # Force kill remaining processes
            for pid in remaining_celery:
                try:
                    os.kill(pid, signal.SIGKILL)
                    print(f"[DEBUG] Force killed celery process {pid}")
                except:
                    pass
        
        print("✅ Monitoring stopped successfully!")
        return {
            'success': True,
            'message': 'Monitoring stopped',
            'details': {
                'worker': worker_result,
                'beat': beat_result
            }
        }


# Global instance
monitoring_controller = MonitoringController()
