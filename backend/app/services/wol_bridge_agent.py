"""
Wake-on-LAN Local Bridge Agent
===============================
Solves the WoL broadcast domain problem by acting as a local proxy.

Architecture:
- Cloud Dashboard → MQTT/REST → Local Agent → WoL Broadcast → Local Devices

This agent runs on a local machine (laptop/Raspberry Pi) and listens for
wake commands from the cloud controller, then broadcasts the magic packet
on the local Ethernet segment.
"""

import paho.mqtt.client as mqtt
import socket
import struct
import logging
import json
import time
from typing import Dict, Optional
from datetime import datetime
from flask import Flask, request, jsonify
import threading


class WoLLocalBridge:
    """
    Local bridge agent that receives wake commands and broadcasts magic packets.
    
    Supports two modes:
    1. MQTT mode: Subscribes to an MQTT broker
    2. REST API mode: Runs a local REST endpoint
    """
    
    def __init__(self, mode: str = "mqtt", config: Optional[Dict] = None):
        """
        Initialize WoL bridge.
        
        Args:
            mode: "mqtt" or "rest"
            config: Configuration dict with connection parameters
        """
        self.mode = mode
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'commands_received': 0,
            'errors': 0,
            'start_time': datetime.now().isoformat()
        }
        
        # Initialize based on mode
        if mode == "mqtt":
            self.mqtt_client = self._init_mqtt()
        elif mode == "rest":
            self.flask_app = self._init_flask()
        else:
            raise ValueError(f"Invalid mode: {mode}. Must be 'mqtt' or 'rest'")
    
    # =========================================================================
    # MQTT MODE
    # =========================================================================
    
    def _init_mqtt(self):
        """Initialize MQTT client."""
        mqtt_config = self.config.get('mqtt', {})
        broker = mqtt_config.get('broker', 'localhost')
        port = mqtt_config.get('port', 1883)
        topic = mqtt_config.get('topic', 'uaf/wol/wake')
        
        client = mqtt.Client(client_id="wol-bridge")
        
        # Set callbacks
        client.on_connect = self._on_mqtt_connect
        client.on_message = self._on_mqtt_message
        
        self.mqtt_broker = broker
        self.mqtt_port = port
        self.mqtt_topic = topic
        
        self.logger.info(f"MQTT client initialized: {broker}:{port}")
        
        return client
    
    def _on_mqtt_connect(self, client, userdata, flags, rc):
        """Callback when MQTT connection is established."""
        if rc == 0:
            self.logger.info("✅ Connected to MQTT broker")
            # Subscribe to wake topic
            client.subscribe(self.mqtt_topic)
            self.logger.info(f"📡 Subscribed to topic: {self.mqtt_topic}")
        else:
            self.logger.error(f"❌ MQTT connection failed: code {rc}")
    
    def _on_mqtt_message(self, client, userdata, msg):
        """Callback when MQTT message is received."""
        try:
            self.stats['commands_received'] += 1
            
            # Parse message
            payload = json.loads(msg.payload.decode())
            
            self.logger.info(f"📨 Wake command received via MQTT")
            self.logger.info(f"   Topic: {msg.topic}")
            self.logger.info(f"   Payload: {payload}")
            
            # Extract parameters
            mac_address = payload.get('target_mac') or payload.get('mac_address')
            broadcast_ip = payload.get('broadcast_ip', '255.255.255.255')
            port = payload.get('port', 9)
            
            if not mac_address:
                raise ValueError("Missing 'target_mac' in payload")
            
            # Send wake packet
            result = self.send_wake_packet(mac_address, broadcast_ip, port)
            
            if result:
                self.logger.info(f"✅ Magic packet sent to {mac_address}")
            else:
                self.logger.error(f"❌ Failed to send magic packet")
                
        except Exception as e:
            self.logger.error(f"Error processing MQTT message: {str(e)}")
            self.stats['errors'] += 1
    
    def start_mqtt_mode(self):
        """Start the MQTT client (blocking)."""
        self.logger.info(f"Starting WoL bridge in MQTT mode")
        self.logger.info(f"Broker: {self.mqtt_broker}:{self.mqtt_port}")
        self.logger.info(f"Topic: {self.mqtt_topic}")
        
        try:
            self.mqtt_client.connect(self.mqtt_broker, self.mqtt_port, 60)
            
            # Start loop (blocking)
            self.mqtt_client.loop_forever()
            
        except Exception as e:
            self.logger.error(f"MQTT mode error: {str(e)}")
            raise
    
    # =========================================================================
    # REST API MODE
    # =========================================================================
    
    def _init_flask(self):
        """Initialize Flask REST API."""
        app = Flask(__name__)
        
        @app.route('/health', methods=['GET'])
        def health():
            """Health check endpoint."""
            return jsonify({
                'status': 'healthy',
                'mode': 'rest',
                'stats': self.stats
            })
        
        @app.route('/wake', methods=['POST'])
        def wake():
            """Wake endpoint."""
            try:
                self.stats['commands_received'] += 1
                
                data = request.json
                
                mac_address = data.get('mac_address') or data.get('target_mac')
                broadcast_ip = data.get('broadcast_ip', '255.255.255.255')
                port = data.get('port', 9)
                
                if not mac_address:
                    return jsonify({
                        'success': False,
                        'error': 'Missing mac_address parameter'
                    }), 400
                
                # Send wake packet
                result = self.send_wake_packet(mac_address, broadcast_ip, port)
                
                if result:
                    self.logger.info(f"✅ Magic packet sent to {mac_address}")
                    return jsonify({
                        'success': True,
                        'mac_address': mac_address,
                        'broadcast_ip': broadcast_ip,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    self.stats['errors'] += 1
                    return jsonify({
                        'success': False,
                        'error': 'Failed to send magic packet'
                    }), 500
                    
            except Exception as e:
                self.logger.error(f"Error in wake endpoint: {str(e)}")
                self.stats['errors'] += 1
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @app.route('/stats', methods=['GET'])
        def get_stats():
            """Get statistics."""
            return jsonify(self.stats)
        
        return app
    
    def start_rest_mode(self, host: str = '0.0.0.0', port: int = 5001):
        """Start the Flask REST API server."""
        self.logger.info(f"Starting WoL bridge in REST mode")
        self.logger.info(f"Listening on {host}:{port}")
        self.logger.info(f"Endpoints:")
        self.logger.info(f"  POST http://{host}:{port}/wake")
        self.logger.info(f"  GET  http://{host}:{port}/health")
        self.logger.info(f"  GET  http://{host}:{port}/stats")
        
        self.flask_app.run(host=host, port=port, debug=False)
    
    # =========================================================================
    # WAKE-ON-LAN PACKET GENERATION
    # =========================================================================
    
    def send_wake_packet(self, mac_address: str, broadcast_ip: str = '255.255.255.255', 
                        port: int = 9) -> bool:
        """
        Send a Wake-on-LAN magic packet.
        
        The magic packet format is:
        - 6 bytes of 0xFF
        - 16 repetitions of the target MAC address
        
        Args:
            mac_address: Target MAC address (format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
            broadcast_ip: Broadcast IP address (default: 255.255.255.255)
            port: UDP port (default: 9)
            
        Returns:
            True if packet was sent successfully, False otherwise
        """
        try:
            # Clean and validate MAC address
            mac_address = mac_address.replace(':', '').replace('-', '').upper()
            
            if len(mac_address) != 12:
                raise ValueError(f"Invalid MAC address length: {mac_address}")
            
            # Convert MAC address to bytes
            mac_bytes = bytes.fromhex(mac_address)
            
            # Build magic packet: 6 bytes of 0xFF + 16 repetitions of MAC
            magic_packet = b'\xFF' * 6 + mac_bytes * 16
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Send the packet
            sock.sendto(magic_packet, (broadcast_ip, port))
            sock.close()
            
            self.stats['packets_sent'] += 1
            
            self.logger.info(f"🔌 Magic packet sent:")
            self.logger.info(f"   MAC: {mac_address}")
            self.logger.info(f"   Broadcast: {broadcast_ip}:{port}")
            self.logger.info(f"   Packet size: {len(magic_packet)} bytes")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send magic packet: {str(e)}")
            self.stats['errors'] += 1
            return False
    
    def send_multiple_packets(self, mac_address: str, count: int = 3, 
                             delay: float = 1.0, broadcast_ip: str = '255.255.255.255') -> Dict:
        """
        Send multiple magic packets (increases reliability).
        
        Args:
            mac_address: Target MAC address
            count: Number of packets to send
            delay: Delay between packets in seconds
            broadcast_ip: Broadcast IP
            
        Returns:
            Dict with success count and failure count
        """
        self.logger.info(f"Sending {count} magic packets to {mac_address}")
        
        success_count = 0
        failure_count = 0
        
        for i in range(count):
            result = self.send_wake_packet(mac_address, broadcast_ip)
            
            if result:
                success_count += 1
            else:
                failure_count += 1
            
            if i < count - 1:
                time.sleep(delay)
        
        return {
            'total_sent': count,
            'success_count': success_count,
            'failure_count': failure_count
        }
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_stats(self) -> Dict:
        """Get agent statistics."""
        return {
            'mode': self.mode,
            'stats': self.stats,
            'uptime': self._calculate_uptime()
        }
    
    def _calculate_uptime(self) -> str:
        """Calculate uptime since start."""
        start_time = datetime.fromisoformat(self.stats['start_time'])
        uptime_delta = datetime.now() - start_time
        
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return f"{days}d {hours}h {minutes}m {seconds}s"


# ============================================================================
# CLOUD DASHBOARD INTEGRATION (Client Side)
# ============================================================================

class WoLCloudClient:
    """
    Client for cloud dashboard to send wake commands to local bridge.
    
    This would be used in your FastAPI backend running in DigitalOcean.
    """
    
    def __init__(self, bridge_url: str):
        """
        Initialize cloud client.
        
        Args:
            bridge_url: URL of local WoL bridge REST API (via Tailscale)
                       e.g., "http://100.x.y.z:5001"
        """
        self.bridge_url = bridge_url
        self.logger = logging.getLogger(__name__)
    
    def wake_device(self, mac_address: str, broadcast_ip: str = '255.255.255.255') -> Dict:
        """
        Send wake command to local bridge.
        
        Args:
            mac_address: Target MAC address
            broadcast_ip: Broadcast IP (usually 255.255.255.255)
            
        Returns:
            Response from bridge
        """
        import requests
        
        wake_url = f"{self.bridge_url}/wake"
        
        payload = {
            'mac_address': mac_address,
            'broadcast_ip': broadcast_ip
        }
        
        try:
            self.logger.info(f"Sending wake command to local bridge: {mac_address}")
            
            response = requests.post(wake_url, json=payload, timeout=5)
            response.raise_for_status()
            
            result = response.json()
            
            self.logger.info(f"✅ Wake command successful")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to send wake command: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_bridge_health(self) -> Dict:
        """Check if local bridge is reachable."""
        import requests
        
        try:
            response = requests.get(f"{self.bridge_url}/health", timeout=3)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {
                'status': 'unreachable',
                'error': str(e)
            }


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    """
    Standalone execution.
    
    Run this script on your local laptop/Raspberry Pi.
    """
    
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    parser = argparse.ArgumentParser(description='WoL Local Bridge Agent')
    parser.add_argument('--mode', choices=['mqtt', 'rest'], default='rest',
                       help='Operation mode (default: rest)')
    parser.add_argument('--mqtt-broker', default='localhost',
                       help='MQTT broker address (for MQTT mode)')
    parser.add_argument('--mqtt-port', type=int, default=1883,
                       help='MQTT broker port')
    parser.add_argument('--mqtt-topic', default='uaf/wol/wake',
                       help='MQTT topic to subscribe to')
    parser.add_argument('--rest-host', default='0.0.0.0',
                       help='REST API host (for REST mode)')
    parser.add_argument('--rest-port', type=int, default=5001,
                       help='REST API port')
    
    args = parser.parse_args()
    
    logger.info("=" * 60)
    logger.info("WoL Local Bridge Agent")
    logger.info("=" * 60)
    
    if args.mode == 'mqtt':
        # MQTT mode
        config = {
            'mqtt': {
                'broker': args.mqtt_broker,
                'port': args.mqtt_port,
                'topic': args.mqtt_topic
            }
        }
        
        bridge = WoLLocalBridge(mode='mqtt', config=config)
        
        logger.info("Starting in MQTT mode...")
        logger.info(f"To test, publish a message:")
        logger.info(f'  mosquitto_pub -h {args.mqtt_broker} -t {args.mqtt_topic} -m \'{{"target_mac": "AA:BB:CC:DD:EE:FF"}}\'')
        logger.info("")
        
        try:
            bridge.start_mqtt_mode()
        except KeyboardInterrupt:
            logger.info("Stopping...")
    
    else:
        # REST mode
        bridge = WoLLocalBridge(mode='rest')
        
        logger.info("Starting in REST mode...")
        logger.info(f"To test, send a POST request:")
        logger.info(f'  curl -X POST http://{args.rest_host}:{args.rest_port}/wake \\')
        logger.info(f'       -H "Content-Type: application/json" \\')
        logger.info(f'       -d \'{{"mac_address": "AA:BB:CC:DD:EE:FF"}}\'')
        logger.info("")
        
        try:
            bridge.start_rest_mode(host=args.rest_host, port=args.rest_port)
        except KeyboardInterrupt:
            logger.info("Stopping...")
