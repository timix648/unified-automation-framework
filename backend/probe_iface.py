import os, sys
os.environ.setdefault("MOCK_MODE", "False")
sys.path.insert(0, ".")

from app.services.device_manager import DeviceFactory
from app.inventory.netbox_client import NetboxInventory

nb = NetboxInventory()
dev = next(d for d in nb.get_all_devices() if d["name"] == "cisco-switch-01")
print("DEVICE IP:", dev.get("ip") or dev.get("primary_ip"), "platform:", dev.get("platform"))

drv = DeviceFactory.get_driver(dev)
print("DRIVER TYPE:", type(drv).__name__)
print("DRIVER mock_mode:", getattr(drv, "mock_mode", "??"))

drv.connect()
res = drv.get_port_status()
print("PORT COUNT:", res.get("count"))
print("PORTS:", [i.get("interface") for i in res.get("interfaces", [])])
drv.disconnect()