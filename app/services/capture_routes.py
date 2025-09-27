from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import text
from app.db.DB_Setup import DBHandler
from app.auth.auth_routes import get_current_user
import pyshark, asyncio
from typing import Optional
from datetime import datetime, timedelta, timezone
import socket
import threading
import asyncio
import pdb

from scapy.all import sniff, IP,get_if_list,get_if_addr,get_if_hwaddr
print(get_if_list())

for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
    except Exception:
        ip = "No IP"
    try:
        mac = get_if_hwaddr(iface)
    except Exception:
        mac = "No MAC"
    print(f"{iface} -> IP: {ip}, MAC: {mac}")


router = APIRouter(prefix="/api/v1/capture", tags=["capture"])

db = DBHandler()

traffic_cache = {}
cache_lock = threading.Lock()

# background task handles
_capture_thread = None
_flush_task = None

# get device name
def get_device_name_from_ip(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except socket.herror:
        return "Unknown"

def dst_ip_domain(ip:str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

# Packet Processor
# def process_packet(packet, user_id: int):
#     try:
#         if not hasattr(packet, "ip"):
#             return
#         src = getattr(packet.ip, "src", None)
#         dst = getattr(packet.ip, "dst", None)
#         length = int(getattr(packet, "length", 0))
#         now = datetime.now(timezone.utc).replace(second=0, microsecond=0)

#         for ip in (src, dst):
#             if not ip:
#                 continue
#             key = (ip, now)
#             with cache_lock:
#                 entry = traffic_cache.get(key)
#                 if entry is None:
#                     traffic_cache[key] = {"bytes": 0, "packets": 0, "user_id": user_id}
#                     entry = traffic_cache[key]
#                 entry["bytes"] += length
#                 entry["packets"] += 1
#     except Exception as e:
#         print("process_packet error:", e)

# New async capture function


# --- New Helper Function for the blocking sniff ---
def capture_loop(user_id, interface=None):
    """
    Runs in a background thread using scapy.sniff.
    Captures IP packets and updates the traffic_cache.
    """
    global _my_ip
    _my_ip = get_if_addr(interface)
    print(f"my ip: {_my_ip}")
    def handle(pkt):
        if pkt.haslayer(IP):
            length = len(pkt)
            now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            src = pkt[IP].src
            dst = pkt[IP].dst
            if src != _my_ip and dst!= _my_ip:
                return
            
            key = (src,dst, now)
            with cache_lock:
                entry = traffic_cache.get(key)
                if entry is None:
                    traffic_cache[key] = {"bytes": 0, "packets": 0, "user_id": user_id}
                    entry = traffic_cache[key]
                entry["bytes"] += length
                entry["packets"] += 1
    # blocking sniff in thread
    sniff(iface=interface, prn=handle, store=0)

# --- Updated async capture task ---
async def capture_traffic(user_id: int, interface: Optional[str] = None):
    """
    Async wrapper that starts capture thread.
    """
    global _capture_thread
    if _capture_thread and _capture_thread.is_alive():
        return
    _capture_thread = threading.Thread(target=capture_loop, args=(user_id, interface), daemon=True)
    _capture_thread.start()

# --- No changes to other functions/endpoints ---
# ... (rest of your code remains the same)
# The `start_capture` and `stop_capture` functions are good as they are.
# Flush cache
async def flush_cache(user_id: int):
    
    global _my_ip
    while True:
        await asyncio.sleep(60)
        async with db.get_session() as session:
            with cache_lock:
                items = [((src,dst,minute), stats.copy()) for (src,dst, minute), stats in traffic_cache.items() if stats.get("user_id") == user_id]

            for (src,dst, minute), stats in items:
                try:
                    total_bytes = stats["bytes"]
                    packets = stats["packets"]
                    avg_bandwidth = (total_bytes * 8 / 1_000_000) / 60
                    print(f"src and my_ip :{src} ip and my ip {_my_ip}")
                    if src == _my_ip:

                        device_name = get_device_name_from_ip(src)

                        sql_device = text("""
                                INSERT INTO devices (device_ip, name, user_id)
                                VALUES (:ip, :name, :user_id)
                                ON CONFLICT (device_ip) DO UPDATE SET name = EXCLUDED.name
                                RETURNING id
                            """)
                        result = await session.execute(
                                sql_device, {"ip": src, "name": device_name, "user_id": user_id}
                            )
                        device_id = result.scalar()  

                        sql_traffic = text("""
                            INSERT INTO device_traffic (src_ip,dst_ip,dst_domain, minute_window, total_bytes, avg_bandwidth_mbps, packet_count,src_device_id)
                            VALUES (:src,:dst,:dst_domain, :minute_window, :total_bytes, :avg_bandwidth_mbps, :packets,:src_device_id)
                        """)
                        dst_domain = dst_ip_domain(dst)

                        await session.execute(sql_traffic, {
                            "src": src,
                            "dst":dst,
                            "dst_domain":dst_domain,
                            "minute_window": minute,
                            "total_bytes": total_bytes,
                            "avg_bandwidth_mbps": avg_bandwidth,
                            "packets": packets,
                            "src_device_id":device_id
                        })

                        with cache_lock:
                            traffic_cache.pop((src,dst, minute), None)
                except Exception as e:
                    print("Error flushing entry for", src,dst, minute, ":", e)
        print(f"✅ flushed cache for user {user_id}")

# APIs
class StartCaptureIn(BaseModel):
    interface: Optional[str] = None

@router.post("/start")
async def start_capture(
    payload: StartCaptureIn = None,
    current_user: dict = Depends(get_current_user)
):
   
    global _flush_task

    if _flush_task and not _flush_task.done():
        raise HTTPException(status_code=400, detail="Flush task already running")

    user_id = current_user["user_id"]
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid user")
    print(f"user_id:{user_id}")

    # Start the async capture and flush tasks 
    await capture_traffic(user_id, payload.interface if payload else None)
    loop = asyncio.get_running_loop()
    _flush_task = loop.create_task(flush_cache(user_id))

    return {"status": "capture started", "user_id": user_id, "interface": payload.interface if payload else None}

    
@router.post("/stop")
async def stop_capture():
    global _capture_thread, _flush_task
    if _flush_task:
        _flush_task.cancel()
        _flush_task = None

    if _capture_thread and _capture_thread.is_alive():
        print("⚠️ capture thread still running (daemon), will exit when process stops.")
    return {"status": "capture stopped"}

@router.get("/devices")
async def list_devices(current_user=Depends(get_current_user)):
    """Return all devices + latest traffic snapshot for current user."""
    db = DBHandler()
    user_id = current_user["id"]

    async with db.get_session() as session:
        sql = text("""
            SELECT DISTINCT ON (dt.src_ip)
                dt.src_ip,
                dt.dst_ip,
                d.name as device_name,
                dt.minute_window,
                dt.total_bytes,
                dt.avg_bandwidth_mbps,
                dt.packet_count
            FROM device_traffic dt
            JOIN devices d ON dt.src_ip = d.device_ip
            WHERE d.user_id = :user_id
            ORDER BY dt.src_ip, dt.minute_window DESC
        """)
        result = await session.execute(sql, {"user_id": user_id})
        rows = result.fetchall()

    devices = []
    for row in rows:
        devices.append({
            "src_ip": row.src_ip,
            "dst_ip":row.dst_ip,
            "device_name": row.device_name if row.device_name else "Unknown",
            "minute_window": row.minute_window,
            "total_bytes": row.total_bytes,
            "avg_bandwidth_mbps": float(row.avg_bandwidth_mbps) if row.avg_bandwidth_mbps else 0,
            "packet_count": row.packet_count
        })
    return {"devices": devices}