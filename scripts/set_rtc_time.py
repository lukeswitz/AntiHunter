#!/usr/bin/env python3
Import("env")
import time
import serial

def after_upload(source, target, env):
    upload_port = env.get("UPLOAD_PORT")
    if not upload_port:
        return
    
    epoch = int(time.time())
    print(f"\n[RTC] Setting to system time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(epoch))}")
    
    try:
        time.sleep(3)
        ser = serial.Serial(upload_port, 115200, timeout=2)
        time.sleep(1)
        ser.write(f"SETTIME:{epoch}\n".encode())
        ser.flush()
        time.sleep(0.5)
        if ser.in_waiting:
            print(f"[RTC] {ser.readline().decode().strip()}")
        ser.close()
        print("[RTC] Done\n")
    except Exception as e:
        print(f"[RTC] Failed: {e}\n")

env.AddPostAction("upload", after_upload)