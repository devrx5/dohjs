#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import random
import string
import subprocess
import logging
from typing import Optional, Tuple, List

import requests
from dotenv import load_dotenv

# ──────────────────────────── Константы ────────────────────────────
URL = "https://site.com"
TIMEOUT_SEC = 15                  # тайм-аут запроса к сайту
SLEEP_BETWEEN = 10                # пауза после смены IP, сек
MAX_ALLOC_RETRIES = 3             # кол-во повторов allocate-static-ip при лимите
RETRY_SLEEP_SEC = 4               # пауза между повторами

# ──────────────────────────── Загрузка .env ─────────────────────────
load_dotenv()
INSTANCE_NAME = os.getenv("INSTANCE_NAME")
REMNA_TOKEN = os.getenv("REMNA_TOKEN")
BASE_URL = os.getenv("REMNA_BASE_URL")
NODE_UUID = os.getenv("NODE_UUID")
HOST_UUIDS = os.getenv("HOST_UUIDS")
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = os.getenv("ADMIN_ID")
REGION = os.getenv("REGION")

if not all([INSTANCE_NAME, REMNA_TOKEN, BASE_URL, NODE_UUID, HOST_UUIDS]):
    sys.stderr.write("❌ В .env должны быть заданы INSTANCE_NAME, REMNA_TOKEN, REMNA_BASE_URL, NODE_UUID, HOST_UUIDS\n")
    sys.exit(1)

HOST_UUIDS_LIST = [u.strip() for u in HOST_UUIDS.split(",") if u.strip()]

# ─────────────── Настройка логгера ────────────────────────────────
LOG_FILE = "Blok.log"
logger = logging.getLogger("blok")
logger.setLevel(logging.INFO)

fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
console_h = logging.StreamHandler(sys.stdout)
file_h = logging.FileHandler(LOG_FILE, encoding="utf-8")

console_h.setFormatter(fmt)
file_h.setFormatter(fmt)

logger.addHandler(console_h)
logger.addHandler(file_h)
logger.propagate = False


# ────────────────────────── Telegram helper ─────────────────────────
def send_telegram(message: str) -> None:
    if not BOT_TOKEN or not ADMIN_ID:
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": ADMIN_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("✅ Telegram-уведомление отправлено.")
    except requests.RequestException as e:
        logger.error(f"❌ Ошибка отправки Telegram-уведомления: {e}")


# ──────────────────────────── AWS helpers ──────────────────────────
def run_aws(cmd: List[str]) -> Tuple[str, str, int]:
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout.strip(), res.stderr.strip(), res.returncode


def generate_random_name(length: int = 10) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=length))


def find_attached_static_ip_name(instance_name: str) -> Optional[str]:
    out, err, rc = run_aws([
        "aws", "lightsail", "get-static-ips",
        "--region", REGION, "--output", "json"
    ])
    if rc != 0:
        logger.warning(f"[{REGION}] Не удалось получить список staticIps: {err}")
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    for ip in data.get("staticIps", []):
        if ip.get("attachedTo") == instance_name:
            return ip.get("name")
    return None


def is_static_ip_limit_error(err_text: str) -> bool:
    if not err_text:
        return False
    low = err_text.lower()
    return (
        "maximum number of static ips" in low
        or "you have reached the maximum number of static ips" in low
        or ("service quotas" in low and "static ip" in low)
    )


def cleanup_static_ips_in_region(region: str) -> int:
    deleted = 0
    out, err, rc = run_aws([
        "aws", "lightsail", "get-static-ips",
        "--region", region, "--output", "json"
    ])
    if rc != 0:
        logger.warning(f"[{region}] Не удалось получить список staticIps: {err}")
        send_telegram(f"⚠️ <b>Не удалось получить staticIps</b> для региона {region}: {err}")
        return 0

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        logger.error(f"[{region}] Некорректный JSON от get-static-ips")
        send_telegram(f"❌ <b>Некорректный JSON</b> от get-static-ips в регионе {region}")
        return 0

    for ip_info in data.get("staticIps", []):
        if not ip_info.get("attachedTo"):
            name = ip_info.get("name")
            address = ip_info.get("ipAddress")
            _, err_rel, rc_rel = run_aws([
                "aws", "lightsail", "release-static-ip",
                "--static-ip-name", name,
                "--region", region
            ])
            if rc_rel == 0:
                deleted += 1
                logger.info(f"🗑️ Удалён непривязанный Static IP: {name} ({address}) из {region}")
                send_telegram(f"🗑️ <b>Удалён Static IP</b>: {name} ({address}) из {region}")
            else:
                logger.error(f"[{region}] Ошибка release-static-ip для {name}: {err_rel}")
                send_telegram(f"❌ <b>Ошибка удаления Static IP</b> {name} ({address}) из {region}: {err_rel}")

    if deleted == 0:
        logger.info(f"[{region}] Нет непривязанных Static IP для удаления.")
        send_telegram(f"ℹ️ <b>Нет непривязанных Static IP</b> для удаления в регионе {region}.")
    else:
        logger.info(f"[{region}] Всего удалено {deleted} Static IP.")
        send_telegram(f"✅ <b>Удалено {deleted} Static IP</b> в регионе {region}.")

    return deleted


def rotate_lightsail_ip(instance_name: str) -> dict:
    out, err, rc = run_aws([
        "aws", "lightsail", "get-instance",
        "--instance-name", instance_name,
        "--region", REGION,
        "--output", "json"
    ])
    if rc != 0:
        raise RuntimeError(f"Инстанс '{instance_name}' не найден или не доступен в регионе {REGION}: {err}")
    try:
        instance = json.loads(out)["instance"]
    except Exception as ex:
        raise RuntimeError(f"Не удалось распарсить ответ get-instance: {ex}")

    is_static = instance.get("isStaticIp", False)

    if is_static:
        static_name = instance.get("staticIpName") or find_attached_static_ip_name(instance_name)
        if not static_name:
            raise RuntimeError("Статический IP прикреплён, но имя не найдено.")

        logger.info(f"Открепляем статический IP «{static_name}» в {REGION} …")
        send_telegram(f"🚀 <b>Открепление статического IP</b>: {static_name} [{REGION}]")
        _, err_detach, rc_detach = run_aws([
            "aws", "lightsail", "detach-static-ip",
            "--static-ip-name", static_name,
            "--region", REGION
        ])
        if rc_detach != 0:
            raise RuntimeError(f"Ошибка detach-static-ip: {err_detach}")

        old_ip = instance.get("publicIpAddress")
        new_ip = old_ip
        for _ in range(12):  # ~6 сек
            new_ip, _, _ = run_aws([
                "aws", "lightsail", "get-instance",
                "--instance-name", instance_name,
                "--region", REGION,
                "--query", "instance.publicIpAddress",
                "--output", "text"
            ])
            if new_ip and new_ip != old_ip:
                break
            time.sleep(0.5)

        if new_ip == old_ip:
            raise RuntimeError("AWS не выдал новый динамический IP (timeout).")

        logger.info(f"Получен новый динамический IP: {new_ip}")
        send_telegram(f"✅ <b>Новый динамический IP</b>: {new_ip} [{REGION}]")
        return {"status": "detached", "ip": new_ip, "static_name": static_name, "region": REGION}

    for attempt in range(1, MAX_ALLOC_RETRIES + 1):
        random_name = generate_random_name()
        logger.info(f"[{REGION}] Попытка {attempt}/{MAX_ALLOC_RETRIES}: создаём статический IP «{random_name}» …")
        send_telegram(f"🚀 <b>Создание статического IP</b> (попытка {attempt}/{MAX_ALLOC_RETRIES}): {random_name} [{REGION}]")

        _, err_alloc, rc_alloc = run_aws([
            "aws", "lightsail", "allocate-static-ip",
            "--static-ip-name", random_name,
            "--region", REGION
        ])

        if rc_alloc == 0:
            _, err_attach, rc_attach = run_aws([
                "aws", "lightsail", "attach-static-ip",
                "--static-ip-name", random_name,
                "--instance-name", instance_name,
                "--region", REGION
            ])
            if rc_attach != 0:
                logger.error(f"❌ Ошибка attach-static-ip: {err_attach}. Попробуем release.")
                run_aws(["aws", "lightsail", "release-static-ip", "--static-ip-name", random_name, "--region", REGION])
                raise RuntimeError(f"Ошибка attach-static-ip: {err_attach}")

            ip, err_get, rc_get = run_aws([
                "aws", "lightsail", "get-static-ip",
                "--static-ip-name", random_name,
                "--region", REGION,
                "--query", "staticIp.ipAddress",
                "--output", "text"
            ])
            if rc_get != 0 or not ip:
                raise RuntimeError(f"Ошибка get-static-ip: {err_get}")

            logger.info(f"Прикрепили статический IP {ip} (имя {random_name}) [{REGION}]")
            send_telegram(f"✅ <b>Новый статический IP прикреплён</b>: {ip} [{REGION}]")
            return {"status": "attached", "ip": ip, "static_name": random_name, "region": REGION}

        # Обработка лимита
        if is_static_ip_limit_error(err_alloc):
            logger.warning(f"[{REGION}] Лимит Static IP достигнут. Очищаю непривязанные и повторяю попытку.")
            send_telegram(f"⚠️ <b>Лимит Static IP</b> в {REGION}. Чищу непривязанные IP и повторю попытку.")
            freed = cleanup_static_ips_in_region(REGION)
            if freed == 0:
                logger.warning(f"[{REGION}] Нечего удалять. Жду {RETRY_SLEEP_SEC} сек и пробую снова.")
                time.sleep(RETRY_SLEEP_SEC)
            else:
                logger.info(f"[{REGION}] Освободил {freed} слотов. Жду {RETRY_SLEEP_SEC} сек и повторяю allocate.")
                time.sleep(RETRY_SLEEP_SEC)
            continue
        else:
            raise RuntimeError(f"Ошибка allocate-static-ip: {err_alloc}")

    raise RuntimeError("Не удалось выделить статический IP после очистки лимита и повторных попыток.")


def url_is_up() -> bool:
    try:
        resp = requests.get(URL, timeout=TIMEOUT_SEC)
        return resp.status_code == 200
    except requests.RequestException as e:
        logger.warning(f"Ошибка соединения к {URL}: {e}")
        send_telegram(f"⚠️ <b>Ошибка соединения</b> к {URL}: {e}")
        return False


def fetch_list(endpoint: str) -> list:
    url = f"{BASE_URL}{endpoint}"
    try:
        r = requests.get(url, headers={"Authorization": f"Bearer {REMNA_TOKEN}"}, timeout=10)
        r.raise_for_status()
        payload = r.json()
        if "response" not in payload:
            logger.error(f"Ошибка: в ответе нет ключа 'response'. Ответ: {payload}")
            send_telegram(f"❌ <b>Remna API error</b>: нет ключа 'response'. Ответ: {payload}")
            sys.exit(1)
        return payload["response"]
    except requests.RequestException as e:
        logger.error(f"Ошибка запроса {url}: {e}")
        send_telegram(f"❌ <b>Ошибка Remna API</b> при GET {endpoint}: {e}")
        sys.exit(1)


def patch_node(uuid: str, new_ip: str) -> None:
    url = f"{BASE_URL}/api/nodes"
    body = {"uuid": uuid, "address": new_ip}
    try:
        r = requests.patch(url, headers={"Authorization": f"Bearer {REMNA_TOKEN}"}, json=body, timeout=10)
        r.raise_for_status()
        logger.info(f"✅ Node ({uuid}) IP обновлён → {new_ip}")
        send_telegram(f"✅ <b>Node</b> ({uuid}) IP обновлён → {new_ip}")
    except requests.RequestException as e:
        err_text = getattr(e.response, "text", "")
        logger.error(f"❌ Ошибка PATCH /api/nodes для {uuid}: {e} Ответ: {err_text}")
        send_telegram(f"❌ <b>Ошибка обновления Node</b> ({uuid}): {err_text}")
        sys.exit(1)


def patch_host(uuid: str, new_ip: str) -> None:
    url = f"{BASE_URL}/api/hosts"
    body = {"uuid": uuid, "address": new_ip}
    try:
        r = requests.patch(url, headers={"Authorization": f"Bearer {REMNA_TOKEN}"}, json=body, timeout=10)
        r.raise_for_status()
        logger.info(f"✅ Host ({uuid}) IP обновлён → {new_ip}")
        send_telegram(f"✅ <b>Host</b> ({uuid}) IP обновлён → {new_ip}")
    except requests.RequestException as e:
        err_text = getattr(e.response, "text", "")
        logger.error(f"❌ Ошибка PATCH /api/hosts для {uuid}: {e} Ответ: {err_text}")
        send_telegram(f"❌ <b>Ошибка обновления Host</b> ({uuid}): {err_text}")
        sys.exit(1)


def update_remna_ip(new_ip: str) -> None:
    nodes = fetch_list("/api/nodes")
    hosts = fetch_list("/api/hosts")

    target_node = next((n for n in nodes if n["uuid"] == NODE_UUID), None)
    if not target_node:
        logger.error(f"❌ Не найден Node с UUID: {NODE_UUID}")
        send_telegram(f"❌ <b>Node не найден</b> (UUID: {NODE_UUID})")
        return

    target_hosts = [h for h in hosts if h["uuid"] in HOST_UUIDS_LIST]
    if not target_hosts:
        logger.error(f"❌ Не найден ни один Host из списка: {HOST_UUIDS_LIST}")
        send_telegram(f"❌ <b>Hosts не найдены</b> (UUIDs: {HOST_UUIDS_LIST})")
        return

    current_node_ip = target_node["address"].strip()
    if current_node_ip != new_ip:
        patch_node(NODE_UUID, new_ip)
    else:
        logger.info(f"ℹ️ Node ({NODE_UUID}) уже использует IP {new_ip}")
        send_telegram(f"ℹ️ <b>Node</b> ({NODE_UUID}) уже использует IP {new_ip}")

    for h in target_hosts:
        current_host_ip = h["address"].strip()
        if current_host_ip != new_ip:
            patch_host(h["uuid"], new_ip)
        else:
            logger.info(f"ℹ️ Host ({h['uuid']}) уже использует IP {new_ip}")
            send_telegram(f"ℹ️ <b>Host</b> ({h['uuid']}) уже использует IP {new_ip}")

    logger.info("🎉 Обновление Remna завершено.")
    send_telegram("🎉 <b>Обновление Remna завершено.</b>")


# ────────────────────────────── Main Loop ───────────────────────────
def main():
    attempt = 1
    last_ip = None

    while True:
        logger.info(f"[Попытка {attempt}] Проверяем доступность {URL}")
        if url_is_up():
            logger.info("🎉 Сайт доступен (HTTP 200). Обновляем Remna и завершаем.")
            if last_ip:
                update_remna_ip(last_ip)
                cleanup_static_ips_in_region(REGION)
            break
        else:
            logger.warning("Сайт недоступен. Запускаем смену IP …")
            send_telegram("⚠️ <b>Сайт недоступен</b>, начинаю смену IP...")
            try:
                result = rotate_lightsail_ip(INSTANCE_NAME)
                last_ip = result["ip"]
            except RuntimeError as e:
                logger.error(f"Ошибка ротации IP: {e}")
                send_telegram(f"❌ <b>Ошибка ротации IP:</b> {e}")
                sys.exit(1)

            logger.info(f"⏳ Ждём {SLEEP_BETWEEN} сек и пробуем снова …")
            time.sleep(SLEEP_BETWEEN)
            attempt += 1


if __name__ == "__main__":
    main()
