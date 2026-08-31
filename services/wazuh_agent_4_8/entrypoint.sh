#!/usr/bin/env bash
set -euo pipefail

WAZUH_MANAGER_SERVER="${WAZUH_MANAGER_SERVER:-wazuh.manager}"
WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER:-${WAZUH_MANAGER_SERVER}}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-agent003}"

# Keep ossec.conf aligned with the target manager and registration server.
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER_SERVER}</address>|" /var/ossec/etc/ossec.conf
sed -i "s|<server>MANAGER_IP</server>|<server>${WAZUH_REGISTRATION_SERVER}</server>|" /var/ossec/etc/ossec.conf || true

# Ensure no invalid name tag is present in client config.
sed -i '/<name>.*<\/name>/d' /var/ossec/etc/ossec.conf

# Register the agent if no client key is present yet.
if [[ ! -s /var/ossec/etc/client.keys ]]; then
  echo "[wazuh-agent-4.8] registering ${WAZUH_AGENT_NAME} against ${WAZUH_REGISTRATION_SERVER}:1515"
  /var/ossec/bin/agent-auth -m "${WAZUH_REGISTRATION_SERVER}" -A "${WAZUH_AGENT_NAME}" || true
fi

echo "[wazuh-agent-4.8] starting agent ${WAZUH_AGENT_NAME} (manager=${WAZUH_MANAGER_SERVER})"
/var/ossec/bin/wazuh-control start

# Keep container in foreground while streaming logs.
exec tail -F /var/ossec/logs/ossec.log
