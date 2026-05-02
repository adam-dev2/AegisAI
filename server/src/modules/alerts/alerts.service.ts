import { rapid7ClientVersion2 } from '../siem/rapid7.client.js';

export async function fetchAlerts(
  investigationId?: string,
  limit = 50
) {
  const url = investigationId
    ? `/investigations/${encodeURIComponent(investigationId)}/alerts`
    : '/alerts';

  const response = await rapid7ClientVersion2.get(url, {
    params: { size: limit },
  });
  return response.data?.data ?? [];
}

export async function fetchAlertById(alertId: string) {
  const response = await rapid7ClientVersion2.get(`/alerts/${encodeURIComponent(alertId)}`);
  return response.data;
}

export async function updateAlertStatus(alertId: string, status: string) {
  const response = await rapid7ClientVersion2.patch(`/alerts/${encodeURIComponent(alertId)}`, {
    status,
  });
  return response.data;
}
