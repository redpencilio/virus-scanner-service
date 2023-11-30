export const LOG_INCOMING_DELTA =
  process.env.LOG_INCOMING_DELTA === 'true' || false;
export const LOG_INCOMING_SCAN_REQUESTS =
  process.env.LOG_INCOMING_SCAN_REQUESTS === 'true' || false;
// TODO: MALWARE_ANALYSIS_RESOURCE_BASE
// TODO: VIRUS_SCANNER_CLAMD_DEBUG to set /etc/clamav/clamd.conf Debug.
// TODO: VIRUS_SCANNER_CLAMSCANJS_DEBUGMODE to set ClamScan.debugMode.