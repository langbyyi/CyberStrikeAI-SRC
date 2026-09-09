package handler

import "sync"

// configFileMu serializes complete read-modify-write transactions across
// handlers that share config.yaml. Per-handler locks cannot prevent lost
// updates when another settings page saves a different YAML section.
var configFileMu sync.Mutex
