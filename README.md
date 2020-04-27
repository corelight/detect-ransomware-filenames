# Detect Ransomware Filenames

This package/script watches SMB transactions to look for known bad filenames
that ransomware is known to use. It rides on top of the Anti-Ransomware File
System Resource Manager Lists maintained [here](https://fsrm.experiant.ca/).

A Python script is included to be able to refresh the list periodically.

The script generates notices like the following:

```{
  "_path": "notice",
  "_system_name": "bas-cl-swsensor-01",
  "_write_ts": "2020-04-27T21:40:10.494579Z",
  "_node": "worker-02",
  "ts": "2020-04-27T21:40:10.494579Z",
  "uid": "CNhUff2G2TzzRoQi45",
  "note": "Ransomware::KnownBadFilename",
  "msg": "Detected potential ransomware! Known bad file name: test3.hj36MM in use by client 10.0.2.51 on file server 172.16.4.66",
  "src": "10.0.2.51",
  "dst": "172.16.4.66",
  "peer_descr": "worker-02",
  "actions": [
    "Notice::ACTION_LOG"
  ],
  "suppress_for": 3600
}```