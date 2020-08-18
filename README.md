# Detect Ransomware Filenames

This package/script watches SMB transactions to look for known bad filenames
that ransomware is known to use. It rides on top of the Anti-Ransomware File
System Resource Manager Lists maintained [here](https://fsrm.experiant.ca/).

## How to use

A Python script (`download-list.py`) is included to be able to refresh the
list periodically. By default, it will download the new file to the `inputs/`
folder.

Use `zkg` to install this, the way you would any Zeek package.

The script generates notices like the following:

```
{
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
}
```

If/when you get a notice, investigate, ideally as quickly as possible!

## License

Please read the license file [here](./LICENSE) for information about the license
for this software.
