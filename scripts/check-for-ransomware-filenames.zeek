# @load policy/protocols/smb

# This script loads a file fsrm_patterns_for_zeek.tsv and then watches SMB file
# transactions to see if any file transactions use any known filenames/patterns
# that are known to be associated with ransomware.
#
# May need to tweak the path of the fsrm_patterns_for_zeek.tsv filename below
# depending on how you're using this. For example, put the script and the tsv
# into /etc/corelight on a software sensor, and adjust the filename below to
# use the absolute path /etc/corelight/fsrm_filenames_for_zeek.tsv

module checkforransomwarefilenames;

type Idx: record {
  index: count;
};

# Value type
type Val: record {
  rw_pattern: string;
};

export {
  redef enum Notice::Type += {
    Ransomware::KnownBadFilename
  };
}

# Initialize table for Input Framework
global ransomware_filename_patterns_table: table[count] of Val;
# Initialize global Paraglob object
global ransomware_filename_patterns_paraglob : opaque of paraglob;

event zeek_init()
  {
  Input::add_table([$source="fsrm_patterns_for_zeek.tsv", $name="ransomware_patterns", $idx=Idx, $val=Val, $destination=ransomware_filename_patterns_table, $mode=Input::REREAD]);
  # Justin says Input::remove is unnecessary, so taking this out for now
  #Input::remove("ransomware_patterns");
  }

event Input::end_of_data(name: string, source: string)
  {
  # Skip any files that aren't relevant to this script
  if (name != "ransomware_patterns")
    return;

  # Now all data is in the table
  # Build the vector that will be used to initialize the paraglob structure

  # Initialize vector (for Paraglob)
  local ransomware_filename_patterns_vector: vector of string;
  # Populate the vector with the records from the table
  for (idx in ransomware_filename_patterns_table)
    {
    ransomware_filename_patterns_vector += ransomware_filename_patterns_table[idx]$rw_pattern;
    }
  # Initialize the paraglob structure
  ransomware_filename_patterns_paraglob = paraglob_init(ransomware_filename_patterns_vector);
  }

# We will use the Files::log_files event to determine when there is a file entry to inspect
event Files::log_files(rec: Files::Info)
  {
  # Skip any files not in SMB/Windows File Sharing or without filenames
  if ( rec$source != "SMB" || !rec?$filename)
    return;

  # Test for matches in the paraglob set
  local num_matches = |paraglob_match(ransomware_filename_patterns_paraglob, rec$filename)|;

  # Have to test the Zeek version since the files.log changed in v5
  # See here: https://docs.zeek.org/en/master/scripts/policy/frameworks/files/deprecated-txhosts-rxhosts-connuids.zeek.html
  @if ( Version::info$major >= 5 && Version::info$minor >= 1 )
  # Handle the v5 files log
    # see if there were any matches
    if ( num_matches > 0 )
      {
      # Handle the alert (Zeek >= 5)
      NOTICE([$note=Ransomware::KnownBadFilename,
              $msg=fmt("Detected potential ransomware! Known bad file name: %s detected in connection [id.orig_h: %s, id.resp_h: %s, uid: %s]", rec$filename, rec$id$orig_h, rec$id$resp_h, rec$uid),
              $src=rec$id$orig_h,  $dst=rec$id$resp_h, $uid=rec$uid]);
      }
  @else
  # Handle the v4 and below files log
    # see if there were any matches
    if ( num_matches > 0 )
      {
      if ( rec?$tx_hosts && rec?$rx_hosts )
        {
        for (tx_host in rec$tx_hosts)
          {
          for (cuid in rec$conn_uids)
            {
            for (rx_host in rec$rx_hosts)
              {
              NOTICE([$note=Ransomware::KnownBadFilename,
                $msg=fmt("Detected potential ransomware! Known bad file name: %s in use by client %s on file server %s", rec$filename, tx_host, rx_host),
                $src=tx_host,  $dst=rx_host, $uid=cuid]);
              }
            }
          }
        return;
        }
      }
  @endif
  }
