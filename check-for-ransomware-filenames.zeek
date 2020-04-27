# @load policy/protocols/smb

# This script loads a file fsrm_patterns_for_zeek.tsv and then watches SMB file
# transactions to see if any file transactions use any known filenames/patterns
# that are known to be associated with ransomware.
#
# Either place the file fsrm_patterns_for_zeek.tsv in the same directory as this file
# or modify the script below to reference the file by its absolute path

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
# Initialize vector (for Paraglob)
global ransomware_filename_patterns_vector: vector of string;
# Initialize global Paraglob object
global ransomware_filename_patterns_paraglob = paraglob_init(ransomware_filename_patterns_vector);

event zeek_init()
	{
	Input::add_table([$source="./fsrm_patterns_for_zeek.tsv", $name="ransomware_patterns", $idx=Idx, $val=Val, $destination=ransomware_filename_patterns_table, $mode=Input::REREAD]);
  Input::remove("ransomware_patterns");
	}

event Input::end_of_data(name: string, source: string)
  {
	# now all data is in the table
	# build the vector that will be used to initialize the paraglob structure
	for (idx in ransomware_filename_patterns_table)
		{
		ransomware_filename_patterns_vector += ransomware_filename_patterns_table[idx]$rw_pattern;
	  }
  # initialize the paraglob structure
	ransomware_filename_patterns_paraglob = paraglob_init(ransomware_filename_patterns_vector);
}

# we will use the Files::log_files event to determine when there is a file entry to inspect
event Files::log_files(rec: Files::Info)
  {
  if ( rec$source == "SMB" )
    {
		# test for matches in the paraglob set
		local num_matches = |paraglob_match(ransomware_filename_patterns_paraglob, rec$filename)|;
		# see if there were any matches
		if ( num_matches > 0 )
      {
      for (tx_host in rec$tx_hosts)
        {
        for (cuid in rec$conn_uids)
          {
          for (rx_host in rec$rx_hosts)
            {
						NOTICE([$note=Ransomware::KnownBadFilename,
            	$msg=fmt("Detected potential ransomware! Known bad file name: %s in use by client %s on file server %s", rec$filename, tx_host, rx_host),
            	$src=tx_host,	$dst=rx_host, $uid=cuid]);
            }
          }
        }
      }
    }
	}
