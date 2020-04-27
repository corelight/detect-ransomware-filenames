import requests
import json

# URL that the search patterns are hosted at
url = "https://fsrm.experiant.ca/api/v1/combined"

# Download the (JSON-formatted) list
response = requests.get(url)

# Read the list into a JSON object
json_structure = json.loads(response.text)

# Open the output file
outfile = open("fsrm_patterns_for_zeek.tsv","w+")

# Add the header information
outfile.write("#fields" + "\t" + "index" + "\t" + "rw_pattern" + "\n")

# Prep the index
index = 0

# Iterate through the list of filters (patterns)
for filter in json_structure["filters"]:
    # Escape certain literals []? in the string, because Paraglob 
    # uses them to break up the strings into meta-words
    filter = filter.replace("[", "\[")
    filter = filter.replace("]", "\]")
    filter = filter.replace("?", "\?")
    # Hack to deal with one of the records that has an unexpected \n in it
    for filter2 in filter.split("\n"):
        # Write out the reformatted filter as a new line in the file
        outfile.write(str(index) + "\t" + filter2 + "\n")
        index += 1

# Close the file
outfile.close()
