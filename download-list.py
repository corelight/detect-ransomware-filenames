import requests
import json

# URL that the search patterns are hosted at
url = "https://fsrm.experiant.ca/api/v1/combined"
filename = "inputs/fsrm_patterns_for_zeek.tsv"

# Download the (JSON-formatted) list
try:
    print("Getting %s" % url)
    response = requests.get(url)
except:
    print("Failed to get %s" % url)
    quit(1)

# Read the list into a JSON object
try:
    print("Parsing JSON response")
    json_structure = json.loads(response.text)
except:
    print("Error parsing JSON")
    quit(1)

# Open the output file
try:
    print("Opening output file %s" % filename)
    outfile = open(filename, "w+")
except:
    print("Error opening output file %s" % filename)
    quit(1)

# Add the header information
try:
    print("Writing header to file")
    outfile.write("#fields" + "\t" + "index" + "\t" + "rw_pattern" + "\n")
except:
    print("Error writing header to file")
    quit(1)

# Prep the index
index = 0

# Iterate through the list of filters (patterns)
try:
    print("Writing filters to output file")
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
except:
    print("Failed to write filters to output file")
    quit(1)

# Close the file
try:
    print("Closing output file")
    outfile.close()
except:
    print("Failed to close output file")
    quit(1)

quit(0)
