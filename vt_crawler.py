import requests
import configparser
import os.path
import sys
import argparse
import datetime
import base64

VERSION = "0.1"

# Start
# Print Banner


def banner():
    banner = '''
                                    _ _                           _     
oooooo     oooo ooooooooooooo        .oooooo.                                       oooo                          
 `888.     .8'  8'   888   `8       d8P'  `Y8b                                      `888                          
  `888.   .8'        888           888          oooo d8b  .oooo.   oooo oooo    ooo  888   .ooooo.  oooo d8b      
   `888. .8'         888           888          `888""8P `P  )88b   `88. `88.  .8'   888  d88' `88b `888""8P      
    `888.8'          888           888           888      .oP"888    `88..]88..8'    888  888ooo888  888          
     `888'           888           `88b    ooo   888     d8(  888     `888'`888'     888  888    .o  888          
      `8'           o888o           `Y8bood8P'  d888b    `Y888""8o     `8'  `8'     o888o `Y8bod8P' d888b  
'''
    print(banner)
    print("**********************VT Crawler -v" + VERSION + "**************************")


# Usage
def usage():
    usage = """
        -h --help       Prints this help
        -c --config     Required parameter. Specify config, otherwise uses example.conf

        --------------------------Simple Search----------------------------
        -s --infile     Search a list of keywords or IOCs in a file
        
        ------Options-----
        -d --domain   Search domain objects
        -f --file     Search file objects
        -u --url      Search URL objects
        -ip --ip      Search IP objects

        Example: python vt_crawler.py -f -s 83d05d3289bdf31aa63d49fd36fe59b25656d2a6 -c
        Example: python vt_crawler.py -i -s 8.8.8.8 -c
        """
    print(usage)
    sys.exit


#####################################
#  VT Main #
#####################################w

def vt_main():
    # Config file processing & analysis
    if os.path.exists(args.c):
        try:
            config = configparser.ConfigParser()
            config.read(args.c)
            # Config.sections()
            # Assigned VT variables
            vt_api = config.get('VT', 'api_key')
            vt_url = config.get('VT', 'api_url')
            # Build header
            vt_header = {'x-apikey': vt_api}
            # Assigned proxy variables
            proxy = config.get('PROXY', 'proxy')
            proxy_user = config.get('PROXY', 'username')
            proxy_password = config.get('PROXY', 'password')
            proxy_creds = proxy_user + ':' + proxy_password
        except FileNotFoundError:
            sys.exc_info()
    else:
        print("No such file '{}'".format(args.c), file=sys.stderr)
        exit()
    # Simple search and collection assignment
    if args.s:
        vt_value = args.s
        if args.i:
            vt_collection = 'ip_addresses'
            vt_request = vt_url + vt_collection
            # Call IP search function
            vt_simple_search_ips(vt_request, vt_value, vt_header)
        elif args.f:
            vt_collection = 'files'
            vt_request = vt_url + vt_collection
            # Call file search function
            vt_simple_search_files(vt_request, vt_value, vt_header)
        elif args.d:
            vt_collection = 'domains'
            vt_request = vt_url + vt_collection
            # Call domain search function
            vt_simple_search_domains(vt_request, vt_value, vt_header)
        elif args.u:
            vt_collection = 'urls'
            # Covert to byte type for base64 encoding
            vt_value = vt_value.encode('utf-8')
            # Perform base64 encoding
            vt_value = base64.urlsafe_b64encode(vt_value)
            # Covert back to string for strip
            vt_value = str(vt_value).strip("b'")
            vt_value = vt_value.strip("=")
            vt_request = vt_url + vt_collection
            # Call URL search function
            vt_simple_search_urls(vt_request, vt_value, vt_header)


# Function to pull from nested JSON output
def extract_values(obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    results = ' '.join(map(str, results))
    return results


# Function to search VT for hashes
def vt_simple_search_files(vt_request, vt_value, vt_header):
    # Perform get request
    url = requests.get(vt_request + '/' + vt_value, headers=vt_header, verify=False)
    with url as result:
        # Check web response
        if result.status_code == 200:
            # Assign JSON response to data variable
            data = result.json()
            for obj in data:
                print('*' * 15 + 'Main Results:' + '*' * 15)
                meaningful_name = extract_values(data, 'meaningful_name')
                md5_hash = extract_values(data, 'md5')
                file_type = extract_values(data, 'file_type')
                size = extract_values(data, 'size')
                print('Name: ' + str(meaningful_name))
                print('Type: ' + str(file_type))
                print('MD5: ' + str(md5_hash))
                print('Size: ' + str(size))
                submission_date = extract_values(data, 'first_submission_date')
                submission_date = int(submission_date)
                submission_date = datetime.datetime.fromtimestamp(submission_date).strftime('%c')
                last_submission_date = extract_values(data, 'last_submission_date')
                last_submission_date = int(last_submission_date)
                last_submission_date = datetime.datetime.fromtimestamp(last_submission_date).strftime('%c')
                times_submitted = extract_values(data, 'times_submitted')
                self = extract_values(data, 'self')
                print('First Submission Date: ' + str(submission_date))
                print('Last Submission Date: ' + str(last_submission_date))
                print('Times Submitted: ' + str(times_submitted))
                print('Link: ' + str(self))
                analysis(data)
        # Typical errors
        elif result.status_code == 204:
            print('Request rate limit exceeded.')
        elif result.status_code == 400:
            print('Bad Request.')
        elif result.status_code == 403:
            print('Forbidden.')
        elif result.status_code == 403:
            print('Authentication or API key issue.')
        else:
            print("Unable to generate request")


# Function to search VT for URLs
def vt_simple_search_urls(vt_request, vt_value, vt_header):
    # Perform get request
    url = requests.get(vt_request + '/' + vt_value, headers=vt_header, verify=False)
    with url as result:
        # Check web response
        if result.status_code == 200:
            # Assign JSON response to data variable
            data = result.json()
            for obj in data:
                print('*' * 15 + 'Main Results:' + '*' * 15)
                url = extract_values(data, 'url')
                print('Name: ' + str(url))
                submission_date = extract_values(data, 'first_submission_date')
                submission_date = int(submission_date)
                submission_date = datetime.datetime.fromtimestamp(submission_date).strftime('%c')
                last_submission_date = extract_values(data, 'last_submission_date')
                last_submission_date = int(last_submission_date)
                last_submission_date = datetime.datetime.fromtimestamp(last_submission_date).strftime('%c')
                times_submitted = extract_values(data, 'times_submitted')
                self = extract_values(data, 'self')
                print('First Submission Date: ' + str(submission_date))
                print('Last Submission Date: ' + str(last_submission_date))
                print('Times Submitted: ' + str(times_submitted))
                print('Link: ' + str(self))
                analysis(data)
        # Typical errors
        elif result.status_code == 204:
            print('Request rate limit exceeded.')
        elif result.status_code == 400:
            print('Bad Request.')
        elif result.status_code == 403:
            print('Forbidden.')
        elif result.status_code == 403:
            print('Authentication or API key issue.')
        else:
            print("Unable to generate request")


# Function to search VT for IPs
def vt_simple_search_ips(vt_request, vt_value, vt_header):
    # Perform get request
    url = requests.get(vt_request + '/' + vt_value, headers=vt_header, verify=False)
    with url as result:
        # Check web response
        if result.status_code == 200:
            # Assign JSON response to data variable
            data = result.json()
            for obj in data:
                print('*' * 15 + 'Main Results:' + '*' * 15)
                id = extract_values(data, 'id')
                asn = extract_values(data, 'asn')
                as_owner = extract_values(data, 'as_owner')
                country = extract_values(data, 'country')
                print('Name: ' + str(id))
                print('ASN: ' + str(asn))
                print('AS Owner: ' + str(as_owner))
                print('Country: ' + str(country))
                self = extract_values(data, 'self')
                print('Link: ' + str(self))
                analysis(data)
        # Typical errors
        elif result.status_code == 204:
            print('Request rate limit exceeded.')
        elif result.status_code == 400:
            print('Bad Request.')
        elif result.status_code == 403:
            print('Forbidden.')
        elif result.status_code == 403:
            print('Authentication or API key issue.')
        else:
            print("Unable to generate request")


# Function to search VT for domains
def vt_simple_search_domains(vt_request, vt_value, vt_header):
    # Perform get request
    url = requests.get(vt_request + '/' + vt_value, headers=vt_header, verify=False)
    with url as result:
        # Check web response
        if result.status_code == 200:
            # Assign JSON response to data variable
            data = result.json()
            for obj in data:
                print('*' * 15 + 'Main Results:' + '*' * 15)
                self = extract_values(data, 'self')
                registrar = extract_values(data, 'registrar')
                reputation = extract_values(data, 'reputation')
                alexa = extract_values(data, 'Alexa')
                websense = extract_values(data, 'Websense ThreatSeeker')
                print('Link: ' + str(self))
                print('Registrar: ' + str(registrar))
                print('Reputation: ' + str(reputation))
                print('Categories: ' + '\nAlexa: ' + str(alexa) + '\nWebsense: ' + str(websense))
                analysis(data)
        # Typical errors
        elif result.status_code == 204:
            print('Request rate limit exceeded.')
        elif result.status_code == 400:
            print('Bad Request.')
        elif result.status_code == 403:
            print('Forbidden.')
        elif result.status_code == 403:
            print('Authentication or API key issue.')
        else:
            print("Unable to generate request")


# Process analysis for each request
def analysis(data):
    category = extract_values(data, 'category')
    # Convert category to list
    category = list(category.split(" "))
    # Get totals
    harmless_count = category.count('harmless')
    undetected_count = category.count('undetected')
    suspicious_count = category.count('suspicious')
    malicious_count = category.count('malicious')
    print('*' * 15 + 'Analysis Results:' + '*' * 15)
    print('Harmless:', harmless_count)
    print('Undetected:', undetected_count)
    print('Suspicious:', suspicious_count)
    print('Malicious:', malicious_count)
    print('*' * 47)
    # Calculate percentage of detections
    totals = str((suspicious_count + malicious_count) / (harmless_count + undetected_count)
                 * 100)
    print(str(totals + '% detection rate'))


if __name__ == '__main__':
    banner()
    usage()
    # Arg Parse
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Config File', nargs='?', required=True, const='./conf/example.conf',
                        dest="c")
    parser.add_argument('-s', '--search', help='Basic Search', dest="s")
    # Search Commands
    search_group = parser.add_mutually_exclusive_group()
    search_group.add_argument('-f', help='File', action='store_true', dest="f")
    search_group.add_argument('-d', help='Domain', action='store_true', dest="d")
    search_group.add_argument('-i', help='IP', action='store_true', dest="i")
    search_group.add_argument('-u', help='URL', action='store_true', dest="u")
    args = parser.parse_args()
    vt_main()