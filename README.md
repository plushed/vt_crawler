# vt_crawler


# Usage
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
