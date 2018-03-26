# Copyright (c) 2016-2017, Matteo Cafasso
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import logging
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from vminspect.filesystem import FileSystem

from load_cve import load_local

class VulnScanner:
    """Vulnerability scanner.

    Allows to scan the given disk content and query
    a CVE DB for vulnerabilities.

    disk must contain the path of a valid disk image.

    """
    def __init__(self, disk, cvefeed):
        self._disk = disk
        self._filesystem = None
        self._cvefeed = load_local(cvefeed)['CVE_Items']
        self.logger = logging.getLogger(
            "%s.%s" % (self.__module__, self.__class__.__name__))
        self.logger.setLevel(50)

    def __enter__(self):
        self._filesystem = FileSystem(self._disk)
        self._filesystem.mount()

        return self

    def __exit__(self, *_):
        self._filesystem.umount()

    def __getattr__(self, attr):
        return getattr(self._filesystem, attr)

    def scan(self, concurrency=1):
        """Iterates over the applications installed within the disk
        and queries the CVE DB to determine whether they are vulnerable.

        Concurrency controls the amount of concurrent queries
        against the CVE DB.

        For each vulnerable application the method yields a namedtuple:

        VulnApp(name             -> application name
                version          -> application version
                vulnerabilities) -> list of Vulnerabilities

        Vulnerability(id       -> CVE Id
                      summary) -> brief description of the vulnerability

        """
        self.logger.debug("Scanning FS content.")

        applications = self.applications()
        #print("#####application versions: ######")
        #for application in applications:
            #print(application.name + " : " + application.version + " : " + application.publisher)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = executor.map(self.query_vulnerabilities,
                                   self.applications()) 
        for report in results:
            #TODO: implement output design here for each application in correct json format
            application, vulnerabilities = report                              
            #vulnerabilities = list(lookup_vulnerabilities(application.version,
            #                                              vulnerabilities))
                
            if vulnerabilities:
            #    full_vulnerabilities = [FullVuln(v.id, v.summary, self.query_cve_info(v.id)) for v in vulnerabilities]
                yield VulnApp(application.name,
                              application.version,
                              vulnerabilities)

    def query_vulnerabilities(self, application):
        self.logger.debug("Quering %s vulnerabilities.", application.name)

        name = application.name.lower()
        version = application.version
        results = []
        for cve in self._cvefeed:
            vendor_list = cve['cve']['affects']['vendor']['vendor_data']
            for vendor in vendor_list:
                for product in vendor['product']['product_data']: 
                    if product['product_name'].lower() == name:
                        product_versions_list = product['version']['version_data']
                        if {'version_value' : version} in product_versions_list:
                            #print(name + ":" + cve['cve']['CVE_data_meta']['ID'] + ":" + version)
                            results.append(cve)
        return application, results
            

    def query_cve_info(self, cve_id):
        # query local cve database
        result = [item['cve'] for item in self._cvefeed if item['cve']['CVE_data_meta']['ID'] == cve_id]
        return result
        

    def applications(self):
        return (Application(a['app2_name'], a['app2_version'], a['app2_publisher'])
                for a in self._filesystem.inspect_list_applications2(
                        self._filesystem._root))


def lookup_vulnerabilities(app_version, vulnerabilities):
    for vulnerability in vulnerabilities:
        for configuration in vulnerability['vulnerable_configuration']:
            try:
                vuln_version = configuration.split(':')[5]
            except IndexError:
                pass
            else:
                if app_version == vuln_version:
                    yield Vulnerability(vulnerability['id'],
                                        vulnerability['summary'])


VulnApp = namedtuple('VulnApp', ('name',
                                 'version',
                                 'vulnerabilities'))
Application = namedtuple('Application', ('name',
                                         'version',
                                         'publisher'))
Vulnerability = namedtuple('Vulnerability', ('id',
                                             'summary'))
FullVuln = namedtuple('FullVuln', ('id', 'summary', 'impact'))
