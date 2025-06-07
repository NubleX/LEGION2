from pyShodan import PyShodan

class PyShodanScript():
    def __init__(self):
        self.dbHost = None
        self.session = None

    def setDbHost(self, dbHost):
        self.dbHost = dbHost

    def setSession(self, session):
        self.session = session

    def run(self):
        print('Running PyShodan Class')
        if self.dbHost:
            pyShodanObj = PyShodan(apiKey="SNYEkE0gdwNu9BRURVDjWPXePCquXqht")
            pyShodanObj.createSession()
            pyShodanResults = pyShodanObj.searchIp(self.dbHost.ipv4, allData = True)
            if isinstance(pyShodanResults, dict):
                if pyShodanResults:
                    self.dbHost.latitude = pyShodanResults.get('latitude', 'unknown')
                    self.dbHost.longitude = pyShodanResults.get('longitude', 'unknown')
                    self.dbHost.asn = pyShodanResults.get('asn', 'unknown')
                    self.dbHost.isp = pyShodanResults.get('isp', 'unknown')
                    self.dbHost.city = pyShodanResults.get('city', 'unknown')
                    self.dbHost.countryCode = pyShodanResults.get('country_code', 'unknown')
                    self.session.add(self.dbHost)
            else:
                print(f"Unexpected result type from pyShodanObj.searchIp: {type(pyShodanResults)} - {pyShodanResults}")

if __name__ == "__main__":
    pass
