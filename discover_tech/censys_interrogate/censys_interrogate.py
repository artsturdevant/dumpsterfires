import json
import logging
import os
import pprint

import censys.ipv4

from censys.base import CensysRateLimitExceededException, CensysNotFoundException


class CensysInterrogate:

    def __init__(self):
        self.conn = censys.ipv4.CensysIPv4(
            api_id=os.getenv('CENSYS_SECRET', None), api_secret=os.getenv('CENSYS_SECRET_KEY')
        )

    def ip_report(self, addresses):

        conn = self.conn

        report = []

        for address in addresses:
            try:
                report.append(
                    {
                        'ip': address,
                        'report': conn.view(address)
                    }
                )
            except CensysNotFoundException as e:
                report.append(
                    {
                        'ip': address,
                        'report': {}
                    }
                )
            except CensysRateLimitExceededException as e:
                logging.warning('Rate limit exceeded. {} could not be queried'.format(address))
            except Exception as e:
                logging.critical('Something went wrong... Error: {}'.format(e))
                raise e

        return report
