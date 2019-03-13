import json
import os
import pprint
import time

from requests.models import Response

from bs4 import BeautifulSoup
from censys_interrogate import CensysInterrogate
from cloud_expo import AWSExpo

from Wappalyzer.Wappalyzer import Wappalyzer, WebPage


t = time.time()
a = AWSExpo()

reports = []

#aws_addresses = a.get_ec2_instances()

# Test data
aws_addresses = [
    {
        'interfaces': [
            '74.220.192.208',
            '87.149.162.60',
            '217.92.83.58'
        ]
    }
]


def get_scripts(html_text):

    page_text = BeautifulSoup(html_text, 'html.parser')

    text_to_dict = {
        'stylesheets': page_text.findAll('link', href=True),
        'scripts': page_text.find_all('script', src=True)
        #'external': page_text.find_all('src')
    }

    return text_to_dict


def fake_response(url, html, headers):

    r = Response()

    r._content = https_html.encode()
    r.headers = headers
    r.url = url

    return r

for a in aws_addresses:
    reports.append(CensysInterrogate().ip_report(a.get('interfaces')))

# Let's look at the reports and parse them with bs4

# This will parse through the report from each region, then through each report

for region_report in reports:
    for r in region_report:

        if r.get('report', {}):
            # Only process records with a report
            https_html = r.get('report', {}).get('443', {}).get('https', {}).get('get', {}).get('body', None)
            https_headers = r.get('report', {}).get('443', {}).get('https', {}).get('get', {}).get('headers', None)
            http_html = r.get('report', {}).get('80', {}).get('http', {}).get('get', {}).get('body', None)
            http_headers = r.get('report', {}).get('80', {}).get('http', {}).get('get', {}).get('headers', None)

            if https_html:
                #pprint.pprint(get_scripts(https_html))
                webpage = WebPage.new_from_response(fake_response('test.com', https_html, https_headers))
                wp = Wappalyzer.latest()
                #pprint.pprint(wp.analyze(webpage))
            #if http_html:
            #    print(Wappalyzer().analyze(http_html))

print('run time: {}'.format(time.time() - t))
