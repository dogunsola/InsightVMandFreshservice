import csv
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapid7_freshservice_sync.cli import main


class ConsoleExportTests(unittest.TestCase):
    def test_export_uses_v3_routes_and_creates_freshservice_ticket(self):
        origin = 'https://security-console.example:3780/api/3'
        def page(records):
            return {'resources': records, 'page': {'totalPages': 1}}
        responses = {
            ('GET', '/vulnerabilities'): page([
                {'id': 'apache-vuln', 'title': 'Apache vulnerability', 'severity': 'Critical'},
                {'id': 'moderate', 'title': 'Apache issue', 'severity': 'Moderate'},
                {'id': 'ms', 'title': 'Other', 'severity': 'Severe', 'categories': ['Microsoft Patch']},
            ]),
            ('GET', '/asset_groups'): page([{'id': 8, 'name': 'workstations/laptops'}]),
            ('GET', '/asset_groups/8/assets'): {'resources': [42]},
            ('POST', '/assets/search'): page([{'id': 42, 'hostName': 'laptop.example'}]),
            ('GET', '/assets/42/vulnerabilities'): page([
                {'id': 'apache-vuln', 'status': 'vulnerable'},
                {'id': 'moderate', 'status': 'vulnerable'},
                {'id': 'ms', 'status': 'vulnerable'},
                {'id': 'exception', 'status': 'invulnerable'},
            ]),
            ('GET', '/vulnerabilities/apache-vuln/solutions'): {'resources': ['apache-upgrade']},
            ('GET', '/solutions/apache-upgrade'): {
                'summary': {'text': 'Upgrade Apache'}, 'steps': {'text': 'Install latest release'},
            },
            ('POST', '/tickets'): {'ticket': {'id': 100, 'status': 2}},
        }
        seen = []
        filter_requests = 0

        def request(client, method, url, **kwargs):
            nonlocal filter_requests
            if url.startswith(origin + '/'):
                self.assertEqual(client.headers['Authorization'], 'Basic dXNlcjpwYXNzd29yZA==')
                self.assertNotIn('X-Api-Key', client.headers)
                key = (method, url[len(origin):].split('?')[0])
                seen.append(key)
                return responses[key]
            freshservice_origin = 'https://example.freshservice.com/api/v2'
            self.assertTrue(url.startswith(freshservice_origin + '/'), url)
            self.assertEqual(client.headers['Authorization'], 'Basic ZnJlc2gta2V5Olg=')
            key = (method, url[len(freshservice_origin):].split('?')[0])
            if key == ('GET', '/tickets/filter'):
                filter_requests += 1
                return {'tickets': [], 'total': 0}
            if key == ('POST', '/tickets'):
                seen.append(key)
                self.assertEqual(kwargs['json_body']['email'], 'security@example.com')
                self.assertEqual(kwargs['json_body']['status'], 2)
                return responses[key]
            self.fail(f'Unexpected Freshservice request: {method} {url}')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'export.csv'
            with patch.dict(os.environ, {
                'RAPID7_CONSOLE_URL': origin.removesuffix('/api/3'),
                'RAPID7_CONSOLE_USERNAME': 'user', 'RAPID7_CONSOLE_PASSWORD': 'password',
                'FRESHSERVICE_DOMAIN': 'https://example.freshservice.com',
                'FRESHSERVICE_API_KEY': 'fresh-key',
                'FRESHSERVICE_REQUESTER_EMAIL': 'security@example.com',
            }, clear=True), patch(
                'sys.argv', ['sync', '--output', str(output), '--create-tickets']
            ), patch(
                'rapid7_freshservice_sync.http.HttpClient.request_json', new=request
            ):
                main()
            with output.open(newline='') as file:
                self.assertEqual(list(csv.reader(file)), [
                    ['Hosts', 'Solution', 'Fix details'],
                    ['laptop.example', 'Upgrade Apache', 'Install latest release'],
                ])
        self.assertEqual(set(seen), set(responses))
        self.assertEqual(filter_requests, 2)
