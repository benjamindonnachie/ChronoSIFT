"""F06: an absent address is not a failed detection-input database."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from geoip2.errors import AddressNotFoundError
from maxminddb.errors import InvalidDatabaseError
import pandas as pd
import chronoSIFT_v2_31 as c

OUTPUTS = {role: 'fixture_' + role for role in c.GEOIP_ENRICHMENT_OUTPUT_ROLES}


def readers():
    city = Mock()
    city.city.return_value = SimpleNamespace(
        city=SimpleNamespace(geoname_id=123, name='Example'),
        country=SimpleNamespace(iso_code='GB'),
        location=SimpleNamespace(latitude=51.5, longitude=-0.1))
    asn = Mock()
    asn.asn.return_value = SimpleNamespace(autonomous_system_number=64500)
    return city, asn


class GeoIPFailuresTest(unittest.TestCase):
    def enrich(self, values):
        return c.build_geoip_enrichment_table(
            pd.DataFrame({'source_ip': values}), 'city.mmdb', 'asn.mmdb',
            ip_field='source_ip', output_fields=OUTPUTS)

    def test_success_deduplicates_ipv4_and_ipv6_and_closes_readers(self):
        city, asn = readers()
        with patch.object(c.geoip2_database, 'Reader', side_effect=[city, asn]):
            out = self.enrich(['8.8.8.8', '8.8.8.8', '2606:4700:4700::1111'])
        self.assertEqual(len(out), 2)
        self.assertEqual(city.city.call_count, 2)
        self.assertEqual(asn.asn.call_count, 2)
        self.assertEqual(out.fixture_city_name.tolist(), ['Example', 'Example'])
        self.assertEqual(out.fixture_asn.tolist(), [64500, 64500])
        city.close.assert_called_once_with()
        asn.close.assert_called_once_with()

    def test_expected_misses_remain_independent(self):
        for missing in ('city', 'asn', 'both'):
            with self.subTest(missing=missing):
                city, asn = readers()
                if missing in ('city', 'both'):
                    city.city.side_effect = AddressNotFoundError('No record')
                if missing in ('asn', 'both'):
                    asn.asn.side_effect = AddressNotFoundError('No record')
                with patch.object(c.geoip2_database, 'Reader', side_effect=[city, asn]):
                    out = self.enrich(['8.8.8.8'])
                self.assertEqual(bool(pd.isna(out.fixture_city_name.iloc[0])), missing in ('city', 'both'))
                self.assertEqual(bool(pd.isna(out.fixture_asn.iloc[0])), missing in ('asn', 'both'))
                city.close.assert_called_once_with()
                asn.close.assert_called_once_with()

    def test_unexpected_city_failures_propagate_and_close_both(self):
        self.check_reader_failures('city')

    def test_unexpected_asn_failures_propagate_and_close_both(self):
        self.check_reader_failures('asn')

    def check_reader_failures(self, kind):
        for error in (InvalidDatabaseError('Corrupt database'), OSError('Read failure'),
                      TypeError('Wrong database type'), RuntimeError('Reader failure')):
            with self.subTest(kind=kind, error=type(error).__name__):
                city, asn = readers()
                getattr(city if kind == 'city' else asn, kind).side_effect = error
                with patch.object(c.geoip2_database, 'Reader', side_effect=[city, asn]):
                    with self.assertRaises(type(error)) as raised:
                        self.enrich(['8.8.8.8'])
                self.assertIs(raised.exception, error)
                city.close.assert_called_once_with()
                asn.close.assert_called_once_with()

    def test_malformed_reader_response_is_not_a_miss(self):
        city, asn = readers()
        city.city.return_value = SimpleNamespace(city=SimpleNamespace(geoname_id=123))
        with patch.object(c.geoip2_database, 'Reader', side_effect=[city, asn]):
            with self.assertRaises(AttributeError):
                self.enrich(['8.8.8.8'])
        city.close.assert_called_once_with()
        asn.close.assert_called_once_with()

    def test_asn_open_failure_closes_city(self):
        city, _ = readers()
        with patch.object(c.geoip2_database, 'Reader', side_effect=[city, OSError('Cannot open ASN')]):
            with self.assertRaisesRegex(OSError, 'Cannot open ASN'):
                self.enrich(['8.8.8.8'])
        city.close.assert_called_once_with()

    def test_city_open_failure_propagates(self):
        with patch.object(c.geoip2_database, 'Reader', side_effect=OSError('Cannot open City')) as factory:
            with self.assertRaisesRegex(OSError, 'Cannot open City'):
                self.enrich(['8.8.8.8'])
        factory.assert_called_once_with('city.mmdb')

    def test_real_invalid_database_file_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'broken.mmdb'
            path.write_bytes(b'not a MaxMind database')
            with self.assertRaises(InvalidDatabaseError):
                c.build_geoip_enrichment_table(pd.DataFrame({'source_ip': ['8.8.8.8']}),
                    str(path), str(path), ip_field='source_ip', output_fields=OUTPUTS)

    def test_private_invalid_and_placeholder_inputs_do_not_query_readers(self):
        city, asn = readers()
        with patch.object(c.geoip2_database, 'Reader', side_effect=[city, asn]):
            out = self.enrich(['10.0.0.1', '127.0.0.1', 'not-an-ip', None, '-', '', 'NULL'])
        self.assertEqual(out.source_ip.tolist(), ['10.0.0.1', '127.0.0.1', 'not-an-ip'])
        self.assertTrue(out[list(OUTPUTS.values())].isna().all().all())
        city.city.assert_not_called()
        asn.asn.assert_not_called()

    def test_absent_or_empty_input_does_not_open_databases(self):
        with patch.object(c.geoip2_database, 'Reader') as factory:
            self.assertTrue(self.enrich([]).empty)
            self.assertTrue(c.build_geoip_enrichment_table(pd.DataFrame(), 'unused', 'unused',
                ip_field='source_ip', output_fields=OUTPUTS).empty)
        factory.assert_not_called()
