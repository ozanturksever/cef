import unittest
from cef_parser import CefParser, ParseFailed

TEST_LINE = 'Aug 2 12:30:38 Innotim-PC CEF:0|Trend Micro|Deep Security Agent|8.0.2224|10|Renewal Error|10|cn1=1 cn1Label=Host ID dvc=192.168.1.48 dmac=00:0C:29:C7:C1:03 smac=B8:8D:12:55:93:76 TrendMicroDsFrameType=IP src=192.168.1.93 dst=192.168.1.48 in=252 cs3=DF 0 cs3Label=Fragmentation Bits proto=TCP spt=59028 dpt=4119 cs2=ACK PSH cs2Label=TCP Flags cnt=1 act=Reset cn2=-309 cn2Label=DPI Reason cn3=0 cn3Label=DPI Packet Position cs5=0 cs5Label=DPI Stream Position cs6=8 cs6Label=DPI Flags'
#TEST_LINE ='Aug 2 11:56:04 Innotim-PC CEF:0|Trend Micro|Deep Security Agent|8.0.2224|21|IPv6 Packet|5|cn1=1 cn1Label=Host ID dvc=192.168.1.48 act=Deny dmac=33:33:00:00:00:0C smac=00:26:4D:2B:2D:4B TrendMicroDsFrameType=IPv6 src=fe80:0:0:0:fc50:a94f:4328:e94c dst=ff02:0:0:0:0:0:0:c in=208 cs3= cs3Label=Fragmentation Bits proto=UDP spt=0 dpt=0 cnt=1'
#TEST_LINE ='Aug 4 14:02:07 Innotim-PC CEF:0|Trend Micro|Deep Security Agent|8.0.2224|21|Out Of Allowed Policy|5|cn1=1 cn1Label=Host ID dvc=192.168.1.48 act=Deny dmac=00:0C:29:C7:C1:03 smac=00:00:00:00:00:00 TrendMicroDsFrameType=IP src=10.0.0.0 dst=224.0.0.1 in=60 cs3= cs3Label=Fragmentation Bits proto=IGMP spt=0 dpt=0 cnt=1'
class test_cef(unittest.TestCase):
    def setUp(self):
        self.p = CefParser(TEST_LINE)

    def test_parse_syslog_header(self):
        msg = self.p.get_syslog_message()
        self.assertEqual(msg['date'], 'Aug 2 12:30:38')
        self.assertEqual(msg['host'], 'Innotim-PC')

    def test_parse_cef_message(self):
        msg = self.p.get_cef_message()
        self.assertEqual(msg['device_vendor'], 'Trend Micro')
        self.assertEqual(msg['device_product'], 'Deep Security Agent')
        self.assertEqual(msg['device_version'], '8.0.2224')
        self.assertEqual(msg['severity'], '10')
        self.assertEqual(msg['version'], 'CEF:0')

    def test_get_extension_keys(self):
        keys = self.p.get_extension_keys()
        self.assertTrue('src' in keys)
        self.assertTrue('dvc' in keys)

    def test_get_extension_values(self):
        vals = self.p.get_extension_values()
        self.assertEqual(vals['cn1'], '1')
        self.assertEqual(vals['src'], '192.168.1.93')

    def test_get_common_values(self):
        vals = self.p.get_with_common_values()
        self.assertEqual(vals['src'], '192.168.1.93')
        self.assertEqual(vals['Host ID'], '1')

    def test_replace_space(self):
        p = CefParser(TEST_LINE, '')
        vals = p.get_with_common_values()
        self.assertEqual(vals['src'], '192.168.1.93')
        self.assertEqual(vals['HostID'], '1')
        self.assertEqual(vals['FragmentationBits'], 'DF 0')
        self.assertFalse(vals.has_key('cs3'))

    def test_get(self):
        vals = self.p.get()
        self.assertEqual(vals['src'], '192.168.1.93')
        self.assertEqual(vals['device_vendor'],'Trend Micro')

    def test_not_parse_raises_parsefailed(self):
        self.assertRaises(ParseFailed, CefParser, ('bla'))

    def test_sample_1(self):
        line='Aug  2 11:56:04 Innotim-PC CEF:0|Trend Micro|Deep Security Agent|8.0.2224|21|IPv6 Packet|5|cn1=1 cn1Label=Host ID dvc=192.168.1.48 act=Deny dmac=33:33:00:00:00:0C smac=00:26:4D:2B:2D:4B TrendMicroDsFrameType=IPv6 src=fe80:0:0:0:fc50:a94f:4328:e94c dst=ff02:0:0:0:0:0:0:c in=208 cs3= cs3Label=Fragmentation Bits proto=UDP spt=0 dpt=0 cnt=1'
        p = CefParser(line, '')
        vals = p.get()
        self.assertTrue(isinstance(vals, dict))

    def test_sample_2(self):
        line='Aug  2 11:56:04 Innotim-PC CEF:0|Trend Micro|Deep Security Manager|8.0.1046|600|User Signed In|3|src=10.52.116.160 suser=admin target=admin msg=User signed in from fe80:0:0:0:2d02:9870:beaa:fd41'
        p = CefParser(line, '')
        vals = p.get()
        self.assertTrue(isinstance(vals, dict))

    def test_sample_3(self):
        line='Aug  2 11:56:04 Innotim-PC CEF:0|Trend Micro|Deep Security Agent|8.0.0.995|30|New Integrity Monitoring Rule|6|cn1=1 cn1Label=Host ID dvchost=hostname act=updated filePath=c:\\windows\\message.dll msg=lastModified,sha1,size'
        p = CefParser(line, '')
        vals = p.get()
        self.assertTrue(isinstance(vals, dict))

    def test_sample_4(self):
        line='Jul 31 09:32:32 Innotim-PC CEF:0|Trend Micro|Deep Security Agent|8.0.2224|5000000|WebReputation|6|cn1=159 cn1Label=Host ID dvchost=laptop_usilks request=http://rod.bnh4uln9imw.com.tv/K4/TLWaWTgCRat.com msg=Suspicious'
        p = CefParser(line, '')
        vals = p.get()
        self.assertTrue(isinstance(vals, dict))


