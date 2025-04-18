import unittest
from unittest.mock import patch, MagicMock
from netpidtracer_en import parse_netstat_output, get_process_path

class TestNetPIDTracer(unittest.TestCase):

    def test_parse_netstat_output_basic(self):
        sample_output = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       1234
  UDP    192.168.1.100:53       *:*                                  4321
        """
        result = parse_netstat_output(sample_output)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ('TCP', '127.0.0.1:8080', '0.0.0.0:0', 'LISTENING', '1234'))
        self.assertEqual(result[1][0], 'UDP')

    def test_parse_netstat_output_with_filters(self):
        sample_output = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       1234
  UDP    192.168.1.100:53       *:*                                  4321
        """
        result = parse_netstat_output(sample_output, proto_filter='TCP')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 'TCP')

    @patch('psutil.Process')
    def test_get_process_path(self, mock_process):
        mock_proc_instance = MagicMock()
        mock_proc_instance.exe.return_value = "/fake/path/to/exe"
        mock_process.return_value = mock_proc_instance

        path = get_process_path(1234)
        self.assertEqual(path, "/fake/path/to/exe")

    @patch('psutil.Process', side_effect=Exception("Access Denied"))
    def test_get_process_path_exception(self, mock_process):
        path = get_process_path(9999)
        self.assertEqual(path, "Access Denied / Not Found")


if __name__ == '__main__':
    unittest.main()
