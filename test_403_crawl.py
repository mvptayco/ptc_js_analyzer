
import unittest
from unittest.mock import patch, MagicMock
from analyzer import JavaScriptAnalyzer

class TestAnalyzer403(unittest.TestCase):
    def setUp(self):
        self.analyzer = JavaScriptAnalyzer()

    @patch('analyzer.requests.get')
    def test_403_analysis(self, mock_get):
        # Mock a 403 response with some content
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = """
        <html>
            <head>
                <script src="https://example.com/app.js"></script>
                <script src="/static/login.js"></script>
            </head>
            <body>
                <h1>Access Denied</h1>
                <script>
                    var key = "AIzaSyDummyGoogleAPIKey1234567890123456789";
                </script>
            </body>
        </html>
        """
        # Important: iter_content needs to behave like a real response for the new logic
        mock_response.iter_content.return_value = [mock_response.text.encode('utf-8')]
        mock_response.apparent_encoding = 'utf-8'
        mock_response.headers = {'Content-Type': 'text/html', 'Content-Length': str(len(mock_response.text))}
        
        mock_get.return_value = mock_response

        # Run analysis
        result = self.analyzer.analyze("https://example.com/admin")

        # Verify results
        print(f"Errors: {result.errors}")
        
        # Check if 403 error is reported but analysis continued
        self.assertTrue(any("Access Denied (403 Forbidden)" in e for e in result.errors))
        
        # Check if API key was found in the 403 content
        found_keys = [k['match'] for k in result.api_keys]
        print(f"Found keys: {found_keys}")
        self.assertTrue(any("AIzaSyDummyGoogleAPIKey" in k for k in found_keys))
        
        # Check if scripts were extracted
        paths = [p['path'] for p in result.paths_directories if p['type'] == 'Script Reference']
        print(f"Found paths: {paths}")
        self.assertIn("https://example.com/app.js", paths)
        self.assertIn("/static/login.js", paths)

if __name__ == '__main__':
    unittest.main()
