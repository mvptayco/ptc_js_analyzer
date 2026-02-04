import requests
import json

url = "http://127.0.0.1:5000/api/analyze"
payload = {"url": "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"}
headers = {"Content-Type": "application/json"}

try:
    response = requests.post(url, json=payload, headers=headers)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text[:500]}") # Print first 500 chars
except Exception as e:
    print(f"Error: {e}")
