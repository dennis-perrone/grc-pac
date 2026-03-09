import json
import requests

with open("test-data/pod_latest_tag.json") as f:
    resource = json.load(f)

resp = requests.post(
    "http://localhost:8181/v1/data/grc/kubernetes/deny",
    json={"input": resource}
)

print(json.dumps(resp.json(), indent=2))