import os
import sys
import json
from datetime import datetime, timezone
import jsonschema

FEED_FILE_PATH = "advisories/immunity-feed.json"
SCHEMA_FILE_PATH = "schemas/threat-object.schema.json"

def load_json_file(filepath):
    """Loads a JSON file if it exists, otherwise returns None."""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {filepath}: {e}", file=sys.stderr)
            sys.exit(1)
    return None

def validate_feed(feed_data, schema_data):
    """Validates the feed data against the JSON schema."""
    try:
        jsonschema.validate(instance=feed_data, schema=schema_data)
        print("Schema validation successful.", file=sys.stderr)
        return True
    except jsonschema.exceptions.ValidationError as e:
        print(f"Schema validation error: {e}", file=sys.stderr)
        return False
        
def merge_threats(existing_feed, new_threats):
    """Merges new threats into the existing feed, updating based on ID."""
    
    if not existing_feed:
        existing_feed = {
            "version": "1.1.0",
            "updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "description": "Prismor Agent Immunity Intelligence Feed",
            "advisories": []
        }
    
    existing_advisories = {adv["id"]: adv for adv in existing_feed.get("advisories", [])}
    
    added_count = 0
    updated_count = 0
    
    for threat in new_threats:
        threat_id = threat["id"]
        if threat_id in existing_advisories:
            # Simplistic merge: overwrite with new data from NVD.
            # In a robust system, we would retain manual overrides or specific Prismor analysis.
            existing_advisories[threat_id] = threat
            updated_count += 1
        else:
            existing_advisories[threat_id] = threat
            added_count += 1
            
    existing_feed["advisories"] = list(existing_advisories.values())
    existing_feed["updated"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    print(f"Merged {added_count} new advisories and updated {updated_count} existing.", file=sys.stderr)
    return existing_feed

if __name__ == "__main__":
    
    # Read incoming threats from stdin (piped from fetch script)
    input_data = sys.stdin.read()
    
    if not input_data.strip():
        print("No input data received from stdin. Exiting.", file=sys.stderr)
        sys.exit(0)
        
    try:
        new_threats = json.loads(input_data)
    except json.JSONDecodeError as e:
         print(f"Error decoding JSON from stdin: {e}", file=sys.stderr)
         sys.exit(1)
         
    if not isinstance(new_threats, list):
         print("Input data must be a JSON array of threats.", file=sys.stderr)
         sys.exit(1)
         
    print(f"Received {len(new_threats)} threats from the feed.", file=sys.stderr)
         
    existing_feed = load_json_file(FEED_FILE_PATH)
    schema_data = load_json_file(SCHEMA_FILE_PATH)
    
    if not schema_data:
        print(f"Schema file not found at {SCHEMA_FILE_PATH}", file=sys.stderr)
        sys.exit(1)

    merged_feed = merge_threats(existing_feed, new_threats)
    
    if validate_feed(merged_feed, schema_data):
        with open(FEED_FILE_PATH, 'w') as f:
            json.dump(merged_feed, f, indent=2)
        print(f"Successfully updated feed at {FEED_FILE_PATH}", file=sys.stderr)
    else:
        print("Failed to update feed due to validation errors.", file=sys.stderr)
        sys.exit(1)
