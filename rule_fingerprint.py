"""Fingerprint executable rule configuration, preserving raw licensed rules unmodified."""
import hashlib,json

def fingerprint(text):
    from ruamel.yaml import YAML
    data=YAML(typ='safe').load(text)
    assert isinstance(data,dict) and isinstance(data.get('rules'),list)
    # Metadata carries registry counters/links and copyright notices, not matching logic.
    # Only ignore it for hashing; never remove it from the file used by Semgrep.
    rules=[]
    for rule in data['rules']:
        logical={k:v for k,v in rule.items() if k!='metadata'}
        rules.append(json.dumps(logical,ensure_ascii=False,sort_keys=True,separators=(',',':')))
    canonical='\n'.join(sorted(rules)).encode('utf-8')
    return {'algorithm':'full_rule_except_metadata_sorted_v1','rules':len(rules),'sha256':hashlib.sha256(canonical).hexdigest()}
