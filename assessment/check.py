"""Offline inventory correlation for every CVE in the supplied catalog. No network tests."""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def correlate(catalog, inventory, cve=None):
    results = []
    selected = [r for r in catalog if cve is None or r['cveID'] == cve]
    if cve and not selected:
        raise ValueError(f'Unknown CVE: {cve}')
    for asset in inventory:
        for row in selected:
            # Exact caller-supplied product/vendor identities avoid dangerous substring guesses.
            match = (asset.get('vendor', '').casefold() == row['vendorProject'].casefold()
                     and asset.get('product', '').casefold() == row['product'].casefold())
            if match or cve:
                results.append({'asset': asset.get('asset', 'unnamed'), 'cve': row['cveID'],
                                'status': 'Candidate' if match else 'Not matched',
                                'version': asset.get('version', ''),
                                'reason': 'Exact catalog product match; verify version, patch and configuration against vendor advisory.' if match else 'No exact identity match. This does NOT establish absence.',
                                'references': row['references']})
    return results

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cve', help='Optional CVE ID; omit to correlate all entries')
    parser.add_argument('--inventory', required=True, type=Path)
    args = parser.parse_args()
    try:
        inventory = json.loads(args.inventory.read_text(encoding='utf-8-sig'))
        if not isinstance(inventory, list) or not all(isinstance(a, dict) for a in inventory):
            raise ValueError('Inventory must be an array of asset objects')
        if any(not isinstance(a.get(k, ''), str) for a in inventory for k in ('asset', 'vendor', 'product', 'version')):
            raise ValueError('Asset, vendor, product and version must be strings when supplied')
        catalog = json.loads((HERE / 'data' / 'catalog.json').read_text(encoding='utf-8'))
        print(json.dumps(correlate(catalog, inventory, args.cve), indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(2, f'{exc}\n')

if __name__ == '__main__':
    main()
