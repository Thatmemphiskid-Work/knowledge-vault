"""Rebuild the offline catalog, page index, and Obsidian vault from local sources."""
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'assessment'
VAULT = ROOT / 'Assessment Vault'

COMMANDS = {
    'Windows': ('PowerShell, local read-only inventory', '''Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber
Get-HotFix | Sort InstalledOn -Descending | Select -First 20
Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Select DisplayName,DisplayVersion,Publisher
Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess'''),
    'Linux': ('Shell, local read-only inventory', '''cat /etc/os-release
uname -r
command -v dpkg-query >/dev/null && dpkg-query -W
command -v rpm >/dev/null && rpm -qa
ss -lntup'''),
    'Dependencies': ('Shell, from the approved application directory; tools must already be installed', '''npm ls --all --json
python -m pip list --format=json
find . -type f -name 'log4j-core-*.jar' -print
# JAR filenames are leads, not proof of the bundled version.
# Review lockfiles, SBOMs, image digests and deployed artifacts, not just source.'''),
    'Web and appliances': ('Shell, replace the example URL with one approved asset; this is NOT a CVE test', '''curl --head --connect-timeout 5 --max-time 10 https://asset.example
# Headers can be hidden or misleading. Use the authenticated admin UI
# or vendor-supported inventory command for the exact firmware/build.
# Do not run generic commands on restricted appliance shells.'''),
}

def family(row):
    text = (row['vendorProject'] + ' ' + row['product']).lower()
    if any(x in text for x in ['windows', 'microsoft', 'exchange']):
        return 'Windows'
    if any(x in text for x in ['linux', 'kernel', 'ubuntu', 'red hat']):
        return 'Linux'
    if any(x in text for x in ['struts', 'log4j', 'python', 'npm', 'library']):
        return 'Dependencies'
    return 'Web and appliances'

def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')

def clean(text):
    # Only repair reversible, recognizable UTF-8-as-Windows-1252 corruption.
    if 'â€' in text or 'Ã' in text:
        try:
            return text.encode('cp1252').decode('utf-8')
        except (UnicodeError, LookupError):
            pass
    return text

def guide_markdown(guide):
    content = f"## {guide['title']}\n\n{guide['scope']}\n\n"
    content += '\n\n'.join(guide['concepts']) + '\n\n'
    for command in guide['discover']:
        content += f"### {command['title']}\n\n```{command['language']}\n{command['code']}\n```\n\n{command['interpretation']}\n\n"
    for key, title in [('verify', 'Verify'), ('fix', 'Fix / prevent'), ('retest', 'Retest'), ('detection', 'Detection evidence')]:
        content += f'### {title}\n\n' + '\n'.join(f'{i}. {step}' for i, step in enumerate(guide[key], 1)) + '\n\n'
    content += '### Decision branches\n\n' + '\n'.join(f"- **If {b['condition']}:** {b['outcome']}" for b in guide['branches']) + '\n\n'
    return content

def configuration_text(value, depth=0):
    """Readable outline, not a version matcher: retain AND/OR, negation and platform constraints."""
    lines = []
    if isinstance(value, list):
        for i, item in enumerate(value, 1):
            lines.append('  ' * depth + f'Group {i}:')
            lines.extend(configuration_text(item, depth + 1))
    elif isinstance(value, dict):
        if 'criteria' in value:
            lines.append('  ' * depth + ('Affected component' if value.get('vulnerable') else 'Environment prerequisite') + ': ' + value['criteria'])
            for key, symbol in [('versionStartIncluding', '>='), ('versionStartExcluding', '>'), ('versionEndIncluding', '<='), ('versionEndExcluding', '<')]:
                if key in value:
                    lines.append('  ' * (depth + 1) + f'Version {symbol} {value[key]}')
        else:
            if 'operator' in value:
                lines.append('  ' * depth + f"Operator: {value['operator']}; negated: {value.get('negate', False)}")
            elif value.get('negate'):
                lines.append('  ' * depth + 'Negated group')
            for key in ('nodes', 'cpeMatch', 'children'):
                if key in value:
                    lines.extend(configuration_text(value[key], depth + 1))
    return lines

PATCH_REPOS = {
    'torvalds/linux', 'abrt/abrt', 'apache/httpd', 'cacti/cacti', 'craftcms/cms',
    'erlang/otp', 'exiftool/exiftool', 'geosolutions-it/jai-ext', 'gogs/gogs',
    'grafana/grafana', 'langflow-ai/langflow', 'livewire/livewire', 'marimo-team/marimo',
    'metabase/metabase', 'michaelschwarz/ajax.net-professional', 'minio/minio',
    'mlflow/mlflow', 'n8n-io/n8n', 'netty/netty', 'notepad-plus-plus/notepad-plus-plus',
    'notepad-plus-plus/wingup', 'octobercms/library', 'openbsd/src', 'pear/archive_tar',
    'projectsend/projectsend', 'ray-project/ray', 'react-native-community/cli',
    'roundcube/roundcubemail', 'sebastianbergmann/phpunit', 'sebhildebrandt/systeminformation',
    'usmannasir/cyberpanel', 'v8/v8', 'vitejs/vite', 'vrana/adminer',
    'webmproject/libvpx', 'webmproject/libwebp', 'xwiki/xwiki-platform', 'yiisoft/yii2',
    'berriai/litellm', 'kludex/starlette', 'reviewdog/action-setup',
}

def patch_links(cve):
    results = {}
    for ref in cve.get('references', []):
        u = urlsplit(ref['url'])
        parts = u.path.strip('/').split('/')
        tags = set(ref.get('tags', []))
        if (u.hostname == 'github.com' and len(parts) >= 4
                and '/'.join(parts[:2]).casefold() in PATCH_REPOS
                and parts[2] == 'commit' and re.fullmatch(r'[0-9a-f]{40}', parts[3])
                and 'Patch' in tags and not tags & {'Exploit', 'Broken Link'}):
            results[ref['url']] = {'url': ref['url'], 'kind': 'NVD-indexed upstream patch candidate',
                                   'note': 'Source commit linked by NVD as Patch; not individually reviewed or executed. Check branch and backport applicability.'}
    return list(results.values())

def main():
    with (ROOT / 'known_exploited_vulnerabilities.csv').open(encoding='utf-8-sig', newline='') as f:
        rows = [{k: clean(v or '') for k, v in r.items()} for r in csv.DictReader(f)]
    ids = [r['cveID'] for r in rows]
    if len(ids) != len(set(ids)) or not all(re.fullmatch(r'CVE-\d{4}-\d{4,}', i) for i in ids):
        raise ValueError('Duplicate or invalid CVE IDs in input')
    guides = json.loads((OUT / 'guide_content.json').read_text(encoding='utf-8'))
    overrides = json.loads((OUT / 'cve_overrides.json').read_text(encoding='utf-8'))
    research = json.loads((OUT / 'research' / 'nvd-kev.json').read_text(encoding='utf-8'))
    nvd = {item['cve']['id']: item['cve'] for item in research['vulnerabilities']}
    if len(research['vulnerabilities']) != research['totalResults']:
        raise ValueError('Incomplete NVD snapshot: retrieve every pagination page before building')
    guide_map = {g['id']: g for g in guides}
    extra = {'server-input-injection': {'CWE-77', 'CWE-94', 'CWE-95', 'CWE-917'},
             'authentication-access-control': {'CWE-284', 'CWE-288', 'CWE-863', 'CWE-798'},
             'memory-parser-safety': {'CWE-120', 'CWE-121', 'CWE-122', 'CWE-416', 'CWE-476', 'CWE-502'}}
    for g in guides:
        text = '# ' + g['title'] + '\n\n' + guide_markdown(g)
        text += '## Optional source provenance\n\nThe procedure is self-contained; these sources are audit context, not required reading.\n\n'
        text += '\n'.join(f"- [[{p['source']}]] (PDF page {p['page']}): {p['reason']}" for p in g['provenance'])
        write(VAULT / 'Guides' / f"{g['id']}.md", text)
    write(VAULT / 'Guides.md', '# Followable assessment guides\n\n' + '\n'.join(f"- [[{g['id']}|{g['title']}]]" for g in guides))
    training = json.loads((OUT / 'training_content.json').read_text(encoding='utf-8'))
    training_index = '# Analyst Training\n\n' + training['scope'] + '\n\n' + training['taxonomy'] + '\n\n'
    training_index += '''## How to use this curriculum

1. Start with the group overview, then the topic-specific evidence and control checks.
2. Choose a linked hands-on lab. Read prerequisites and replace placeholders before running commands. The app never runs commands on your behalf.
3. Separate configuration review, live harmless activity, offline fixture replay and tabletop results. They prove different things; none is automatically an exploit reproduction.
4. Record asset, test principal/vantage, UTC window, exact method, expected result, observed result, source event, collector event, alert and containment evidence.
5. Close a training exercise only when the trainee can explain the boundary, identify a legitimate comparison case, locate the failed milestone and retest after correction.

## Outcome branches

- Missing authority, prerequisite or source evidence: stop that case and mark **not tested / coverage gap**.
- Approved activity occurs but required source evidence is missing: investigate audit policy/visibility.
- Source evidence exists but central evidence is missing: investigate collection/retention.
- Central evidence exists but the intended alert is absent: investigate the rule/query; do not count silence as proof of absence.
- Alert exists but expected access denial/containment did not occur: response remains unverified.
- No alert was intended: evaluate collection only; ordinary administration should not automatically be labeled malicious.
- All expected observations match: record the specific tested control and mode, not universal attack resistance.

## Hands-on labs
'''
    for lab in training['labs']:
        text = f"# {lab['title']}\n\n## Prerequisites\n\n{lab['prerequisites']}\n\n"
        for cmd in lab['commands']:
            text += f"## {cmd['title']}\n\n```{cmd['language']}\n{cmd['code']}\n```\n\n{cmd['interpretation']}\n\n"
        text += '## Operator and defender walkthrough\n\n' + '\n'.join(f'{i}. {step}' for i, step in enumerate(lab['steps'], 1))
        text += f"\n\n## Expected result\n\n{lab['expected']}\n\n## What this does not prove\n\n{lab['limits']}\n\n[[Analyst Training]]"
        write(VAULT / 'Training' / 'Labs' / f"training-lab-{lab['id']}.md", text)
        training_index += f"- [[training-lab-{lab['id']}|{lab['title']}]]\n"
    training_index += '\n## All requested groups and topics\n\n'
    for group in training['groups']:
        labs = [lab for lab in training['labs'] if group['id'] in lab['groups']]
        lab_links = '\n'.join(f"- [[training-lab-{lab['id']}|{lab['title']}]]" for lab in labs)
        workflow = guide_markdown(dict(title=group['title'] + ' workflow', scope=training['scope'],
                                      concepts=[group['goal']], discover=group['commands'], verify=group['verify'],
                                      fix=group['fix'], retest=group['retest'], detection=[group['detection']],
                                      branches=[{'condition': 'Evidence or authority is incomplete', 'outcome': 'Mark not tested or a coverage gap; do not invent a result.'},
                                                {'condition': 'Expected deny/control fails', 'outcome': 'Record the exact boundary and escalate to its owner; do not expand access.'},
                                                {'condition': 'Expected collection/alert/containment is missing', 'outcome': 'Locate the failed milestone using Analyst Training outcome branches and repeat after repair.'}]))
        group_index = f"# {group['title']} training\n\n{group['goal']}\n\n{workflow}\n\n## Hands-on labs\n\n{lab_links}\n\n## Topics\n\n"
        for i, (title, meaning, evidence, prevention, exercise) in enumerate(group['topics'], 1):
            name = f"training-{group['id']}-{i:02d}"
            text = f"# {title} — {group['title']}\n\n## Understand the behavior\n\n{meaning}\n\n## Find / assess evidence\n\n{evidence}\n\n## Prevent / remediate\n\n{prevention}\n\n## Safe exercise\n\n{exercise}\n\n"
            text += f"## Full procedure and result interpretation\n\n{workflow}\n\n## Runnable labs and limits\n\n{lab_links}\n\nThese are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.\n\n[[training-group-{group['id']}]] · [[Analyst Training]]"
            write(VAULT / 'Training' / 'Topics' / f'{name}.md', text)
            group_index += f'- [[{name}|{title}]]\n'
        write(VAULT / 'Training' / f"training-group-{group['id']}.md", group_index + '\n[[Analyst Training]]')
        training_index += f"- [[training-group-{group['id']}|{group['title']}]] — {len(group['topics'])} topics\n"
    training_index += '\n## Source and coverage\n\n' + '\n'.join(training['sources'])
    training_index += '\n\nOriginal defensive synthesis aligned to the requested topic list, not vendor-validated exploit procedures. Topic coverage does not imply a live reproduction of every technique.\n'
    write(VAULT / 'Analyst Training.md', training_index)
    pages, sources = [], []
    pdfs = sorted(list(ROOT.glob('*.pdf')) + list((ROOT / 'hacking-main').glob('*.pdf')))
    for number, path in enumerate(pdfs):
        sid = f'book-{number + 1:02d}'
        with pymupdf.open(path) as doc:
            empty = []
            for i, page in enumerate(doc):
                text = page.get_text(sort=True)
                if len(text.strip()) < 40:
                    empty.append(i + 1)
                pages.append({'source': sid, 'page': i + 1, 'text': text})
            source = {'id': sid, 'name': path.stem, 'path': path.relative_to(ROOT).as_posix(),
                      'pages': len(doc), 'lowTextPages': empty,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'toc': doc.get_toc()}
        sources.append(source)
        toc = '\n'.join(f'- {title} — PDF page {page}' for _, title, page in source['toc'])
        write(VAULT / 'Sources' / f'{sid}.md', f'''# {source['name']}

Local source: [{path.name}](../../{source['path']})

Pages: {source['pages']}. SHA-256: `{source['sha256']}`.
Extracted text is searchable in the app with exact PDF page references.
{len(empty)} pages have fewer than 40 extracted characters; scans, diagrams and tables may require visual review. No OCR was performed.
Books are background references, not current affected-version authorities. Do not infer a CVE test from a book keyword match.

## Embedded table of contents
{toc or 'No embedded table of contents. Use the app page search or the original PDF.'}
''')
    readme = ROOT / 'hacking-main' / 'README.md'
    write(VAULT / 'Sources' / 'Collection README.md', '# Collection usage guidance\n\n' + readme.read_text(encoding='utf-8'))
    vendors, cwes = defaultdict(list), defaultdict(list)
    for row in rows:
        row['playbook'] = family(row)
        row['references'] = list(dict.fromkeys(re.findall(r'https?://[^\s;]+', row['notes'])))
        row['references'] = [u.rstrip('.,)') for u in row['references']]
        record = nvd.get(row['cveID'], {})
        row['nvdDescription'] = next((d['value'] for d in record.get('descriptions', []) if d['lang'] == 'en'), '')
        row['configurations'] = record.get('configurations', [])
        row['versionConditions'] = '\n'.join(configuration_text(row['configurations']))
        row['nvdTimestamp'] = research['timestamp']
        row['nvdModified'] = record.get('lastModified', '')
        row['nvdStatus'] = record.get('vulnStatus', 'Missing')
        row['affectedVersions'] = record.get('affected', [])
        row['curated'] = overrides.get(row['cveID'])
        metrics = record.get('metrics', {})
        row['accessMetrics'] = [dict(m['cvssData'], source=m['source'], type=m.get('type', ''))
                                for version in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30')
                                for m in metrics.get(version, [])]
        weakness = set(re.findall(r'CWE-\d+', row['cwes']))
        weakness.update(d['value'] for w in record.get('weaknesses', []) for d in w['description'] if d['value'].startswith('CWE-'))
        related = [g['id'] for g in guides if g['id'] not in ('service-discovery', 'vulnerability-patch-assessment', 'network-voip-exposure')
                   and weakness & (set(g['cwes']) | extra.get(g['id'], set()))]
        row['guideIds'] = ['vulnerability-patch-assessment'] + related
        if any(word in (row['vendorProject'] + ' ' + row['product']).lower() for word in ('voip', 'sip', 'asterisk')):
            row['guideIds'].append('network-voip-exposure')
        row['guideIds'] = list(dict.fromkeys(row['guideIds']))
        row['codeLinks'] = patch_links(record) + (row['curated']['code'] if row['curated'] else [])
        row['coverage'] = 'Vendor-reviewed defensive guide' if row['curated'] else 'Book-derived guide + NVD applicability; CVE-specific diagnostic not validated'
        row['safeTest'] = None
        vendors[row['vendorProject']].append(row['cveID'])
        for cwe in row['cwes'].split(','):
            if cwe.strip():
                cwes[cwe.strip()].append(row['cveID'])
        command = f'..\\.tools\\python\\python.exe check.py --cve {row["cveID"]} --inventory inventory.json'
        refs = '\n'.join(f'- [{u}]({u})' for u in row['references'])
        embedded = '\n'.join(guide_markdown(guide_map[gid]) for gid in row['guideIds'])
        specific = ''
        if row['curated']:
            c = row['curated']
            specific = f"## CVE-specific guide: {c['title']}\n\n{c['summary']}\n\n### Affected / fixed conditions\n\n{c['affected']}\n\n"
            for cmd in c['discover']:
                specific += f"### {cmd['title']}\n\n```{cmd['language']}\n{cmd['code']}\n```\n\n{cmd['interpretation']}\n\n"
            for key in ('verify', 'fix', 'retest', 'detection'):
                specific += f'### {key.title()}\n\n' + '\n'.join(f'{i}. {step}' for i, step in enumerate(c[key], 1)) + '\n\n'
            specific += 'Vendor evidence: ' + ', '.join(c['sources']) + '\n\n'
        code = '\n'.join(f"- [{c['kind']}]({c['url']}): {c['note']}" for c in row['codeLinks']) or 'No curated upstream GitHub patch/source link in this snapshot. This does not establish that no code exists.'
        write(VAULT / 'CVEs' / f'{row["cveID"]}.md', f'''---
cve: {row['cveID']}
vendor: {json.dumps(row['vendorProject'], ensure_ascii=False)}
product: {json.dumps(row['product'], ensure_ascii=False)}
tags: [kev, assessment]
---
# {row['cveID']} — {row['vulnerabilityName'].strip()}

{row['shortDescription']}

{specific}
## Find the deployed product
Identify **{row['vendorProject']} / {row['product']}**. Use the appropriate local inventory below if you have that access; privileged inventory is not an unauthenticated attacker capability. Product-name matches are candidates, not vulnerabilities.

```{'powershell' if row['playbook'] == 'Windows' else 'sh'}
{COMMANDS[row['playbook']][1]}
```

```powershell
# Run from the assessment folder. Prepare inventory.json using inventory.example.json.
{command}
```

## Followable assessment workflow
The following procedures contain the knowledge needed to collect evidence, interpret it and remediate. They are weakness-family/configuration guides, not proof that a generic probe verifies this exact CVE. No book reading is required to follow them.

{embedded}

## Catalog-required action
{row['requiredAction']}

Capture evidence before changes if incident response requires it. Schedule approved vendor fixes, restrict exposure as an interim control, then repeat the same version/configuration checks. A temporary mitigation is not necessarily a patch. Retest and retain before/after evidence; check [[Incident Response]] if compromise is suspected.

## Catalog context
- Added: {row['dateAdded']}; catalog due date: {row['dueDate']} (not automatically your organization's deadline).
- Ransomware use: {row['knownRansomwareCampaignUse']}; forensic triage: {row['forensicTriage']}.
- Weakness: {row['cwes'] or 'Not provided'}.
- Coverage: {row['coverage']}.

## GitHub defensive code / upstream fixes
{code}

## Applicability evidence available offline
{row['nvdDescription'] or 'No English NVD description in this snapshot.'}

NVD snapshot: {row['nvdTimestamp']}; record status: {row['nvdStatus']}; last modified: {row['nvdModified']}.
NVD and vendor conditions can disagree. This is evidence for an analyst decision, not an automatic version detector. CPE groups preserve affected and environment-prerequisite distinctions; do not flatten AND/OR groups or treat wildcard versions as universal applicability.

```text
{row['versionConditions'] or 'No structured version conditions available.'}
```

## Access prerequisite metrics (not a configuration verdict)
```json
{json.dumps(row['accessMetrics'], ensure_ascii=False, indent=2)}
```

## Optional provenance / advisory references
Books were synthesized into the guide body. External links are audit evidence, not required book-reading steps. NVD data was fetched for the supplied catalog; only the marked vendor-specific guides were individually reviewed against their vendors. Remaining links have not all been fetched/validated.
{refs}

[[Catalog]] · [[Assessment Decision Tree]] · [[Evidence Template]]
''')
    for name, values in vendors.items():
        slug = re.sub(r'[^\w .-]', '_', name).strip('. ') or 'Unknown'
        if slug in COMMANDS:
            slug = 'Vendor - ' + slug
        write(VAULT / 'Vendors' / f'{slug}.md', f'# {name}\n\n' + '\n'.join(f'- [[{i}]]' for i in values))
    for name, values in cwes.items():
        slug = re.sub(r'[^\w-]', '_', name)
        write(VAULT / 'Weaknesses' / f'{slug}.md', f'# {name}\n\n' + '\n'.join(f'- [[{i}]]' for i in values))
    for name, (label, commands) in COMMANDS.items():
        write(VAULT / 'Playbooks' / f'{name}.md', f'''# {name}

## Find: {label}
Only use on explicitly approved assets. Read-only commands may still reveal sensitive inventory; protect output.

```{'powershell' if name == 'Windows' else 'sh'}
{commands}
```

## Test and defend
Inventory is not an exploit test. Compare exact deployed versions and configuration with the CVE's vendor advisory; use supported authenticated scanners or vendor diagnostics where available. Linux distribution backports can invalidate upstream version comparisons. A missing Windows hotfix does not prove vulnerability because updates can be superseded. Runtime dependencies can differ from package-manager output.
Record evidence in [[Evidence Template]], follow [[Assessment Decision Tree]], apply the specific vendor fix, and recheck the deployed instance. For managed services and appliances, use their vendor console rather than assuming host shell access.
''')
    write(VAULT / 'Catalog.md', '# Complete supplied KEV catalog\n\n' + '\n'.join(f'- [[{r["cveID"]}]] — {r["vendorProject"]} / {r["product"]}' for r in rows))
    write(OUT / 'data' / 'catalog.json', json.dumps(rows, ensure_ascii=False))
    write(OUT / 'data' / 'sources.json', json.dumps(sources, ensure_ascii=False))
    write(OUT / 'data' / 'pages.json', json.dumps(pages, ensure_ascii=False))
    write(OUT / 'data' / 'commands.json', json.dumps(dict(COMMANDS, _guides=guides, _training=training), ensure_ascii=False))
    stats = {'cves': len(rows), 'pdfs': len(sources), 'pages': len(pages),
             'lowTextPages': sum(len(s['lowTextPages']) for s in sources),
             'families': dict(Counter(r['playbook'] for r in rows)),
             'guides': len(guides), 'nvdEnriched': sum(r['nvdStatus'] != 'Missing' for r in rows),
             'trainingGroups': len(training['groups']), 'trainingTopics': sum(len(g['topics']) for g in training['groups']),
             'trainingLabs': len(training['labs']),
             'vendorReviewed': sum(bool(r['curated']) for r in rows),
             'withGithubCode': sum(bool(r['codeLinks']) for r in rows),
             'githubLinks': sum(len(r['codeLinks']) for r in rows),
             'csvSha256': hashlib.sha256((ROOT / 'known_exploited_vulnerabilities.csv').read_bytes()).hexdigest()}
    write(OUT / 'data' / 'coverage.json', json.dumps(stats, indent=2))
    print(json.dumps(stats, indent=2))

if __name__ == '__main__':
    main()
