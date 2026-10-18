#!/usr/bin/env python3
"""Build two exact, offline Stirling-PDF v3.1.0 UI asset fixes; never deploy."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAIN = Path('/tmp/stirling-index-original.js')
LANDING = Path('/tmp/stirling-landing-original.js')
EXPECTED = {
    'main': '42cc0f4ae0afbee21d36ac67920156323789e9f69c46cc152bca2ce75d0c5cc2',
    'landing': '080240de0d40b5c826b587d411b489719d898d4a2e2a66231ab6fa5cdc3f77a1',
}
REFRESH_OLD = 'function Qg(){const{t}=A(),s=ot(),{refresh:n,bumpDiskRevision:i}=ft(),[o,r]=u.useState(!1),a=u.useCallback(async()=>{r(!0);try{const l=await s.pullFromServer();!l.ok&&l.reason!=="endpoint-missing"&&s.setError(l.reason==="network"?t("filesPage.syncError.network","Could not reach the server."):l.reason==="server"?t("filesPage.syncError.server","Server error during folder sync."):t("filesPage.syncError.client","Folder sync failed.")),i(),await n()}finally{r(!1)}},[s,n,i,t]);return{refreshing:o,refresh:a}}'
REFRESH_NEW = 'function Qg(){const{t}=A(),s=ot(),{refresh:n,bumpDiskRevision:i}=ft(),{config:stirlingUiConfig}=Ze(),stirlingStorageEnabled=stirlingUiConfig?.storageEnabled===!0,[o,r]=u.useState(!1),a=u.useCallback(async()=>{r(!0);try{if(stirlingStorageEnabled){const l=await s.pullFromServer();!l.ok&&l.reason!=="endpoint-missing"&&s.setError(l.reason==="network"?t("filesPage.syncError.network","Could not reach the server."):l.reason==="server"?t("filesPage.syncError.server","Server error during folder sync."):t("filesPage.syncError.client","Folder sync failed."))}else{s.setError(null);await s.refresh()}i(),await n()}finally{r(!1)}},[s,n,i,t,stirlingStorageEnabled]);return{refreshing:o,refresh:a}}'


def checked_read(name, path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED[name]:
        raise RuntimeError(f'{name}: original asset SHA256 mismatch')
    return data.decode('utf-8')


def one(text, old, new, name):
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f'{name}: expected exactly one anchor, got {count}')
    return text.replace(old, new, 1)


def build():
    main = checked_read('main', MAIN)
    landing = checked_read('landing', LANDING)
    if 'stirlingUiConfig' in main or 'stirlingUiConfig' in landing:
        raise RuntimeError('Unminified patch variable unexpectedly already present')
    patched_main = one(main,
        '},x=[b,E,C],T=[...r?.hasOpenFromComputer?',
        '},x=[b,E,...(r?.accountId?[C]:[])],T=[...r?.hasOpenFromComputer?',
        'QuickNavRailHost processor visible only for existing authenticated account identity')
    patched_landing = one(landing, REFRESH_OLD, REFRESH_NEW,
        'complete useLibraryRefresh function')
    patched_landing = one(patched_landing,
        'label:i("filesPage.refresh","Refresh"),onClick:()=>{p()},',
        'label:"Refresh files",onClick:()=>{p()},',
        'visible refresh label (literal avoids existing i18n overriding fallback)')
    outputs = {'main': patched_main, 'landing': patched_landing}
    report = {'original_sha256': EXPECTED, 'files': {},
        'changes': [
            'Main: QuickNavRailHost includes Processor only when existing host.accountId is present. Official account bridge populates it from user?.id ?? null; no identity or permission is synthesized. Existing portalAccess disabled/reason/onClick logic is unchanged. This avoids calling AppConfig outside its provider and needs only one main-module anchor.',
            'Landing: server folder sync only when storageEnabled is strictly true; otherwise clear stale folder sync error and await existing local folders.refresh().',
            'Landing: preserve server/network/client errors, endpoint-missing handling, disk revision, files refresh and finally loading cleanup. Include storage flag in callback dependencies.',
            'Landing: literal English Refresh files label so old translated Refresh text cannot replace the desired visible label.',
        ],
        'deployment_notes': [
            'No original static module specifier is rewritten inside either patched module. Relative imports still resolve in /assets/.',
            'Import map must precede every module/modulepreload. Map absolute original main URL to new main URL, and original Landing URL to new Landing URL.',
            'Cover both /assets/... and any active base-path URL if served under a context path. Root deployment is /.',
            'Do not load old and new main modules together; duplicate React contexts would break hook consumers.',
            'HTML must have correct cache behavior so refreshed tabs receive the import map. Already-open tabs keep their old module graph until reloaded.',
            'Native import maps cover static and dynamic imports. Vite preload links may fetch old bytes without evaluating them; optional preload rewriting is a performance concern.',
            'Retain exact upstream image SHA and original bytes for rollback. This builder does not alter VM or project formal files.',
        ]}
    for name, text in outputs.items():
        data = text.encode('utf-8')
        digest = hashlib.sha256(data).hexdigest()
        readable = 'index' if name == 'main' else 'Landing'
        filename = f'{readable}-local-files-fix-{digest[:12]}.js'
        (HERE / filename).write_bytes(data)
        (HERE / ('patched.js' if name == 'main' else 'patched-landing.js')).write_bytes(data)
        report['files'][name] = {'filename': filename, 'sha256': digest, 'bytes': len(data)}
    (HERE / 'refresh-function-original.js').write_text(REFRESH_OLD + '\n')
    (HERE / 'refresh-function-patched.js').write_text(REFRESH_NEW + '\n')
    (HERE / 'patch-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    build()
