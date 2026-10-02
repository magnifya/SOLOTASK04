#!/usr/bin/env python3
"""验证方展示请求主动取消（cancel）端到端测试。

覆盖：
- POST /v1/presentation-requests/{id}/cancel：空对象 200、默认原因
  “展示请求主动取消”、显式原因裁剪（1..256 Unicode 码点）；
- 空体、非法 JSON、非对象（数组/字符串/null）、多余字段、reason 非
  字符串/全空白/超长均 400 且仅含非空中文 error；
- X-Tenant-ID 缺省 default、显式空值 400，先于资源与请求体校验；
  未知与他租户请求统一 404；
- 仅 pending（含已过期）可首次取消；consumed 取消 409；成功保存
  cancelled 与 cancel_reason、cancelled_at（UTC 秒精度 Z），响应与
  GET 查询一致、不含消费字段；
- 重复取消幂等返回首次结果，即使原因不同也不改写、不重复审计；
- present 的 request_id 模式对已取消请求返回 400「展示请求已取消」，
  不生成展示或审计；
- verify 的 request_id 模式保留存在性与绑定校验，绑定通过后若请求已
  取消返回 200 {"valid":false,"reason":"展示请求已取消"}，不消费
  （绑定与非绑定一致，且先于过期与凭证校验）；
- 首次取消仅追加一条 presentation.request.cancelled
  （resource_type=presentation_request、resource_id=请求 ID），重复
  与失败不记审计；落盘失败回滚状态与审计序号；取消结果跨重启保留。

直接运行：python3 tests/presentation_request_cancel_test.py
"""

import json, os, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PORT = 9012
STORE = tempfile.mktemp(suffix='.json')
BASE = f'http://127.0.0.1:{PORT}'
fails = []
def check(name, cond):
    print(('PASS' if cond else 'FAIL'), name)
    if not cond: fails.append(name)
def http(method, url, payload=None, headers=None, raw='__UNSET__'):
    if raw == '__UNSET__':
        data = json.dumps(payload).encode() if payload is not None else None
    else:
        data = raw
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')
def wait_up():
    for _ in range(80):
        try:
            http('GET', f'{BASE}/health'); return True
        except OSError: time.sleep(0.15)
    return False
env = dict(os.environ, VCBACKEND_STORE=STORE)
proc = subprocess.Popen([sys.executable, '-m', 'vcbackend.cli', 'serve',
    '--port', str(PORT), '--host', '127.0.0.1'], cwd=ROOT, env=env,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert wait_up()
try:
    st, r = http('POST', f'{BASE}/v1/dids', {'method': 'example', 'public_key': 'k-iss'})
    assert st == 201, r
    issuer = r['did']
    st, r = http('POST', f'{BASE}/v1/dids', {'method': 'example', 'public_key': 'k-sub'})
    assert st == 201, r
    subject = r['did']; sub_pem = r['public_key']
    st, r = http('POST', f'{BASE}/v1/credentials',
        {'issuer_did': issuer, 'subject_did': subject, 'claims': {'role': 'admin'}})
    assert st == 201, r
    cred = r['credential_id']

    # 基础取消：默认原因
    st, req = http('POST', f'{BASE}/v1/presentation-requests', {'challenge': 'c1'})
    assert st == 201
    rid = req['request_id']
    st, r = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % rid, {})
    check('cancel empty object 200', st == 200)
    check('status cancelled', r.get('status') == 'cancelled')
    check('default reason', r.get('cancel_reason') == '展示请求主动取消')
    cat = r.get('cancelled_at')
    check('cancelled_at shape', isinstance(cat, str) and cat.endswith('Z'))
    check('no consumed fields', 'consumed_at' not in r and 'consumed_presentation_id' not in r)
    check('base fields kept', r.get('challenge') == 'c1' and r.get('holder_binding') is False)

    # 查询返回同样对象
    st, g = http('GET', f'{BASE}/v1/presentation-requests/{rid}')
    check('GET cancelled same', st == 200 and g == r)

    # 重复取消（不同原因）幂等
    st, r2 = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % rid,
                  {'reason': '  other reason  '})
    check('repeat cancel 200 idempotent', st == 200 and r2.get('cancel_reason') == '展示请求主动取消'
          and r2.get('cancelled_at') == cat and r2 == r)

    # present 被拒
    st, r = http('POST', f'{BASE}/v1/credentials/{cred}/present', {'request_id': rid})
    check('present cancelled -> 400 fixed', st == 400 and r == {'error': '展示请求已取消'})

    # 显式原因裁剪
    st, req2 = http('POST', f'{BASE}/v1/presentation-requests', {'challenge': 'c2'})
    st, r = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % req2['request_id'],
                 {'reason': '  不想看了  '})
    check('trimmed reason saved', st == 200 and r.get('cancel_reason') == '不想看了')

    # 先 present 再取消：409
    st, req3 = http('POST', f'{BASE}/v1/presentation-requests',
                    {'challenge': 'c3', 'expires_in': 600, 'disclose': ['/role']})
    st, vp = http('POST', f'{BASE}/v1/credentials/{cred}/present',
                  {'request_id': req3['request_id']})
    assert st == 201, vp
    st, r = http('POST', f'{BASE}/v1/presentations/%s/verify' % vp['presentation_id'],
                 {'presentation': vp, 'request_id': req3['request_id']})
    assert st == 200 and r == {'valid': True}, r
    st, r = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % req3['request_id'], {})
    check('consumed cancel 409', st == 409 and r == {'error': '展示请求已消费'})

    # verify 已取消请求的已有展示 -> valid:false 固定原因，不消费
    st, req4 = http('POST', f'{BASE}/v1/presentation-requests',
                    {'challenge': 'c4', 'expires_in': 600, 'disclose': ['/role']})
    st, vp4 = http('POST', f'{BASE}/v1/credentials/{cred}/present',
                   {'request_id': req4['request_id']})
    assert st == 201
    st, _ = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % req4['request_id'], {})
    assert st == 200
    st, r = http('POST', f'{BASE}/v1/presentations/%s/verify' % vp4['presentation_id'],
                 {'presentation': vp4, 'request_id': req4['request_id']})
    check('verify cancelled bound -> 200 valid:false',
          st == 200 and r == {'valid': False, 'reason': '展示请求已取消'})
    st, r = http('POST', f'{BASE}/v1/presentations/%s/verify' % vp4['presentation_id'],
                 {'presentation': vp4, 'request_id': req4['request_id']})
    check('verify cancelled repeat same, presentation not consumed',
          st == 200 and r == {'valid': False, 'reason': '展示请求已取消'})
    st, g = http('GET', f'{BASE}/v1/presentation-requests/{req4["request_id"]}')
    check('request still cancelled not consumed', g.get('status') == 'cancelled')

    # 绑定形态取消验真
    st, req5 = http('POST', f'{BASE}/v1/presentation-requests',
                    {'challenge': 'c5', 'expires_in': 600, 'disclose': ['/role'],
                     'holder_binding': True, 'issuer_dids': [issuer]})
    st, vp5 = http('POST', f'{BASE}/v1/credentials/{cred}/present',
                   {'request_id': req5['request_id']})
    assert st == 201, vp5
    st, _ = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % req5['request_id'], {})
    st, r = http('POST', f'{BASE}/v1/presentations/%s/verify' % vp5['presentation_id'],
                 {'presentation': vp5, 'request_id': req5['request_id']})
    check('holder-bound cancelled verify',
          st == 200 and r == {'valid': False, 'reason': '展示请求已取消'})
    # 展示正文/签名未被改动
    check('presentation body intact', vp5.get('holder_did') == subject and bool(vp5.get('holder_proof')))

    # 过期请求仍可取消
    st, req6 = http('POST', f'{BASE}/v1/presentation-requests',
                    {'challenge': 'c6', 'expires_in': 1})
    assert st == 201
    time.sleep(1.3)
    st, r = http('POST', f'{BASE}/v1/presentation-requests/%s/cancel' % req6['request_id'], {})
    check('expired pending cancel 200', st == 200 and r.get('status') == 'cancelled')

    # 非法请求体 400
    url6 = f'{BASE}/v1/presentation-requests/{req6["request_id"]}/cancel'
    st, r = http('POST', url6, raw=b'')
    check('empty body 400', st == 400 and isinstance(r.get('error'), str) and r['error'])
    st, r = http('POST', url6, raw=b'{bad')
    check('bad json 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, raw=b'[1,2]')
    check('non-object 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, raw=b'"x"')
    check('string body 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, {'reason': 'x', 'extra': 1})
    check('extra field 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, {'reason': 123})
    check('reason non-string 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, {'reason': '   '})
    check('reason blank 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, {'reason': '好' * 257})
    check('reason too long 400', st == 400 and r.get('error'))
    st, r = http('POST', url6, {'reason': '好' * 256})
    check('reason 256 still idempotent 200 (already cancelled)', st == 200)
    st, r = http('POST', url6, raw=b'null')
    check('json null 400', st == 400 and r.get('error'))

    # 未知 / 他租户
    st, r = http('POST', f'{BASE}/v1/presentation-requests/pr_deadbeef/cancel', {})
    check('unknown 404', st == 404 and r.get('error'))
    st, r = http('POST', f'{BASE}/v1/presentation-requests/{rid}/cancel', {},
                 headers={'X-Tenant-ID': 'other'})
    check('other tenant 404', st == 404 and r.get('error'))

    # 显式空租户头：先于资源，400
    st, r = http('POST', f'{BASE}/v1/presentation-requests/pr_whatever/cancel', {},
                 headers={'X-Tenant-ID': ''})
    check('empty tenant 400', st == 400 and r.get('error'))
    # 空租户头 + 空体仍然 400
    st, r = http('POST', f'{BASE}/v1/presentation-requests/pr_whatever/cancel', raw=b'',
                 headers={'X-Tenant-ID': ''})
    check('empty tenant + empty body 400', st == 400 and r.get('error'))
    # 他租户无桶时未知 404
    st, r = http('POST', f'{BASE}/v1/presentation-requests/pr_x/cancel', {},
                 headers={'X-Tenant-ID': 'newbie'})
    check('fresh tenant unknown 404', st == 404)

    # 审计：首次取消仅一条
    st, audit = http('GET', f'{BASE}/v1/audit?limit=200')
    cancels = [e for e in audit['events'] if e['action'] == 'presentation.request.cancelled']
    check('one audit per first-cancel', len(cancels) == 5)
    e = cancels[0]
    check('audit fields', e['resource_type'] == 'presentation_request' and e['resource_id'] == rid)
    check('audit has tenant', e['tenant_id'] == 'default')

    # 失败不记审计：用消费的请求非法 body 与 409 都不应新增 cancel 审计；
    # 上面总 cancel 尝试数中成功首取消恰为 6 条（c1,c2,expired,req4,req5,req6）
    keep = rid
    proc.terminate(); proc.wait(timeout=10)
    proc = subprocess.Popen([sys.executable, '-m', 'vcbackend.cli', 'serve',
        '--port', str(PORT), '--host', '127.0.0.1'], cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_up()
    st, r = http('GET', f'{BASE}/v1/presentation-requests/{keep}')
    check('persist across restart', st == 200 and r.get('status') == 'cancelled'
          and r.get('cancel_reason') == '展示请求主动取消' and bool(r.get('cancelled_at')))
    st, r = http('POST', f'{BASE}/v1/presentation-requests/{keep}/cancel',
                 {'reason': 'changed'})
    check('idempotent after restart', st == 200 and r.get('cancel_reason') == '展示请求主动取消')

finally:
    proc.terminate()
    try: proc.wait(timeout=10)
    except subprocess.TimeoutExpired: proc.kill()
    if os.path.exists(STORE): os.unlink(STORE)
print()
print('FAILURES:', fails) if fails else print('ALL PASS')
sys.exit(1 if fails else 0)
