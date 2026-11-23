#!/usr/bin/env python3
"""A single, explicitly dispatched GitHub Issue write, never independent Q1 certification.

No PAT or user secrets; only the ephemeral GITHUB_TOKEN of a sandbox workflow.
The actor does not decide whether the effect meets the independent observer oracle.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO = 'seo307/ETB_Q1_Github-etb-sandbox'
ACTOR = 'github-actions[bot]'
PREFIX = 'ETB-Q1C-EXTERNAL-EFFECT-'
API = 'https://api.github.com/repos/' + REPO
MAX_PAGES = 3
PER_PAGE = 100
MAX_RESPONSE = 3_000_000
API_VERSION = '2022-11-28'


def canonical(x):
    return (json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def make_exact_frozen_plan(nonce, frozen_at):
    if not re.fullmatch('[0-9a-f]{32}', str(nonce)):
        raise ValueError('NONCE_NOT_128_BIT_LOWER_HEX')
    when = dt.datetime.fromisoformat(frozen_at.replace('Z','+00:00'))
    if when.tzinfo is None:
        raise ValueError('NAIVE_FREEZE_TIME')
    return {
        'schema':'ETB_Q1C_TRIAL_v091',
        'stage':'Q1C_EXPLORATORY_EXTERNAL_EFFECT_NOT_Q1',
        'target_kind':'GITHUB_PUBLIC_ISSUE',
        'repo':REPO,
        'actor_login':ACTOR,
        'nonce':nonce,
        'title':PREFIX+nonce,
        'body':'ETB Q1C sandbox marker; not native tau2 or production data.\nnonce='+nonce+'\nno customer data or secrets.\n',
        'frozen_at_local_utc':frozen_at,
        'max_pages':MAX_PAGES,
        'per_page':PER_PAGE,
        'allowed_provider_requests':['GET_REPOSITORY','GET_ALL_ISSUES','GET_MATCHED_ISSUE'],
        'writes_performed_by_package':0,
        'model_calls_performed_by_package':0,
        'external_actor_write_authorized':'NOT_GRANTED_BY_THIS_PLAN',
        'ultimate_admin_independence':'UNVERIFIED',
        'actor_token_scopes':'UNVERIFIED',
        'independent_effect_oracle_for_native_airline':'NOT_APPLICABLE_DIFFERENT_SYSTEM',
        'negative_controls':['no_write','preexisting_nonce','multiple_markers','wrong_actor','mutated_body','wrong_repo','replayed_capture','missing_page','tampered_manifest'],
        'stop_budget':{'max_census_pages':MAX_PAGES,'max_recorded_issue_gets':2,'writes':0,'token_use':0},
        'q1_status':'Q1_BLOCKED',
        'confirmatory_eligible':False,
    }


def request(method, url, token, data=None):
    if not url.startswith(API) or (url != API and not url.startswith(API+'/')):
        raise ValueError('ENDPOINT_NOT_SANDBOX_API')
    if method not in ('GET','POST'):
        raise ValueError('METHOD_NOT_ALLOWLISTED')
    if method == 'POST' and url != API+'/issues':
        raise ValueError('POST_NOT_ISSUE_CREATE')
    raw_data = None if data is None else json.dumps(data, separators=(',',':')).encode()
    headers = {'Accept':'application/vnd.github+json', 'X-GitHub-Api-Version':API_VERSION,
               'User-Agent':'ETB-Q1C-092-bounded-actor', 'Authorization':'Bearer '+token}
    if raw_data is not None:headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=raw_data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=25) as resp:
        if resp.geturl() != url:
            raise ValueError('UNEXPECTED_HTTP_REDIRECT')
        status = resp.status
        body = resp.read(MAX_RESPONSE+1)
        if len(body) > MAX_RESPONSE:
            raise ValueError('RESPONSE_SIZE_LIMIT')
        if method == 'GET' and status != 200 or method == 'POST' and status != 201:
            raise ValueError('UNEXPECTED_HTTP_STATUS_'+str(status))
        return json.loads(body), (resp.headers.get('Link') or ''), status, sha(body)


def qualify_live_repo_and_absence(token, plan, do_request=request):
    repo,_,_,_ = do_request('GET', API, token)
    if (repo.get('full_name','').casefold()!=REPO.casefold() or repo.get('private') is not False
            or repo.get('has_issues') is not True or repo.get('archived') is not False):
        raise ValueError('PROVIDER_REPO_INELIGIBLE')
    count = 0
    for p in range(1,MAX_PAGES+1):
        url = API+f'/issues?state=all&per_page={PER_PAGE}&page={p}'
        issues, link,_,_ = do_request('GET',url,token)
        if not isinstance(issues,list) or len(issues)>PER_PAGE:
            raise ValueError('ISSUES_CENSUS_INVALID')
        for issue in issues:
            if not isinstance(issue,dict):raise ValueError('ISSUE_NOT_OBJECT')
            count+=1
            # Catch even modified duplicate nonce in the title, not merely exact title.
            if (plan['nonce'] in (issue.get('title') or '') or
                    issue.get('title')==plan['title']):
                raise ValueError('FROZEN_NONCE_ALREADY_USED')
        next_links = re.findall(r'<([^>]+)>\s*;\s*rel="next"',link)
        if len(next_links)>1:raise ValueError('MULTIPLE_NEXT_LINKS')
        if not next_links:
            return count
        if p==MAX_PAGES or next_links[0]!=API+f'/issues?state=all&per_page={PER_PAGE}&page={p+1}':
            raise ValueError('PAGINATION_NOT_COMPLETE_OR_UNEXPECTED')
    raise ValueError('PAGINATION_EXCEEDED')


def perform(env, do_request=request):
    """At most one POST per invocation, with preconditions checked before any POST."""
    if env.get('GITHUB_ACTIONS')!='true' or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch':
        raise ValueError('WORKFLOW_DISPATCH_REQUIRED')
    if env.get('GITHUB_REPOSITORY')!=REPO or env.get('GITHUB_REF')!='refs/heads/main':
        raise ValueError('EXACT_SANDBOX_MAIN_REQUIRED')
    if env.get('Q1C_CONFIRM')!='YES_ONE_ISSUE_ONLY':
        raise ValueError('EXPLICIT_ONE_WRITE_CONFIRMATION_REQUIRED')
    token = env.get('GH_TOKEN','')
    if not token or len(token)<12:raise ValueError('EPHEMERAL_WORKFLOW_TOKEN_REQUIRED')
    nonce=env.get('Q1C_NONCE','')
    frozen_at=env.get('Q1C_FROZEN_AT','')
    plan=make_exact_frozen_plan(nonce,frozen_at)
    planned_sha=sha(canonical(plan))
    if env.get('Q1C_PLAN_SHA256')!=planned_sha:
        raise ValueError('FROZEN_PLAN_DIGEST_MISMATCH')
    pre_sha=env.get('Q1C_PRE_SHA256','')
    if not re.fullmatch('[0-9a-f]{64}',pre_sha):
        raise ValueError('PRE_CAPTURE_SHA_REQUIRED')
    # This is an operator-provided binding; it is NOT independent proof of pre-capture.
    observed_count=qualify_live_repo_and_absence(token,plan,do_request)
    payload={'title':plan['title'],'body':plan['body']}
    obj,_,status,raw_sha=do_request('POST',API+'/issues',token,payload)
    if not isinstance(obj,dict) or (obj.get('title')!=plan['title'] or obj.get('body')!=plan['body']
            or obj.get('user',{}).get('login','').casefold()!=ACTOR.casefold()
            or type(obj.get('number')) is not int or obj['number']<=0):
        raise ValueError('POST_CREATED_BUT_PROVIDER_RESPONSE_NOT_AS_EXPECTED')
    return {
        'schema':'ETB_Q1C_ACTOR_EXECUTION_RECEIPT_v092',
        'status':'ONE_ISSUE_POST_RETURNED_201_NOT_EFFECT_CERTIFICATION',
        'repo':REPO,'frozen_trial_sha256':planned_sha,'input_pre_capture_manifest_sha256':pre_sha,
        'workflow_run_id':env.get('GITHUB_RUN_ID'),'workflow_sha':env.get('GITHUB_SHA'),
        'workflow_attempt':env.get('GITHUB_RUN_ATTEMPT'),'actor_expected':ACTOR,
        'actor_from_issue_response':obj['user']['login'],
        'pre_write_census_size':observed_count,'writes_attempted_this_invocation':1,
        'post_status':status,'post_response_sha256':raw_sha,
        'issue_number':obj['number'],'issue_id':obj.get('id'),'issue_created_at':obj.get('created_at'),
        'native_agent_runs':0,'independent_administrative_root_verified':False,
        'independent_native_airline_effect_oracle_verified':False,
        'q1_status':'Q1_BLOCKED','q2_confirmatory_eligible':False,
        'claim_guard':'GitHub Actions synthetic one-Issue actor receipt; independent observer required; not LLM or tau2.'
    }


def main():
    a=argparse.ArgumentParser();a.add_argument('--execute',action='store_true');a.add_argument('--out',default='q1c_actor_receipt.json');x=a.parse_args()
    path=pathlib.Path(x.out)
    if path.exists():raise SystemExit('REFUSE_OVERWRITE_EXISTING_RECEIPT')
    # The local mode exercises only freeze parity; no token, no network and no write.
    if not x.execute:
        data={'schema':'ETB_Q1C_ACTOR_EXECUTION_RECEIPT_v092','status':'LOCAL_DRY_RUN_NO_NETWORK_NO_WRITE',
              'writes_attempted_this_invocation':0,'q1_status':'Q1_BLOCKED'}
        code=0
    else:
        try:
            data=perform(os.environ)
            code=0
        except Exception as e:
            data={'schema':'ETB_Q1C_ACTOR_EXECUTION_RECEIPT_v092','status':'ACTOR_EXECUTION_BLOCKED_OR_INDETERMINATE',
                  'exception_type':type(e).__name__, 'reason':str(e)[:150] if not isinstance(e,urllib.error.HTTPError) else 'HTTP_'+str(e.code),
                  'write_outcome':'UNDETERMINED_IF_POST_ATTEMPTED',
                  'q1_status':'Q1_BLOCKED','q2_confirmatory_eligible':False}
            code=2
    with path.open('xb') as f:f.write(canonical(data))
    print(json.dumps(data,indent=2))
    return code

if __name__=='__main__':sys.exit(main())
